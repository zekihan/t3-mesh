package integration

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

func TestTCPLinks(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name   string
		direct bool
	}{
		{name: "relay"},
		{name: "direct", direct: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			testTCPLink(t, tc.direct)
		})
	}
}

func testTCPLink(t *testing.T, direct bool) {
	t.Helper()

	msh := newMesh(t, &meshOpts{cfg: hubCfg{tcp: true}})
	if direct {
		skipNoDirect(t, msh)
	}

	backend, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}

	defer backend.Close()

	local, unread := net.Pipe()
	defer local.Close()
	defer unread.Close()

	blocked := &blockedTCPBackend{
		Conn: local, writing: make(chan struct{}), writeDone: make(chan struct{}),
	}

	var useBlocked atomic.Bool

	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		if addr == backend.Addr().String() && useBlocked.CompareAndSwap(true, false) {
			return blocked, nil
		}

		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}

	nodeA, nodeB := msh.twoNodes(
		&nodeOpts{direct: direct, links: []string{"ssh.b"}},
		&nodeOpts{direct: direct, tcpAddr: backend.Addr().String(), dial: dial},
	)
	if direct {
		nodeA.waitDirectListening()
		nodeB.waitDirectListening()
	}

	revision := msh.watcher.Current().Rules.Revision

	eventually(t, 5*time.Second, "both agents know the rules", func() bool {
		st := msh.status()

		return st.Machines["a"].Acked.Rules == revision && st.Machines["b"].Acked.Rules == revision
	})

	open := func() (*net.TCPConn, *net.TCPConn) {
		eventually(t, 5*time.Second, "previous relay stream closed", func() bool {
			return msh.status().Machines["a"].LinkStreams == 0
		})
		client, server := openTCPLink(t, nodeA, backend)
		assertTCPLinkPath(t, msh, direct, 1)

		return client, server
	}

	// Test an echo and tail after FIN in both directions, reversing who closes
	// first on the second connection.
	client, server := open()
	testTCPHalfClose(t, client, server)
	client, server = open()
	testTCPHalfClose(t, server, client)

	phone := msh.newPhone()
	if code, _ := get(
		t,
		msh.viewer.URL,
		phone.headers(),
		"ssh.b."+viewerDomain,
	); code != http.StatusNotFound {
		t.Fatalf("TCP viewer host returned %d, want 404", code)
	}

	client, server = open()
	tcpTransfer(t, client, server, "before revocation")
	useBlocked.Store(true)

	blockedClient := dialTCPLink(t, nodeA)

	_, err = io.WriteString(blockedClient, "the backend never reads this")
	if err != nil {
		t.Fatal(err)
	}

	waitTCPEvent(t, blocked.writing, "backend write to start")
	assertTCPLinkPath(t, msh, direct, 2)

	msh.update(func(c *hubCfg) { c.noTCPRule = true })
	waitTCPEvent(t, blocked.writeDone, "revocation to unblock the backend write")
	tcpEOF(t, blockedClient)
	tcpEOF(t, client)
	tcpEOF(t, server)
}

type blockedTCPBackend struct {
	net.Conn

	writing   chan struct{}
	writeDone chan struct{}
}

func (c *blockedTCPBackend) Write(p []byte) (int, error) {
	close(c.writing)
	defer close(c.writeDone)

	return c.Conn.Write(p) //nolint:wrapcheck // passthrough
}

func waitTCPEvent(t *testing.T, done <-chan struct{}, event string) {
	t.Helper()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", event)
	}
}

func assertTCPLinkPath(t *testing.T, msh *mesh, direct bool, wantRelayed int64) {
	t.Helper()

	if direct {
		wantRelayed = 0
	}

	if got := msh.status().Machines["a"].LinkStreams; got != wantRelayed {
		t.Fatalf("hub linked streams = %d, want %d", got, wantRelayed)
	}
}

func dialTCPLink(t *testing.T, nodeA *node) *net.TCPConn {
	t.Helper()

	dialer := net.Dialer{Timeout: 5 * time.Second}

	conn, err := dialer.DialContext(
		t.Context(),
		"tcp",
		net.JoinHostPort("127.0.0.1", strconv.Itoa(nodeA.linkPort)),
	)
	if err != nil {
		t.Fatal(err)
	}

	client := conn.(*net.TCPConn) //nolint:forcetypeassert // tcp dial

	t.Cleanup(func() { _ = client.Close() })

	err = client.SetDeadline(time.Now().Add(5 * time.Second))
	if err != nil {
		t.Fatal(err)
	}

	return client
}

func openTCPLink(t *testing.T, nodeA *node, ln *net.TCPListener) (*net.TCPConn, *net.TCPConn) {
	t.Helper()

	client := dialTCPLink(t, nodeA)
	deadline := time.Now().Add(5 * time.Second)

	err := ln.SetDeadline(deadline)
	if err != nil {
		t.Fatal(err)
	}

	const marker = "mesh TCP test"

	_, err = io.WriteString(client, marker)
	if err != nil {
		t.Fatal(err)
	}

	// The agent also opens this listener for its service health checks.
	for {
		server, acceptErr := ln.AcceptTCP()
		if acceptErr != nil {
			t.Fatal(acceptErr)
		}

		err = server.SetDeadline(deadline)
		if err != nil {
			_ = server.Close()

			t.Fatal(err)
		}

		var got [len(marker)]byte

		_, err = io.ReadFull(server, got[:])
		if err == nil && string(got[:]) == marker {
			t.Cleanup(func() { _ = server.Close() })

			return client, server
		}

		_ = server.Close()
	}
}

func testTCPHalfClose(t *testing.T, first, second *net.TCPConn) {
	t.Helper()

	defer first.Close()
	defer second.Close()

	const payload = "\x00\xffSSH-like bytes\r\n"

	tcpTransfer(t, first, second, payload)
	tcpTransfer(t, second, first, payload)

	err := first.CloseWrite()
	if err != nil {
		t.Fatal(err)
	}

	tcpEOF(t, second)
	tcpTransfer(t, second, first, "after first FIN")

	err = second.CloseWrite()
	if err != nil {
		t.Fatal(err)
	}

	tcpEOF(t, first)
}

func tcpTransfer(t *testing.T, from, to net.Conn, payload string) {
	t.Helper()

	_, err := io.WriteString(from, payload)
	if err != nil {
		t.Fatal(err)
	}

	got := make([]byte, len(payload))

	_, err = io.ReadFull(to, got)
	if err != nil || string(got) != payload {
		t.Fatalf("read %q, %v; want %q", got, err, payload)
	}
}

func tcpEOF(t *testing.T, conn net.Conn) {
	t.Helper()

	var data [1]byte

	n, err := conn.Read(data[:])
	if n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("read after close = %d, %v; want EOF", n, err)
	}
}
