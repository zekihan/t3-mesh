package hub

import (
	"bytes"
	"context"
	"crypto/tls"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/yamux"

	"github.com/zekihan/t3-mesh/internal/proto"
	"github.com/zekihan/t3-mesh/internal/tunnel"
)

type rejectionPipe struct {
	net.Conn

	draining chan struct{}
}

func (*rejectionPipe) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
}

func (conn *rejectionPipe) SetReadDeadline(deadline time.Time) error {
	err := conn.Conn.SetReadDeadline(deadline)
	if err == nil && !deadline.IsZero() {
		close(conn.draining)
	}

	return err //nolint:wrapcheck // transparent net.Conn wrapper
}

type helloWriteGate struct {
	net.Conn

	resume <-chan struct{}
	frame  []byte
}

func (gate *helloWriteGate) Write(buf []byte) (int, error) {
	n, err := gate.Conn.Write(buf)
	if err == nil && bytes.Equal(buf, gate.frame) {
		<-gate.resume
	}

	return n, err //nolint:wrapcheck // transparent net.Conn wrapper
}

func openGatedHello(
	t *testing.T,
	conn net.Conn,
	hello *proto.Hello,
) (*yamux.Session, *tunnel.Control, chan<- struct{}) {
	t.Helper()

	var frame bytes.Buffer

	err := proto.WriteMessage(&frame, hello)
	if err != nil {
		t.Fatal(err)
	}

	resume := make(chan struct{}, 1)

	t.Cleanup(func() { close(resume) })

	gate := &helloWriteGate{Conn: conn, resume: resume, frame: frame.Bytes()}

	ymx, err := yamux.Client(gate, tunnel.YamuxConfig())
	if err != nil {
		t.Fatal(err)
	}

	stream, err := ymx.OpenStream()
	if err != nil {
		t.Fatal(err)
	}

	return ymx, tunnel.NewControl(stream), resume
}

func TestLeafRejectionDuringHelloWrite(t *testing.T) {
	harness := newEnv(t)
	cert := harness.newCert("agent-devbox", farFuture)
	harness.fake.SetNewest("agent-devbox", strings.Repeat("b", 64))

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	peer := &rejectionPipe{Conn: server, draining: make(chan struct{})}

	finished := make(chan struct{})
	go func() {
		defer close(finished)

		harness.srv.handleConn(ctx, peer)
	}()

	tc := tls.Client(client, &tls.Config{
		RootCAs:      harness.pool,
		ServerName:   "localhost",
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{proto.TunnelALPN(proto.ProtocolVersion)},
		MinVersion:   tls.VersionTLS13,
	})

	err := tc.HandshakeContext(ctx)
	if err != nil {
		t.Fatal(err)
	}

	hello := proto.Hello{Version: "v0.3.0"}
	ymx, ctrl, resume := openGatedHello(t, tc, &hello)

	sendErr := make(chan error, 1)
	go func() { sendErr <- ctrl.Send(hello) }()

	// Keep Hello's write in flight until the hub has sent its rejection and
	// either started draining the connection or shut down the session.
	select {
	case <-peer.draining:
		resume <- struct{}{}
	case <-ymx.CloseChan():
		t.Fatal("yamux shut down with Hello still in flight")
	case <-ctx.Done():
		t.Fatal("hub did not handle Hello")
	}

	select {
	case err := <-sendErr:
		if err != nil {
			t.Fatalf("send Hello: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("Hello write did not complete")
	}

	select {
	case msg := <-ctrl.Messages():
		if asReject(t, msg).Reason != proto.RejectLeafNotNewest {
			t.Fatalf("got %#v, want leaf-not-newest Reject", msg)
		}
	case <-ctx.Done():
		t.Fatal("hub did not send Reject")
	}

	_ = client.Close()

	select {
	case <-finished:
	case <-ctx.Done():
		t.Fatal("hub still serving after the client disconnected")
	}
}
