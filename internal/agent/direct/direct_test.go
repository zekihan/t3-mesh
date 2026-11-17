package direct

import (
	"crypto/x509"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/zekihan/t3-mesh/internal/pki/pkitest"
	"github.com/zekihan/t3-mesh/internal/policy"
	"github.com/zekihan/t3-mesh/internal/proto"
)

type node struct {
	addr  netip.Addr
	mgr   *Manager
	name  string
	addrs []netip.Addr
	view  View
	mu    sync.Mutex
}

func (n *node) get() View {
	n.mu.Lock()
	defer n.mu.Unlock()

	return n.view
}

func (n *node) set(f func(v *View)) {
	n.mu.Lock()
	f(&n.view)
	n.mu.Unlock()
}

func (n *node) setAddrs(a ...netip.Addr) {
	n.mu.Lock()
	n.addrs = a
	n.mu.Unlock()
}

func tcpPort(t *testing.T, addr net.Addr) int {
	t.Helper()

	tcp, ok := addr.(*net.TCPAddr)
	if !ok {
		t.Fatalf("address %v is not TCP", addr)
	}

	return tcp.Port
}

func freePort(t *testing.T) int {
	t.Helper()

	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	defer ln.Close()

	return tcpPort(t, ln.Addr())
}

func echoServer(t *testing.T) string {
	t.Helper()

	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			c, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}

			go func() { _, _ = io.Copy(c, c); _ = c.Close() }()
		}
	}()

	return ln.Addr().String()
}

type env struct {
	ca   *pkitest.CA
	a    *node
	b    *node
	port int
}

func newNode(t *testing.T, testEnv *env, name, addr string, serve map[string]string) *node {
	t.Helper()

	cert, _, _ := testEnv.ca.IssueIdentity(
		t,
		policy.AgentIdentity(name),
		true,
		time.Now().Add(time.Hour),
	)
	pool := x509.NewCertPool()
	pool.AddCert(testEnv.ca.Cert)

	node := &node{
		name:  name,
		addr:  netip.MustParseAddr(addr),
		addrs: []netip.Addr{netip.MustParseAddr(addr)},
	}
	node.view = View{
		Self: name, Identity: cert, Roots: pool, HubConnected: true, SelfHome: true,
		HomePrefixes: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")},
	}
	node.mgr = New(Options{
		Port: testEnv.port, CacheTTL: time.Hour, Serve: serve, View: node.get,
		Log:        slog.New(slog.DiscardHandler),
		GatewayMAC: func() (string, error) { return "aa:bb:cc:dd:ee:ff", nil },
		LocalAddrs: func() ([]netip.Addr, error) {
			node.mu.Lock()
			defer node.mu.Unlock()

			return append([]netip.Addr(nil), node.addrs...), nil
		},
	})

	t.Cleanup(func() { _ = node.mgr.Close() })

	return node
}

func setup(t *testing.T) *env {
	t.Helper()

	testEnv := &env{ca: pkitest.NewCA(t, "clients"), port: freePort(t)}
	echo := echoServer(t)
	testEnv.a = newNode(t, testEnv, "a", "127.0.0.1", nil)
	testEnv.b = newNode(t, testEnv, "b", "127.0.0.2", map[string]string{"t3": echo})

	rules := proto.Rules{Allow: map[string][]string{"t3.b": {"agent-a"}}}

	testEnv.a.set(func(v *View) {
		v.Rules = rules
		v.Peers = []proto.Peer{
			{
				Machine:    "b",
				Identity:   "agent-b",
				LANAddrs:   []string{"127.0.0.2"},
				DirectPort: testEnv.port,
				Home:       true,
				Services:   []string{"t3"},
			},
		}
	})
	testEnv.b.set(func(v *View) {
		v.Rules = rules
		v.Peers = []proto.Peer{{Machine: "a", Identity: "agent-a", Home: true}}
	})

	testEnv.b.mgr.Reconcile(t.Context())

	return testEnv
}

func roundTrip(t *testing.T, conn net.Conn) {
	t.Helper()

	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))

	_, err := conn.Write([]byte("hello"))
	if err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 5)

	_, err = io.ReadFull(conn, buf)
	if err != nil || string(buf) != "hello" {
		t.Fatalf("echo: %q %v", buf, err)
	}
}

func waitFor(t *testing.T, what string, f func() bool) {
	t.Helper()

	end := time.Now().Add(3 * time.Second)
	for time.Now().Before(end) {
		if f() {
			return
		}

		<-time.After(10 * time.Millisecond)
	}

	t.Fatalf("timeout waiting for %s", what)
}

func TestDirectFlow(t *testing.T) {
	testEnv := setup(t)

	conn, err := testEnv.a.mgr.Dial(t.Context(), "b", "t3")
	if err != nil {
		t.Fatal(err)
	}

	defer conn.Close()

	roundTrip(t, conn)

	waitFor(
		t,
		"sessions",
		func() bool { return testEnv.a.mgr.Sessions() == 1 && testEnv.b.mgr.Sessions() == 1 },
	)
}

func TestOneWayRule(t *testing.T) {
	e := setup(t)
	// b may not reach a, so a is absent from b's peer table; a's rule still
	// lets it reach b.
	e.b.set(func(v *View) { v.Peers = nil })

	conn, err := e.a.mgr.Dial(t.Context(), "b", "t3")
	if err != nil {
		t.Fatal(err)
	}

	defer conn.Close()

	roundTrip(t, conn)
}

func TestCallerNotAllowed(t *testing.T) {
	e := setup(t)
	e.b.set(func(v *View) { v.Rules = proto.Rules{} })

	c, err := e.a.mgr.Dial(t.Context(), "b", "t3")
	if err == nil {
		_ = c.Close()

		t.Fatal("expected refusal")
	}
}

func TestUnservedService(t *testing.T) {
	e := setup(t)

	c, err := e.a.mgr.Dial(t.Context(), "b", "other")
	if err == nil {
		_ = c.Close()

		t.Fatal("expected refusal")
	}
}

func TestRevokedPeerRefused(t *testing.T) {
	e := setup(t)
	e.b.set(func(v *View) { v.Revocations.DisabledIdentities = []string{"agent-a"} })

	conn, err := e.a.mgr.Dial(t.Context(), "b", "t3")
	if err == nil {
		_ = conn.Close()

		t.Fatal("expected refusal")
	}

	// Client side revocation of the server.
	e2 := setup(t)
	e2.a.set(func(v *View) { v.Revocations.DisabledIdentities = []string{"agent-b"} })

	conn, err = e2.a.mgr.Dial(t.Context(), "b", "t3")
	if err == nil {
		_ = conn.Close()

		t.Fatal("expected refusal")
	}
}

func TestRevocationClosesBothDirections(t *testing.T) {
	testEnv := setup(t)

	conn, err := testEnv.a.mgr.Dial(t.Context(), "b", "t3")
	if err != nil {
		t.Fatal(err)
	}

	defer conn.Close()

	roundTrip(t, conn)

	testEnv.a.set(func(v *View) { v.Revocations.DisabledIdentities = []string{"agent-b"} })
	testEnv.b.set(func(v *View) { v.Revocations.DisabledIdentities = []string{"agent-a"} })
	testEnv.a.mgr.Recheck()
	testEnv.b.mgr.Recheck()

	if testEnv.a.mgr.Sessions() != 0 || testEnv.b.mgr.Sessions() != 0 {
		t.Fatalf("sessions a=%d b=%d", testEnv.a.mgr.Sessions(), testEnv.b.mgr.Sessions())
	}

	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

	_, err = conn.Write([]byte("x"))
	if err == nil {
		_, err := conn.Read(make([]byte, 1))
		if err == nil {
			t.Fatal("connection still open")
		}
	}
}

func TestRevocationServerSideOnly(t *testing.T) {
	testEnv := setup(t)

	conn, err := testEnv.a.mgr.Dial(t.Context(), "b", "t3")
	if err != nil {
		t.Fatal(err)
	}

	defer conn.Close()

	roundTrip(t, conn)
	testEnv.b.set(func(v *View) { v.Rules = proto.Rules{} })
	testEnv.b.mgr.Recheck()

	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

	_, err = conn.Read(make([]byte, 1))
	if err == nil {
		t.Fatal("expected closed")
	}

	_ = conn.Close()

	waitFor(t, "client session gone", func() bool { return testEnv.a.mgr.Sessions() == 0 })
}

func TestStallingPeerFailsFastAndRemembered(t *testing.T) {
	testEnv := setup(t)

	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	defer ln.Close()

	var held []net.Conn

	var hmu sync.Mutex

	go func() {
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}

			hmu.Lock()

			held = append(held, conn)
			hmu.Unlock()
		}
	}()

	defer func() {
		hmu.Lock()
		for _, conn := range held {
			_ = conn.Close()
		}
		hmu.Unlock()
	}()

	testEnv.a.set(func(v *View) {
		v.Peers = []proto.Peer{
			{
				Machine:    "b",
				LANAddrs:   []string{"127.0.0.1"},
				DirectPort: tcpPort(t, ln.Addr()),
				Home:       true,
			},
		}
	})

	start := time.Now()

	_, err = testEnv.a.mgr.Dial(t.Context(), "b", "t3")
	if err == nil {
		t.Fatal("expected failure")
	}

	if d := time.Since(start); d > 1500*time.Millisecond || d < 500*time.Millisecond {
		t.Fatalf("dial took %v", d)
	}

	start = time.Now()
	_, err = testEnv.a.mgr.Dial(t.Context(), "b", "t3")

	if !errors.Is(err, ErrRecentFail) || time.Since(start) > 100*time.Millisecond {
		t.Fatalf("second dial: %v in %v", err, time.Since(start))
	}
}

func TestActiveModes(t *testing.T) {
	now := time.Now()
	gw := "aa:bb:cc:dd:ee:ff"
	node := &node{}
	node.view = View{
		HubConnected:   false,
		LastHubContact: now.Add(-time.Minute),
		HomeGatewayMAC: "AA:BB:CC:DD:EE:FF",
	}
	clock := now
	mgr := New(Options{
		CacheTTL: time.Hour, View: node.get, Now: func() time.Time { return clock },
		Log:        slog.New(slog.DiscardHandler),
		GatewayMAC: func() (string, error) { return gw, nil },
	})

	defer mgr.Close()

	if ok, r := mgr.Active(); !ok {
		t.Fatalf("want active: %s", r)
	}

	gw = "11:22:33:44:55:66"

	if ok, _ := mgr.Active(); ok {
		t.Fatal("different gateway must be inactive")
	}

	gw = "aa:bb:cc:dd:ee:ff"
	clock = now.Add(2 * time.Hour)

	if ok, _ := mgr.Active(); ok {
		t.Fatal("past window must be inactive")
	}

	clock = now

	node.set(func(v *View) { v.HomeGatewayMAC = "" })

	if ok, _ := mgr.Active(); ok {
		t.Fatal("no cached mac must be inactive")
	}

	node.set(func(v *View) { v.HubConnected = true; v.SelfHome = false })

	if ok, _ := mgr.Active(); ok {
		t.Fatal("connected but not home must be inactive")
	}

	node.set(func(v *View) { v.SelfHome = true })

	if ok, r := mgr.Active(); !ok {
		t.Fatalf("want active: %s", r)
	}
}

func TestInactiveRefusesAndClosesSessions(t *testing.T) {
	testEnv := setup(t)

	c, err := testEnv.a.mgr.Dial(t.Context(), "b", "t3")
	if err != nil {
		t.Fatal(err)
	}

	defer c.Close()

	testEnv.b.set(func(v *View) { v.SelfHome = false })
	testEnv.b.mgr.Reconcile(t.Context())

	waitFor(t, "b sessions closed", func() bool { return testEnv.b.mgr.Sessions() == 0 })

	if len(testEnv.b.mgr.Listening()) != 0 {
		t.Fatal("listener should be closed")
	}

	_, err = testEnv.a.mgr.Dial(t.Context(), "b", "t3")
	if err == nil {
		t.Fatal("expected failure")
	}
}

func TestListenerClosesWhenAddrDisappears(t *testing.T) {
	testEnv := setup(t)

	if len(testEnv.b.mgr.Listening()) != 1 {
		t.Fatalf("listening: %v", testEnv.b.mgr.Listening())
	}

	c, err := testEnv.a.mgr.Dial(t.Context(), "b", "t3")
	if err != nil {
		t.Fatal(err)
	}

	defer c.Close()

	testEnv.b.setAddrs()
	testEnv.b.mgr.Reconcile(t.Context())

	if len(testEnv.b.mgr.Listening()) != 0 || testEnv.b.mgr.Sessions() != 0 {
		t.Fatalf("listening=%v sessions=%d", testEnv.b.mgr.Listening(), testEnv.b.mgr.Sessions())
	}

	// Addresses outside home prefixes are never bound.
	testEnv.b.setAddrs(netip.MustParseAddr("127.0.0.2"))
	testEnv.b.set(
		func(v *View) { v.HomePrefixes = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")} },
	)
	testEnv.b.mgr.Reconcile(t.Context())

	if len(testEnv.b.mgr.Listening()) != 0 {
		t.Fatal("bound outside homeCIDRs")
	}
}

func TestWrongServerIdentityRejected(t *testing.T) {
	e := setup(t)
	// b presents the identity of another agent.
	cert, _, _ := e.ca.IssueIdentity(t, "agent-c", true, time.Now().Add(time.Hour))
	e.b.set(func(v *View) { v.Identity = cert })

	c, err := e.a.mgr.Dial(t.Context(), "b", "t3")
	if err == nil {
		_ = c.Close()

		t.Fatal("expected rejection")
	}
}

func TestForeignCARejected(t *testing.T) {
	e := setup(t)
	other := pkitest.NewCA(t, "other")
	cert, _, _ := other.IssueIdentity(t, "agent-a", true, time.Now().Add(time.Hour))

	e.a.set(func(v *View) { v.Identity = cert })

	c, err := e.a.mgr.Dial(t.Context(), "b", "t3")
	if err == nil {
		_ = c.Close()

		t.Fatal("expected rejection")
	}
}

func TestExpiryClosesSession(t *testing.T) {
	testEnv := setup(t)
	clock := time.Now()

	var cmu sync.Mutex

	testEnv.b.mgr.opts.Now = func() time.Time {
		cmu.Lock()
		defer cmu.Unlock()

		return clock
	}

	c, err := testEnv.a.mgr.Dial(t.Context(), "b", "t3")
	if err != nil {
		t.Fatal(err)
	}

	defer c.Close()

	cmu.Lock()
	clock = clock.Add(2 * time.Hour)
	cmu.Unlock()
	testEnv.b.mgr.Recheck()

	if testEnv.b.mgr.Sessions() != 0 {
		t.Fatal("session not expired")
	}
}
