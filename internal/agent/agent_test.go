package agent

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/yamux"

	"github.com/zekihan/t3-mesh/internal/agent/agentconfig"
	"github.com/zekihan/t3-mesh/internal/agent/state"
	"github.com/zekihan/t3-mesh/internal/pki"
	"github.com/zekihan/t3-mesh/internal/pki/pkitest"
	"github.com/zekihan/t3-mesh/internal/proto"
	"github.com/zekihan/t3-mesh/internal/tunnel"
)

var errNXDomain = errors.New("nxdomain")

// ---- fake hub ----

type hubConn struct {
	h        *fakeHub
	ymx      *yamux.Session
	ctrl     *tunnel.Control
	hello    proto.Hello
	fp       string
	statuses []proto.Status
	mu       sync.Mutex
}

func (conn *hubConn) lastStatus() (proto.Status, bool) {
	conn.mu.Lock()
	defer conn.mu.Unlock()

	if len(conn.statuses) == 0 {
		return proto.Status{}, false
	}

	return conn.statuses[len(conn.statuses)-1], true
}

// openStream opens a hub -> agent data stream with the given header.
func (conn *hubConn) openStream(t *testing.T, hdr proto.StreamHeader) net.Conn {
	t.Helper()

	st, err := conn.ymx.OpenStream()
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}

	err = proto.WriteLine(st, hdr)
	if err != nil {
		t.Fatalf("write header: %v", err)
	}

	return st
}

type fakeHub struct {
	ln          net.Listener
	t           *testing.T
	ca          *pkitest.CA
	pool        *x509.CertPool
	linkTargets map[string]string
	addr        string
	enrollToken string
	conns       []*hubConn
	ack         proto.HelloAck
	mu          sync.Mutex
	noRenew     bool
}

func newFakeHub(t *testing.T, ca *pkitest.CA) *fakeHub {
	t.Helper()

	srv := ca.IssueServer(t, "127.0.0.1")
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{srv},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{proto.TunnelALPN(proto.ProtocolVersion), proto.ALPNEnroll},
		ClientAuth:   tls.RequestClientCert,
	})
	if err != nil {
		t.Fatal(err)
	}

	hubSrv := &fakeHub{
		t: t, ca: ca, ln: ln, addr: ln.Addr().String(), pool: pool,
		linkTargets: map[string]string{},
		ack: proto.HelloAck{
			Machine: "devbox",
			Release: proto.Release{Version: "v1.0.0", Revision: "rel1"},
			Rules: proto.Rules{
				Revision: "rules1",
				Allow:    map[string][]string{"t3.z-arch": {"agent-devbox"}},
			},
			Peers:       proto.PeerTable{Revision: "peers1"},
			Revocations: proto.Revocations{Revision: "rev1"},
			TrustBundle: proto.TrustBundle{Revision: "tb1", PEM: string(ca.CertPEM)},
			HomeCIDRs:   []string{"192.168.0.0/22"},
		},
	}

	t.Cleanup(hubSrv.close)

	go hubSrv.loop()

	return hubSrv
}

func (hubSrv *fakeHub) close() {
	_ = hubSrv.ln.Close()

	hubSrv.mu.Lock()
	defer hubSrv.mu.Unlock()

	for _, c := range hubSrv.conns {
		_ = c.ymx.Close()
	}
}

func (hubSrv *fakeHub) loop() {
	for {
		c, err := hubSrv.ln.Accept()
		if err != nil {
			return
		}

		go hubSrv.handle(c.(*tls.Conn)) //nolint:forcetypeassert // tls listener
	}
}

func (hubSrv *fakeHub) handle(tc *tls.Conn) {
	err := tc.HandshakeContext(hubSrv.t.Context())
	if err != nil {
		_ = tc.Close()

		return
	}

	st := tc.ConnectionState()

	switch st.NegotiatedProtocol {
	case proto.ALPNEnroll:
		hubSrv.enroll(tc)
	case proto.TunnelALPN(proto.ProtocolVersion):
		hubSrv.tunnel(tc, &st)
	default:
		_ = tc.Close()
	}
}

func (hubSrv *fakeHub) enroll(tc *tls.Conn) {
	defer func() { _ = tc.Close() }()

	_ = tc.SetDeadline(time.Now().Add(10 * time.Second))

	msg, err := proto.ReadMessage(tc, proto.MaxEnrollSize)
	if err != nil {
		return
	}

	req, ok := msg.(proto.Enroll)
	if !ok {
		return
	}

	hubSrv.mu.Lock()
	want := hubSrv.enrollToken
	hubSrv.mu.Unlock()

	if req.Token != want {
		_ = proto.WriteMessage(
			tc,
			proto.Reject{Reason: proto.RejectEnrollFailed, Detail: "bad token"},
		)

		return
	}

	_, _, err = pki.ValidateCSR([]byte(req.CSR))
	if err != nil {
		_ = proto.WriteMessage(
			tc,
			proto.Reject{Reason: proto.RejectEnrollFailed, Detail: err.Error()},
		)

		return
	}

	cert, chain, err := hubSrv.ca.SignCSR([]byte(req.CSR), 365*24*time.Hour)
	if err != nil {
		return
	}

	_ = proto.WriteMessage(tc, proto.Enrolled{Certificate: string(cert), Chain: string(chain)})
}

func (hubSrv *fakeHub) tunnel(tc *tls.Conn, st *tls.ConnectionState) {
	if len(st.PeerCertificates) == 0 {
		_ = tc.Close()

		return
	}

	raw := make([][]byte, 0, len(st.PeerCertificates))
	for _, c := range st.PeerCertificates {
		raw = append(raw, c.Raw)
	}

	leaf, err := pki.VerifyPeer(raw, hubSrv.pool, x509.ExtKeyUsageClientAuth, time.Now())
	if err != nil {
		_ = tc.Close()

		return
	}

	ymx, err := yamux.Server(tc, tunnel.YamuxConfig())
	if err != nil {
		_ = tc.Close()

		return
	}

	cs, err := ymx.AcceptStream()
	if err != nil {
		_ = ymx.Close()

		return
	}

	ctrl := tunnel.NewControl(cs)

	var hello proto.Hello

	select {
	case m, ok := <-ctrl.Messages():
		hh, isHello := m.(proto.Hello)
		if !ok || !isHello {
			_ = ymx.Close()

			return
		}

		hello = hh
	case <-time.After(5 * time.Second):
		_ = ymx.Close()

		return
	}

	hc := &hubConn{h: hubSrv, ymx: ymx, ctrl: ctrl, hello: hello, fp: pki.Fingerprint(leaf)}

	hubSrv.mu.Lock()
	ack := hubSrv.ack
	hubSrv.conns = append(hubSrv.conns, hc)
	hubSrv.mu.Unlock()

	err = ctrl.Send(ack)
	if err != nil {
		return
	}

	go hubSrv.control(hc)
	go hubSrv.streams(hc)
}

func (hubSrv *fakeHub) control(hc *hubConn) {
	for msg := range hc.ctrl.Messages() {
		switch typed := msg.(type) {
		case proto.Status:
			hc.mu.Lock()
			hc.statuses = append(hc.statuses, typed)
			hc.mu.Unlock()
		case proto.Renew:
			hubSrv.mu.Lock()
			deny := hubSrv.noRenew
			hubSrv.mu.Unlock()

			if deny {
				_ = hc.ctrl.Send(proto.Reject{Reason: proto.RejectRenewFailed, Detail: "denied"})

				continue
			}

			_, _, err := pki.ValidateCSR([]byte(typed.CSR))
			if err != nil {
				_ = hc.ctrl.Send(proto.Reject{Reason: proto.RejectRenewFailed, Detail: err.Error()})

				continue
			}

			cert, chain, err := hubSrv.ca.SignCSR([]byte(typed.CSR), 365*24*time.Hour)
			if err != nil {
				continue
			}

			_ = hc.ctrl.Send(proto.Renewed{Certificate: string(cert), Chain: string(chain)})
		}
	}
}

func (hubSrv *fakeHub) streams(hc *hubConn) {
	for {
		st, err := hc.ymx.AcceptStream()
		if err != nil {
			return
		}

		go hubSrv.link(st)
	}
}

func (hubSrv *fakeHub) link(st *yamux.Stream) {
	var hdr proto.StreamHeader

	err := proto.ReadLine(st, &hdr)
	if err != nil {
		_ = st.Close()

		return
	}

	hubSrv.mu.Lock()
	target, ok := hubSrv.linkTargets[hdr.To]
	hubSrv.mu.Unlock()

	if !ok {
		_ = proto.WriteLine(st, proto.StreamReply{OK: false, Error: "no such target"})
		_ = st.Close()

		return
	}

	conn, err := (&net.Dialer{}).DialContext(hubSrv.t.Context(), "tcp", target)
	if err != nil {
		_ = proto.WriteLine(st, proto.StreamReply{OK: false, Error: "dial failed"})
		_ = st.Close()

		return
	}

	_ = proto.WriteLine(st, proto.StreamReply{OK: true})

	tunnel.Join(st, conn)
}

func (hubSrv *fakeHub) connCount() int {
	hubSrv.mu.Lock()
	defer hubSrv.mu.Unlock()

	return len(hubSrv.conns)
}

func (hubSrv *fakeHub) waitConn(t *testing.T, count int) *hubConn {
	t.Helper()

	waitFor(
		t,
		fmt.Sprintf("hub connection %d", count),
		func() bool { return hubSrv.connCount() >= count },
	)

	hubSrv.mu.Lock()
	defer hubSrv.mu.Unlock()

	return hubSrv.conns[count-1]
}

// ---- helpers ----

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()

	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}

		<-time.After(10 * time.Millisecond)
	}

	t.Fatalf("timed out waiting for %s", what)
}

const (
	portBase = 20000
	portSpan = 12000
)

func freePort(t *testing.T) int {
	t.Helper()

	// Config requires link and direct ports below the ephemeral range.
	for range 200 {
		port := portBase + rand.IntN(portSpan) //nolint:gosec // test port picking

		ln, err := (&net.ListenConfig{}).Listen(
			t.Context(), "tcp", fmt.Sprintf("127.0.0.1:%d", port),
		)
		if err != nil {
			continue
		}

		_ = ln.Close()

		return port
	}

	t.Fatal("no free port")

	return 0
}

type fakeHealth struct {
	mu           sync.Mutex
	ready, alive int
}

func (f *fakeHealth) Ready() error {
	f.mu.Lock()
	f.ready++
	f.mu.Unlock()

	return nil
}

func (f *fakeHealth) Alive() error {
	f.mu.Lock()
	f.alive++
	f.mu.Unlock()

	return nil
}
func (f *fakeHealth) Promote() error            { return nil }
func (f *fakeHealth) Fail(string, string) error { return nil }
func (f *fakeHealth) Restart() error            { return nil }

func (f *fakeHealth) readyCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()

	return f.ready
}

type harness struct {
	ident    tls.Certificate
	cfg      *agentconfig.Config
	hub      *fakeHub
	t        *testing.T
	agent    *Agent
	health   *fakeHealth
	ca       *pkitest.CA
	local    *httptest.Server
	remote   *httptest.Server
	hostSeen chan string
	cancel   context.CancelFunc
	done     chan error
	linkPort int
}

type hopts struct {
	hubHost   string
	notAfter  time.Duration
	directPrt int
	noHub     bool
	noIdent   bool
	noStart   bool
	direct    bool
}

func ecdsaKey(t *testing.T, cert *tls.Certificate) *ecdsa.PrivateKey {
	t.Helper()

	key, ok := cert.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatal("identity key is not ECDSA")
	}

	return key
}

func newHarness(t *testing.T, mod func(*hopts)) *harness {
	t.Helper()

	opts := hopts{notAfter: 365 * 24 * time.Hour}
	if mod != nil {
		mod(&opts)
	}

	ca := pkitest.NewCA(t, "test clients CA")
	rig := &harness{t: t, ca: ca, health: &fakeHealth{}, hostSeen: make(chan string, 16)}

	rig.local = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "local:"+r.URL.Path) //nolint:gosec // test echo
	}))
	t.Cleanup(rig.local.Close)

	rig.remote = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case rig.hostSeen <- r.Host:
		default:
		}

		if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
			conn, buf, err := w.(http.Hijacker).Hijack() //nolint:forcetypeassert // test server
			if err != nil {
				return
			}

			defer func() { _ = conn.Close() }()

			_, _ = buf.WriteString(
				"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
			)
			_ = buf.Flush()
			_, _ = io.Copy(conn, buf)

			return
		}

		_, _ = io.WriteString(w, "remote:"+r.URL.Path) //nolint:gosec // test echo
	}))
	t.Cleanup(rig.remote.Close)

	rig.hub = newFakeHub(t, ca)
	rig.hub.linkTargets["t3.z-arch"] = rig.remote.Listener.Addr().String()

	hubAddr := rig.hub.addr
	if opts.noHub {
		hubAddr = fmt.Sprintf("127.0.0.1:%d", freePort(t))
	}

	if opts.hubHost != "" {
		_, port, _ := net.SplitHostPort(hubAddr)
		hubAddr = net.JoinHostPort(opts.hubHost, port)
	}

	rig.linkPort = freePort(t)
	dir := t.TempDir()

	yaml := fmt.Sprintf(`
identity:
  name: agent-devbox
  dir: %s/identity
hub: %s
serve:
  t3: %s
links:
  t3.z-arch: 127.0.0.1:%d
`, dir, hubAddr, rig.local.Listener.Addr().String(), rig.linkPort)

	if opts.direct {
		yaml += fmt.Sprintf("direct:\n  enabled: true\n  port: %d\n", opts.directPrt)
	}

	cfg, err := agentconfig.Parse([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}

	rig.cfg = cfg

	tc, certPEM, _ := ca.IssueIdentity(t, "agent-devbox", true, time.Now().Add(opts.notAfter))
	rig.ident = tc

	if !opts.noIdent {
		store := pki.Store{Dir: cfg.Identity.Dir}

		err = store.SaveKey(ecdsaKey(t, &tc))
		if err != nil {
			t.Fatal(err)
		}

		err = store.SaveCert(certPEM, nil)
		if err != nil {
			t.Fatal(err)
		}
	}

	agent, err := New(Options{
		Config:  cfg,
		Version: "dev",
		Log:     slog.New(slog.DiscardHandler),
		HubTLS: &tls.Config{
			RootCAs:    rig.hub.pool,
			ServerName: "127.0.0.1",
			MinVersion: tls.VersionTLS13,
		},
		Health: rig.health,
	})
	if err != nil {
		t.Fatal(err)
	}

	agent.backoffBase = 10 * time.Millisecond
	agent.backoffMax = 50 * time.Millisecond
	agent.statusEvery = 100 * time.Millisecond
	agent.gatewayMAC = func() (string, error) { return "aa:bb:cc:dd:ee:ff", nil }
	agent.localAddrs = func() ([]netip.Addr, error) { return []netip.Addr{netip.MustParseAddr("192.168.1.5")}, nil }
	rig.agent = agent

	if !opts.noStart {
		rig.start()
	}

	return rig
}

func (rig *harness) start() {
	ctx, cancel := context.WithCancel(context.Background())
	rig.cancel = cancel
	rig.done = make(chan error, 1)

	go func() { rig.done <- rig.agent.Run(ctx) }()

	rig.t.Cleanup(func() {
		cancel()

		select {
		case <-rig.done:
		case <-time.After(10 * time.Second):
			rig.t.Error("agent did not stop")
		}
	})
}

func (rig *harness) linkURL(path string) string {
	return fmt.Sprintf("http://127.0.0.1:%d%s", rig.linkPort, path)
}

func httpGet(t *testing.T, req *http.Request) (int, string) {
	t.Helper()

	cl := &http.Client{
		Transport: &http.Transport{DisableKeepAlives: true},
		Timeout:   10 * time.Second,
	}

	resp, err := cl.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}

	defer func() { _ = resp.Body.Close() }()

	b, _ := io.ReadAll(resp.Body)

	return resp.StatusCode, string(b)
}

func get(t *testing.T, url string) (int, string) {
	t.Helper()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, url, http.NoBody)
	if err != nil {
		t.Fatal(err)
	}

	return httpGet(t, req)
}

// ---- tests ----

func checkCachedRevisions(t *testing.T, rig *harness) {
	t.Helper()

	c, _ := state.Load(rig.cfg.StateDir)
	if c.Rules.Revision != "rules1" || c.TrustBundle.Revision != "tb1" ||
		c.Release.Version != "v1.0.0" ||
		len(c.HomeCIDRs) != 1 ||
		c.LastHubContact.IsZero() ||
		c.Revocations.Revision != "rev1" {
		t.Errorf("cache = %+v", c)
	}
}

func TestHelloAndAckCached(t *testing.T) {
	rig := newHarness(t, nil)
	hc := rig.hub.waitConn(t, 1)

	if hc.hello.Version != "dev" {
		t.Errorf("version = %q", hc.hello.Version)
	}

	if len(hc.hello.Services) != 1 || hc.hello.Services[0] != "t3" {
		t.Errorf("services = %v", hc.hello.Services)
	}

	if hc.hello.CertFingerprint != pki.Fingerprint(rig.ident.Leaf) {
		t.Errorf("fingerprint = %q", hc.hello.CertFingerprint)
	}

	if hc.hello.DirectPort != 0 || len(hc.hello.LANAddrs) != 0 {
		t.Errorf("direct disabled but hello carries direct data: %+v", hc.hello)
	}

	waitFor(t, "cache on disk", func() bool {
		c, err := state.Load(rig.cfg.StateDir)

		return err == nil && c.Machine == "devbox"
	})

	checkCachedRevisions(t, rig)

	waitFor(t, "status", func() bool {
		st, ok := hc.lastStatus()

		return ok && st.RulesRevision == "rules1" && st.TrustBundleRevision == "tb1" &&
			st.RevocationRevision == "rev1" && st.Version == "dev" && st.CertNotAfter != ""
	})
}

func TestHelloLANAddrs(t *testing.T) {
	rig := newHarness(
		t,
		func(o *hopts) { o.noStart = true; o.direct = true; o.directPrt = freePort(t) },
	)
	rig.agent.localAddrs = func() ([]netip.Addr, error) {
		return []netip.Addr{
			netip.MustParseAddr("192.168.1.5"), netip.MustParseAddr("10.0.0.7"),
			netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("fe80::1"),
		}, nil
	}
	rig.agent.cache = &state.Cache{}

	got := rig.agent.hello(&rig.ident)
	if rig.agent.cfg.Direct.Port != got.DirectPort {
		t.Errorf("direct port = %d", got.DirectPort)
	}

	if strings.Join(got.LANAddrs, ",") != "192.168.1.5,10.0.0.7" {
		t.Errorf("fallback lan addrs = %v", got.LANAddrs)
	}

	rig.agent.prefixes = []netip.Prefix{netip.MustParsePrefix("192.168.0.0/22")}

	got = rig.agent.hello(&rig.ident)
	if strings.Join(got.LANAddrs, ",") != "192.168.1.5" {
		t.Errorf("cidr lan addrs = %v", got.LANAddrs)
	}
}

func TestViewerAndRelayStreams(t *testing.T) {
	h := newHarness(t, nil)
	hc := h.hub.waitConn(t, 1)

	// Viewer streams carry raw HTTP immediately and get no reply line.
	st := hc.openStream(t, proto.StreamHeader{Svc: "t3", Viewer: "z-phone"})
	defer st.Close()

	_, _ = io.WriteString(
		st,
		"GET /v HTTP/1.1\r\nHost: t3.devbox.mesh.noqer.com\r\nConnection: close\r\n\r\n",
	)

	resp, err := http.ReadResponse(bufio.NewReader(st), nil)
	if err != nil {
		t.Fatalf("viewer response: %v", err)
	}

	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "local:/v" {
		t.Errorf("viewer body = %q", body)
	}

	// Relayed streams are answered with a StreamReply first.
	rs := hc.openStream(t, proto.StreamHeader{Svc: "t3", From: "agent-z-arch"})
	defer rs.Close()

	var reply proto.StreamReply

	err = proto.ReadLine(rs, &reply)
	if err != nil || !reply.OK {
		t.Fatalf("relay reply = %+v, %v", reply, err)
	}

	_, _ = io.WriteString(rs, "GET /r HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")

	resp, err = http.ReadResponse(bufio.NewReader(rs), nil)
	if err != nil {
		t.Fatalf("relay response: %v", err)
	}

	defer func() { _ = resp.Body.Close() }()

	body, _ = io.ReadAll(resp.Body)
	if string(body) != "local:/r" {
		t.Errorf("relay body = %q", body)
	}

	// Unknown service: relayed gets OK:false.
	bad := hc.openStream(t, proto.StreamHeader{Svc: "nope", From: "agent-z-arch"})
	defer bad.Close()

	err = proto.ReadLine(bad, &reply)
	if err != nil || reply.OK {
		t.Errorf("unknown service reply = %+v, %v", reply, err)
	}
}

func TestLinkPortThroughTunnel(t *testing.T) {
	rig := newHarness(t, nil)
	rig.hub.waitConn(t, 1)

	code, body := get(t, rig.linkURL("/hello"))
	if code != 200 || body != "remote:/hello" {
		t.Fatalf("got %d %q", code, body)
	}

	if host := <-rig.hostSeen; host != fmt.Sprintf("127.0.0.1:%d", rig.linkPort) {
		t.Errorf("upstream Host = %q, want it preserved", host)
	}
}

func TestLinkPortWebSocketUpgrade(t *testing.T) {
	rig := newHarness(t, nil)
	rig.hub.waitConn(t, 1)

	conn, err := (&net.Dialer{}).DialContext(
		t.Context(), "tcp", fmt.Sprintf("127.0.0.1:%d", rig.linkPort),
	)
	if err != nil {
		t.Fatal(err)
	}

	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	_, _ = fmt.Fprintf(
		conn,
		"GET /ws HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
		rig.linkPort,
	)

	br := bufio.NewReader(conn)

	resp, err := http.ReadResponse(br, nil)
	if err != nil || resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade response = %v, %v", resp, err)
	}

	defer func() { _ = resp.Body.Close() }()

	_, _ = io.WriteString(conn, "ping\n")

	line, err := br.ReadString('\n')
	if err != nil || line != "ping\n" {
		t.Fatalf("echo = %q, %v", line, err)
	}
}

func TestLinkPortRefusedByHub(t *testing.T) {
	rig := newHarness(t, nil)
	rig.hub.waitConn(t, 1)

	rig.hub.mu.Lock()
	delete(rig.hub.linkTargets, "t3.z-arch")
	rig.hub.mu.Unlock()

	if code, _ := get(t, rig.linkURL("/x")); code != http.StatusBadGateway {
		t.Errorf("code = %d, want 502", code)
	}
}

func TestLinkPortForeignOrigin(t *testing.T) {
	rig := newHarness(t, nil)
	rig.hub.waitConn(t, 1)

	req, _ := http.NewRequestWithContext(
		t.Context(),
		http.MethodGet,
		rig.linkURL("/x"),
		http.NoBody,
	)
	req.Header.Set("Origin", "https://evil.example")

	if code, _ := httpGet(t, req); code != http.StatusForbidden {
		t.Errorf("foreign origin code = %d, want 403", code)
	}

	req, _ = http.NewRequestWithContext(t.Context(), http.MethodGet, rig.linkURL("/x"), http.NoBody)
	req.Host = "evil.example"

	if code, _ := httpGet(t, req); code != http.StatusForbidden {
		t.Errorf("foreign host code = %d, want 403", code)
	}

	select {
	case host := <-rig.hostSeen:
		t.Errorf("request reached upstream with host %q", host)
	default:
	}
}

func TestLinkPortWithoutHub(t *testing.T) {
	h := newHarness(t, func(o *hopts) { o.noHub = true })

	waitFor(t, "startup ready", func() bool { return h.health.readyCount() > 0 })

	if code, _ := get(t, h.linkURL("/x")); code != http.StatusBadGateway {
		t.Errorf("code = %d, want 502 with no tunnel", code)
	}
}

func TestReconnectAfterDrop(t *testing.T) {
	rig := newHarness(t, nil)
	first := rig.hub.waitConn(t, 1)

	_ = first.ymx.Close()

	second := rig.hub.waitConn(t, 2)
	if second.hello.Version != "dev" {
		t.Errorf("second hello = %+v", second.hello)
	}

	waitFor(t, "current session", func() bool { return rig.agent.current() != nil })

	if code, body := get(t, rig.linkURL("/again")); code != 200 || body != "remote:/again" {
		t.Errorf("after reconnect got %d %q", code, body)
	}
}

func TestUpdateApplied(t *testing.T) {
	rig := newHarness(t, nil)
	hc := rig.hub.waitConn(t, 1)

	home := true
	rules := proto.Rules{
		Revision: "rules2",
		Allow:    map[string][]string{"t3.devbox": {"agent-z-arch"}},
	}

	err := hc.ctrl.Send(proto.Update{Home: &home, Rules: &rules})
	if err != nil {
		t.Fatal(err)
	}

	waitFor(t, "update persisted", func() bool {
		c, err := state.Load(rig.cfg.StateDir)

		return err == nil && c.Rules.Revision == "rules2" && c.Home &&
			c.HomeGatewayMAC == "aa:bb:cc:dd:ee:ff"
	})

	if v := rig.agent.view(); v.Rules.Revision != "rules2" || !v.SelfHome || v.Roots == nil ||
		!v.HubConnected {
		t.Errorf("view = %+v", v)
	}

	waitFor(t, "status after update", func() bool {
		st, ok := hc.lastStatus()

		return ok && st.RulesRevision == "rules2"
	})
}

func TestRenewal(t *testing.T) {
	rig := newHarness(t, func(o *hopts) { o.notAfter = 10 * 24 * time.Hour })
	first := rig.hub.waitConn(t, 1)
	second := rig.hub.waitConn(t, 2)

	if first.fp == second.fp {
		t.Fatal("renewed session used the old certificate")
	}

	store := pki.Store{Dir: rig.cfg.Identity.Dir}

	waitFor(t, "promotion", func() bool {
		_, leaf, err := store.Load()

		return err == nil && pki.Fingerprint(leaf) == second.fp
	})

	for _, f := range []string{"next-key.pem", "next-cert.pem"} {
		_, err := os.Stat(filepath.Join(rig.cfg.Identity.Dir, f))
		if !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s left behind: %v", f, err)
		}
	}

	// promote writes the store before swapping the in-memory identity.
	waitFor(t, "in-memory identity promoted", func() bool {
		return pki.Fingerprint(rig.agent.identity().Leaf) == second.fp
	})

	// The old session is closed once it has no streams.
	waitFor(t, "old session retired", func() bool { return first.ymx.IsClosed() })

	// Reconnects use the new identity.
	_ = second.ymx.Close()

	third := rig.hub.waitConn(t, 3)
	if third.fp != second.fp {
		t.Errorf("reconnect fingerprint = %s, want %s", third.fp, second.fp)
	}
}

// A renew-now file renews a certificate far from its renewal window, then is removed.
func TestForcedRenewal(t *testing.T) {
	rig := newHarness(t, func(o *hopts) { o.noStart = true })

	req := filepath.Join(rig.cfg.StateDir, RenewNowFile)

	err := os.MkdirAll(rig.cfg.StateDir, 0o750)
	if err != nil {
		t.Fatal(err)
	}

	err = os.WriteFile(req, nil, 0o600)
	if err != nil {
		t.Fatal(err)
	}

	rig.start()

	first := rig.hub.waitConn(t, 1)
	second := rig.hub.waitConn(t, 2)

	if first.fp == second.fp {
		t.Fatal("forced renewal used the old certificate")
	}

	waitFor(t, "renew-now removed", func() bool {
		_, err := os.Stat(req)

		return errors.Is(err, os.ErrNotExist)
	})
}

// A renewal whose first tunnel failed leaves next-* on disk. The hub already
// admits only that leaf, so the next connect must use and promote it.
func TestPendingRenewalUsedOnConnect(t *testing.T) {
	rig := newHarness(t, func(o *hopts) { o.noStart = true })

	_, certPEM, keyPEM := rig.ca.IssueIdentity(
		t,
		rig.cfg.Identity.Name,
		true,
		time.Now().Add(365*24*time.Hour),
	)

	key, err := pki.ParseKeyPEM(keyPEM)
	if err != nil {
		t.Fatal(err)
	}

	store := pki.Store{Dir: rig.cfg.Identity.Dir}

	err = store.SaveNext(key, certPEM, rig.ca.CertPEM)
	if err != nil {
		t.Fatal(err)
	}

	_, next, err := store.LoadNext()
	if err != nil {
		t.Fatal(err)
	}

	rig.start()

	first := rig.hub.waitConn(t, 1)
	if first.fp != pki.Fingerprint(next) {
		t.Fatalf("connected with %s, want pending renewed leaf %s", first.fp, pki.Fingerprint(next))
	}

	// The agent promotes the pending identity after its handshake completes,
	// which can be just after the hub has seen the connection.
	waitFor(t, "pending identity promoted", func() bool {
		_, leaf, err := store.Load()

		return err == nil && pki.Fingerprint(leaf) == first.fp
	})
}

func TestRenewalFailureKeepsIdentity(t *testing.T) {
	rig := newHarness(t, func(o *hopts) { o.notAfter = 10 * 24 * time.Hour; o.noStart = true })
	rig.hub.mu.Lock()
	rig.hub.noRenew = true
	rig.hub.mu.Unlock()
	rig.start()

	first := rig.hub.waitConn(t, 1)

	waitFor(t, "renewal warning", func() bool {
		st, ok := first.lastStatus()

		return ok && len(st.Warnings) > 0
	})

	if rig.hub.connCount() != 1 {
		t.Errorf("connections = %d, want 1", rig.hub.connCount())
	}

	store := pki.Store{Dir: rig.cfg.Identity.Dir}

	_, leaf, err := store.Load()
	if err != nil || pki.Fingerprint(leaf) != first.fp {
		t.Errorf("identity changed after failed renewal: %v", err)
	}
}

func TestFailedLookupKeepsSession(t *testing.T) {
	rig := newHarness(t, func(o *hopts) { o.hubHost = "localhost" })
	rig.hub.waitConn(t, 1)

	cur := rig.agent.current()
	if cur == nil {
		waitFor(t, "current", func() bool { return rig.agent.current() != nil })

		cur = rig.agent.current()
	}

	ctx := t.Context()

	rig.agent.lookupHost = func(context.Context, string) ([]netip.Addr, error) { return nil, errNXDomain }
	rig.agent.pathCheck(ctx, "test")

	rig.agent.lookupHost = func(context.Context, string) ([]netip.Addr, error) { return nil, nil }
	rig.agent.pathCheck(ctx, "test")

	rig.agent.lookupHost = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{cur.peer}, nil
	}
	rig.agent.pathCheck(ctx, "test")

	if rig.agent.current() != cur || rig.hub.connCount() != 1 {
		t.Fatalf("session replaced without cause (conns=%d)", rig.hub.connCount())
	}

	// A successful non-empty answer without the current peer moves the tunnel.
	rig.agent.lookupHost = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("10.9.9.9")}, nil
	}
	rig.agent.pathCheck(ctx, "test")

	rig.hub.waitConn(t, 2)

	if rig.agent.current() == cur {
		t.Fatal("current session not replaced")
	}

	waitFor(t, "old session closed", func() bool {
		select {
		case <-cur.done:
			return true
		default:
			return false
		}
	})

	if code, body := get(t, rig.linkURL("/p")); code != 200 || body != "remote:/p" {
		t.Errorf("after switch got %d %q", code, body)
	}
}

func TestLocalAddrGoneReplacesSession(t *testing.T) {
	rig := newHarness(t, nil)
	rig.hub.waitConn(t, 1)

	rig.agent.addrPresent = func(netip.Addr) bool { return false }
	rig.agent.pathCheck(t.Context(), "test")
	rig.agent.addrPresent = func(netip.Addr) bool { return true }

	rig.hub.waitConn(t, 2)
}

func TestRunWithoutIdentity(t *testing.T) {
	h := newHarness(t, func(o *hopts) { o.noIdent = true; o.noStart = true })

	err := h.agent.Run(t.Context())
	if err == nil || !strings.Contains(err.Error(), "enroll") {
		t.Fatalf("err = %v, want enroll hint", err)
	}
}

func TestEnroll(t *testing.T) {
	rig := newHarness(t, func(o *hopts) { o.noIdent = true; o.noStart = true })
	rig.hub.mu.Lock()
	rig.hub.enrollToken = "secret"
	rig.hub.mu.Unlock()

	ctx := t.Context()
	tlsCfg := &tls.Config{RootCAs: rig.hub.pool, ServerName: "127.0.0.1"}

	err := Enroll(ctx, rig.cfg, "wrong", tlsCfg)
	if err == nil || !strings.Contains(err.Error(), "bad token") {
		t.Fatalf("wrong token err = %v", err)
	}

	if (pki.Store{Dir: rig.cfg.Identity.Dir}).Exists() {
		t.Fatal("identity stored after failed enrollment")
	}

	err = Enroll(ctx, rig.cfg, "secret", tlsCfg)
	if err != nil {
		t.Fatal(err)
	}

	store := pki.Store{Dir: rig.cfg.Identity.Dir}

	_, leaf, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}

	if id, _ := pki.CertIdentity(leaf); id != "agent-devbox" {
		t.Errorf("identity = %q", id)
	}

	fi, err := os.Stat(filepath.Join(rig.cfg.Identity.Dir, "key.pem"))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("key mode = %v, %v", fi, err)
	}

	di, _ := os.Stat(rig.cfg.Identity.Dir)
	if di.Mode().Perm() != 0o700 {
		t.Errorf("dir mode = %v", di.Mode().Perm())
	}

	// The enrolled identity runs the agent.
	rig.start()
	rig.hub.waitConn(t, 1)

	// Re-enrolling replaces the identity with a fresh key.
	err = Enroll(ctx, rig.cfg, "secret", tlsCfg)
	if err != nil {
		t.Fatal(err)
	}

	_, leaf2, err2 := store.Load()
	if err2 != nil || pki.Fingerprint(leaf2) == pki.Fingerprint(leaf) {
		t.Errorf("re-enroll did not replace identity: %v", err2)
	}
}

func TestEnrollRejectsOverrideless(t *testing.T) {
	h := newHarness(t, func(o *hopts) { o.noIdent = true; o.noStart = true })

	// Without the test trust override the hub certificate is not trusted.
	err := Enroll(t.Context(), h.cfg, "x", nil)
	if err == nil {
		t.Fatal("enrollment succeeded against an untrusted hub")
	}
}

func TestHelloAckClearsEmptiedHomeCIDRs(t *testing.T) {
	t.Parallel()

	agent := &Agent{
		now:   time.Now,
		cache: &state.Cache{HomeCIDRs: []string{"192.168.0.0/22"}},
	}

	agent.applyAckLocked(&proto.HelloAck{HomeCIDRs: []string{"10.0.0.0/8"}})

	if got := agent.cache.HomeCIDRs; len(got) != 1 || got[0] != "10.0.0.0/8" {
		t.Fatalf("HomeCIDRs = %v, want the ack's list", got)
	}

	agent.applyAckLocked(&proto.HelloAck{})

	if got := agent.cache.HomeCIDRs; len(got) != 0 {
		t.Fatalf("HomeCIDRs = %v, want cleared", got)
	}
}

// A long-lived healthy session counts as recent hub contact for the updater,
// although its HelloAck is old.
func TestHubContactFollowsPongs(t *testing.T) {
	rig := newHarness(t, nil)
	rig.hub.waitConn(t, 1)

	waitFor(t, "session adopted", func() bool { return !rig.agent.lastHelloAckTime().IsZero() })

	rig.agent.mu.Lock()
	rig.agent.lastHelloAck = time.Now().Add(-10 * time.Minute)
	rig.agent.mu.Unlock()

	if age := time.Since(rig.agent.lastHelloAckTime()); age > time.Minute {
		t.Fatalf("hub contact is %s old despite a live session", age)
	}
}
