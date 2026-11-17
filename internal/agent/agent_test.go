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

// ---- fake hub ----

type hubConn struct {
	h     *fakeHub
	ymx   *yamux.Session
	ctrl  *tunnel.Control
	hello proto.Hello
	fp    string

	mu       sync.Mutex
	statuses []proto.Status
}

func (c *hubConn) lastStatus() (proto.Status, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.statuses) == 0 {
		return proto.Status{}, false
	}

	return c.statuses[len(c.statuses)-1], true
}

// openStream opens a hub -> agent data stream with the given header.
func (c *hubConn) openStream(t *testing.T, hdr proto.StreamHeader) net.Conn {
	t.Helper()

	st, err := c.ymx.OpenStream()
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}

	if err = proto.WriteLine(st, hdr); err != nil {
		t.Fatalf("write header: %v", err)
	}

	return st
}

type fakeHub struct {
	t    *testing.T
	ca   *pkitest.CA
	ln   net.Listener
	addr string
	pool *x509.CertPool

	mu          sync.Mutex
	conns       []*hubConn
	ack         proto.HelloAck
	linkTargets map[string]string
	enrollToken string
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

	h := &fakeHub{
		t: t, ca: ca, ln: ln, addr: ln.Addr().String(), pool: pool,
		linkTargets: map[string]string{},
		ack: proto.HelloAck{
			Machine:     "devbox",
			Release:     proto.Release{Version: "v1.0.0", Revision: "rel1"},
			Rules:       proto.Rules{Revision: "rules1", Allow: map[string][]string{"t3.z-arch": {"agent-devbox"}}},
			Peers:       proto.PeerTable{Revision: "peers1"},
			Revocations: proto.Revocations{Revision: "rev1"},
			TrustBundle: proto.TrustBundle{Revision: "tb1", PEM: string(ca.CertPEM)},
			HomeCIDRs:   []string{"192.168.0.0/22"},
		},
	}

	t.Cleanup(h.close)

	go h.loop()

	return h
}

func (h *fakeHub) close() {
	_ = h.ln.Close()

	h.mu.Lock()
	defer h.mu.Unlock()

	for _, c := range h.conns {
		_ = c.ymx.Close()
	}
}

func (h *fakeHub) loop() {
	for {
		c, err := h.ln.Accept()
		if err != nil {
			return
		}

		go h.handle(c.(*tls.Conn)) //nolint:errcheck,forcetypeassert // tls listener
	}
}

func (h *fakeHub) handle(tc *tls.Conn) {
	if err := tc.Handshake(); err != nil {
		_ = tc.Close()

		return
	}

	st := tc.ConnectionState()

	switch st.NegotiatedProtocol {
	case proto.ALPNEnroll:
		h.enroll(tc)
	case proto.TunnelALPN(proto.ProtocolVersion):
		h.tunnel(tc, st)
	default:
		_ = tc.Close()
	}
}

func (h *fakeHub) enroll(tc *tls.Conn) {
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

	h.mu.Lock()
	want := h.enrollToken
	h.mu.Unlock()

	if req.Token != want {
		_ = proto.WriteMessage(tc, proto.Reject{Reason: proto.RejectEnrollFailed, Detail: "bad token"})

		return
	}

	if _, _, err = pki.ValidateCSR([]byte(req.CSR)); err != nil {
		_ = proto.WriteMessage(tc, proto.Reject{Reason: proto.RejectEnrollFailed, Detail: err.Error()})

		return
	}

	cert, chain, err := h.ca.SignCSR([]byte(req.CSR), 365*24*time.Hour)
	if err != nil {
		return
	}

	_ = proto.WriteMessage(tc, proto.Enrolled{Certificate: string(cert), Chain: string(chain)})
}

func (h *fakeHub) tunnel(tc *tls.Conn, st tls.ConnectionState) {
	if len(st.PeerCertificates) == 0 {
		_ = tc.Close()

		return
	}

	raw := make([][]byte, 0, len(st.PeerCertificates))
	for _, c := range st.PeerCertificates {
		raw = append(raw, c.Raw)
	}

	leaf, err := pki.VerifyPeer(raw, h.pool, x509.ExtKeyUsageClientAuth, time.Now())
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

	hc := &hubConn{h: h, ymx: ymx, ctrl: ctrl, hello: hello, fp: pki.Fingerprint(leaf)}

	h.mu.Lock()
	ack := h.ack
	h.conns = append(h.conns, hc)
	h.mu.Unlock()

	if err = ctrl.Send(ack); err != nil {
		return
	}

	go h.control(hc)
	go h.streams(hc)
}

func (h *fakeHub) control(hc *hubConn) {
	for msg := range hc.ctrl.Messages() {
		switch m := msg.(type) {
		case proto.Status:
			hc.mu.Lock()
			hc.statuses = append(hc.statuses, m)
			hc.mu.Unlock()
		case proto.Renew:
			h.mu.Lock()
			deny := h.noRenew
			h.mu.Unlock()

			if deny {
				_ = hc.ctrl.Send(proto.Reject{Reason: proto.RejectRenewFailed, Detail: "denied"})

				continue
			}

			if _, _, err := pki.ValidateCSR([]byte(m.CSR)); err != nil {
				_ = hc.ctrl.Send(proto.Reject{Reason: proto.RejectRenewFailed, Detail: err.Error()})

				continue
			}

			cert, chain, err := h.ca.SignCSR([]byte(m.CSR), 365*24*time.Hour)
			if err != nil {
				continue
			}

			_ = hc.ctrl.Send(proto.Renewed{Certificate: string(cert), Chain: string(chain)})
		}
	}
}

func (h *fakeHub) streams(hc *hubConn) {
	for {
		st, err := hc.ymx.AcceptStream()
		if err != nil {
			return
		}

		go h.link(st)
	}
}

func (h *fakeHub) link(st *yamux.Stream) {
	var hdr proto.StreamHeader
	if err := proto.ReadLine(st, &hdr); err != nil {
		_ = st.Close()

		return
	}

	h.mu.Lock()
	target, ok := h.linkTargets[hdr.To]
	h.mu.Unlock()

	if !ok {
		_ = proto.WriteLine(st, proto.StreamReply{OK: false, Error: "no such target"})
		_ = st.Close()

		return
	}

	conn, err := net.Dial("tcp", target)
	if err != nil {
		_ = proto.WriteLine(st, proto.StreamReply{OK: false, Error: "dial failed"})
		_ = st.Close()

		return
	}

	_ = proto.WriteLine(st, proto.StreamReply{OK: true})

	tunnel.Join(st, conn)
}

func (h *fakeHub) connCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()

	return len(h.conns)
}

func (h *fakeHub) waitConn(t *testing.T, n int) *hubConn {
	t.Helper()

	waitFor(t, fmt.Sprintf("hub connection %d", n), func() bool { return h.connCount() >= n })

	h.mu.Lock()
	defer h.mu.Unlock()

	return h.conns[n-1]
}

// ---- helpers ----

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()

	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}

		time.Sleep(10 * time.Millisecond)
	}

	t.Fatalf("timed out waiting for %s", what)
}

func freePort(t *testing.T) int {
	t.Helper()

	// Config requires link and direct ports below the ephemeral range.
	for range 200 {
		port := 20000 + rand.IntN(12000)

		ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
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

func (f *fakeHealth) Ready() error              { f.mu.Lock(); f.ready++; f.mu.Unlock(); return nil }
func (f *fakeHealth) Alive() error              { f.mu.Lock(); f.alive++; f.mu.Unlock(); return nil }
func (f *fakeHealth) Promote() error            { return nil }
func (f *fakeHealth) Fail(string, string) error { return nil }
func (f *fakeHealth) Restart() error            { return nil }

func (f *fakeHealth) readyCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()

	return f.ready
}

type harness struct {
	t        *testing.T
	ca       *pkitest.CA
	hub      *fakeHub
	cfg      *agentconfig.Config
	agent    *Agent
	health   *fakeHealth
	ident    tls.Certificate
	linkPort int
	local    *httptest.Server // stand-in for the local T3
	remote   *httptest.Server // stand-in for a peer's T3 reached through the hub
	hostSeen chan string
	cancel   context.CancelFunc
	done     chan error
}

type hopts struct {
	notAfter  time.Duration
	hubHost   string
	noHub     bool
	noIdent   bool
	noStart   bool
	direct    bool
	directPrt int
}

func newHarness(t *testing.T, mod func(*hopts)) *harness {
	t.Helper()

	o := hopts{notAfter: 365 * 24 * time.Hour}
	if mod != nil {
		mod(&o)
	}

	ca := pkitest.NewCA(t, "test clients CA")
	h := &harness{t: t, ca: ca, health: &fakeHealth{}, hostSeen: make(chan string, 16)}

	h.local = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, "local:%s", r.URL.Path)
	}))
	t.Cleanup(h.local.Close)

	h.remote = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case h.hostSeen <- r.Host:
		default:
		}

		if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
			conn, buf, err := w.(http.Hijacker).Hijack() //nolint:forcetypeassert // test server
			if err != nil {
				return
			}

			defer func() { _ = conn.Close() }()

			_, _ = buf.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
			_ = buf.Flush()
			_, _ = io.Copy(conn, buf)

			return
		}

		_, _ = fmt.Fprintf(w, "remote:%s", r.URL.Path)
	}))
	t.Cleanup(h.remote.Close)

	h.hub = newFakeHub(t, ca)
	h.hub.linkTargets["t3.z-arch"] = h.remote.Listener.Addr().String()

	hubAddr := h.hub.addr
	if o.noHub {
		hubAddr = fmt.Sprintf("127.0.0.1:%d", freePort(t))
	}

	if o.hubHost != "" {
		_, port, _ := net.SplitHostPort(hubAddr)
		hubAddr = net.JoinHostPort(o.hubHost, port)
	}

	h.linkPort = freePort(t)
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
`, dir, hubAddr, h.local.Listener.Addr().String(), h.linkPort)

	if o.direct {
		yaml += fmt.Sprintf("direct:\n  enabled: true\n  port: %d\n", o.directPrt)
	}

	cfg, err := agentconfig.Parse([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}

	h.cfg = cfg

	tc, certPEM, _ := ca.IssueIdentity(t, "agent-devbox", true, time.Now().Add(o.notAfter))
	h.ident = tc

	if !o.noIdent {
		store := pki.Store{Dir: cfg.Identity.Dir}
		if err = store.SaveKey(tc.PrivateKey.(*ecdsa.PrivateKey)); err != nil { //nolint:forcetypeassert // ecdsa
			t.Fatal(err)
		}

		if err = store.SaveCert(certPEM, nil); err != nil {
			t.Fatal(err)
		}
	}

	a, err := New(Options{
		Config:  cfg,
		Version: "dev",
		Log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		HubTLS:  &tls.Config{RootCAs: h.hub.pool, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS13},
		Health:  h.health,
	})
	if err != nil {
		t.Fatal(err)
	}

	a.backoffBase = 10 * time.Millisecond
	a.backoffMax = 50 * time.Millisecond
	a.statusEvery = 100 * time.Millisecond
	a.gatewayMAC = func() (string, error) { return "aa:bb:cc:dd:ee:ff", nil }
	a.localAddrs = func() ([]netip.Addr, error) { return []netip.Addr{netip.MustParseAddr("192.168.1.5")}, nil }
	h.agent = a

	if !o.noStart {
		h.start()
	}

	return h
}

func (h *harness) start() {
	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel
	h.done = make(chan error, 1)

	go func() { h.done <- h.agent.Run(ctx) }()

	h.t.Cleanup(func() {
		cancel()

		select {
		case <-h.done:
		case <-time.After(10 * time.Second):
			h.t.Error("agent did not stop")
		}
	})
}

func (h *harness) linkURL(path string) string {
	return fmt.Sprintf("http://127.0.0.1:%d%s", h.linkPort, path)
}

func httpGet(t *testing.T, req *http.Request) (int, string) {
	t.Helper()

	cl := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}, Timeout: 10 * time.Second}

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

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}

	return httpGet(t, req)
}

// ---- tests ----

func TestHelloAndAckCached(t *testing.T) {
	h := newHarness(t, nil)
	hc := h.hub.waitConn(t, 1)

	if hc.hello.Version != "dev" {
		t.Errorf("version = %q", hc.hello.Version)
	}

	if len(hc.hello.Services) != 1 || hc.hello.Services[0] != "t3" {
		t.Errorf("services = %v", hc.hello.Services)
	}

	if hc.hello.CertFingerprint != pki.Fingerprint(h.ident.Leaf) {
		t.Errorf("fingerprint = %q", hc.hello.CertFingerprint)
	}

	if hc.hello.DirectPort != 0 || len(hc.hello.LANAddrs) != 0 {
		t.Errorf("direct disabled but hello carries direct data: %+v", hc.hello)
	}

	waitFor(t, "cache on disk", func() bool {
		c, err := state.Load(h.cfg.StateDir)

		return err == nil && c.Machine == "devbox"
	})

	c, _ := state.Load(h.cfg.StateDir)
	if c.Rules.Revision != "rules1" || c.TrustBundle.Revision != "tb1" || c.Release.Version != "v1.0.0" ||
		len(c.HomeCIDRs) != 1 || c.LastHubContact.IsZero() || c.Revocations.Revision != "rev1" {
		t.Errorf("cache = %+v", c)
	}

	waitFor(t, "status", func() bool {
		st, ok := hc.lastStatus()

		return ok && st.RulesRevision == "rules1" && st.TrustBundleRevision == "tb1" &&
			st.RevocationRevision == "rev1" && st.Version == "dev" && st.CertNotAfter != ""
	})
}

func TestHelloLANAddrs(t *testing.T) {
	h := newHarness(t, func(o *hopts) { o.noStart = true; o.direct = true; o.directPrt = freePort(t) })
	h.agent.localAddrs = func() ([]netip.Addr, error) {
		return []netip.Addr{
			netip.MustParseAddr("192.168.1.5"), netip.MustParseAddr("10.0.0.7"),
			netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("fe80::1"),
		}, nil
	}
	h.agent.cache = &state.Cache{}

	got := h.agent.hello(h.ident)
	if h.agent.cfg.Direct.Port != got.DirectPort {
		t.Errorf("direct port = %d", got.DirectPort)
	}

	if strings.Join(got.LANAddrs, ",") != "192.168.1.5,10.0.0.7" {
		t.Errorf("fallback lan addrs = %v", got.LANAddrs)
	}

	h.agent.prefixes = []netip.Prefix{netip.MustParsePrefix("192.168.0.0/22")}

	got = h.agent.hello(h.ident)
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

	_, _ = io.WriteString(st, "GET /v HTTP/1.1\r\nHost: t3.devbox.mesh.noqer.com\r\nConnection: close\r\n\r\n")

	resp, err := http.ReadResponse(bufio.NewReader(st), nil)
	if err != nil {
		t.Fatalf("viewer response: %v", err)
	}

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "local:/v" {
		t.Errorf("viewer body = %q", body)
	}

	// Relayed streams are answered with a StreamReply first.
	rs := hc.openStream(t, proto.StreamHeader{Svc: "t3", From: "agent-z-arch"})
	defer rs.Close()

	var reply proto.StreamReply
	if err = proto.ReadLine(rs, &reply); err != nil || !reply.OK {
		t.Fatalf("relay reply = %+v, %v", reply, err)
	}

	_, _ = io.WriteString(rs, "GET /r HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")

	resp, err = http.ReadResponse(bufio.NewReader(rs), nil)
	if err != nil {
		t.Fatalf("relay response: %v", err)
	}

	body, _ = io.ReadAll(resp.Body)
	if string(body) != "local:/r" {
		t.Errorf("relay body = %q", body)
	}

	// Unknown service: relayed gets OK:false.
	bad := hc.openStream(t, proto.StreamHeader{Svc: "nope", From: "agent-z-arch"})
	defer bad.Close()

	if err = proto.ReadLine(bad, &reply); err != nil || reply.OK {
		t.Errorf("unknown service reply = %+v, %v", reply, err)
	}
}

func TestLinkPortThroughTunnel(t *testing.T) {
	h := newHarness(t, nil)
	h.hub.waitConn(t, 1)

	code, body := get(t, h.linkURL("/hello"))
	if code != 200 || body != "remote:/hello" {
		t.Fatalf("got %d %q", code, body)
	}

	if host := <-h.hostSeen; host != fmt.Sprintf("127.0.0.1:%d", h.linkPort) {
		t.Errorf("upstream Host = %q, want it preserved", host)
	}
}

func TestLinkPortWebSocketUpgrade(t *testing.T) {
	h := newHarness(t, nil)
	h.hub.waitConn(t, 1)

	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", h.linkPort))
	if err != nil {
		t.Fatal(err)
	}

	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	_, _ = fmt.Fprintf(conn, "GET /ws HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n", h.linkPort)

	br := bufio.NewReader(conn)

	resp, err := http.ReadResponse(br, nil)
	if err != nil || resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade response = %v, %v", resp, err)
	}

	_, _ = io.WriteString(conn, "ping\n")

	line, err := br.ReadString('\n')
	if err != nil || line != "ping\n" {
		t.Fatalf("echo = %q, %v", line, err)
	}
}

func TestLinkPortRefusedByHub(t *testing.T) {
	h := newHarness(t, nil)
	h.hub.waitConn(t, 1)

	h.hub.mu.Lock()
	delete(h.hub.linkTargets, "t3.z-arch")
	h.hub.mu.Unlock()

	if code, _ := get(t, h.linkURL("/x")); code != http.StatusBadGateway {
		t.Errorf("code = %d, want 502", code)
	}
}

func TestLinkPortForeignOrigin(t *testing.T) {
	h := newHarness(t, nil)
	h.hub.waitConn(t, 1)

	req, _ := http.NewRequest(http.MethodGet, h.linkURL("/x"), nil)
	req.Header.Set("Origin", "https://evil.example")

	if code, _ := httpGet(t, req); code != http.StatusForbidden {
		t.Errorf("foreign origin code = %d, want 403", code)
	}

	req, _ = http.NewRequest(http.MethodGet, h.linkURL("/x"), nil)
	req.Host = "evil.example"

	if code, _ := httpGet(t, req); code != http.StatusForbidden {
		t.Errorf("foreign host code = %d, want 403", code)
	}

	select {
	case host := <-h.hostSeen:
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
	h := newHarness(t, nil)
	first := h.hub.waitConn(t, 1)

	_ = first.ymx.Close()

	second := h.hub.waitConn(t, 2)
	if second.hello.Version != "dev" {
		t.Errorf("second hello = %+v", second.hello)
	}

	waitFor(t, "current session", func() bool { return h.agent.current() != nil })

	if code, body := get(t, h.linkURL("/again")); code != 200 || body != "remote:/again" {
		t.Errorf("after reconnect got %d %q", code, body)
	}
}

func TestUpdateApplied(t *testing.T) {
	h := newHarness(t, nil)
	hc := h.hub.waitConn(t, 1)

	home := true
	rules := proto.Rules{Revision: "rules2", Allow: map[string][]string{"t3.devbox": {"agent-z-arch"}}}

	if err := hc.ctrl.Send(proto.Update{Home: &home, Rules: &rules}); err != nil {
		t.Fatal(err)
	}

	waitFor(t, "update persisted", func() bool {
		c, err := state.Load(h.cfg.StateDir)

		return err == nil && c.Rules.Revision == "rules2" && c.Home && c.HomeGatewayMAC == "aa:bb:cc:dd:ee:ff"
	})

	if v := h.agent.view(); v.Rules.Revision != "rules2" || !v.SelfHome || v.Roots == nil || !v.HubConnected {
		t.Errorf("view = %+v", v)
	}

	waitFor(t, "status after update", func() bool {
		st, ok := hc.lastStatus()

		return ok && st.RulesRevision == "rules2"
	})
}

func TestRenewal(t *testing.T) {
	h := newHarness(t, func(o *hopts) { o.notAfter = 10 * 24 * time.Hour })
	first := h.hub.waitConn(t, 1)
	second := h.hub.waitConn(t, 2)

	if first.fp == second.fp {
		t.Fatal("renewed session used the old certificate")
	}

	store := pki.Store{Dir: h.cfg.Identity.Dir}

	waitFor(t, "promotion", func() bool {
		_, leaf, err := store.Load()

		return err == nil && pki.Fingerprint(leaf) == second.fp
	})

	for _, f := range []string{"next-key.pem", "next-cert.pem"} {
		if _, err := os.Stat(filepath.Join(h.cfg.Identity.Dir, f)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s left behind: %v", f, err)
		}
	}

	if fp := pki.Fingerprint(h.agent.identity().Leaf); fp != second.fp {
		t.Errorf("in-memory identity fingerprint = %s", fp)
	}

	// The old session is closed once it has no streams.
	waitFor(t, "old session retired", func() bool { return first.ymx.IsClosed() })

	// Reconnects use the new identity.
	_ = second.ymx.Close()

	third := h.hub.waitConn(t, 3)
	if third.fp != second.fp {
		t.Errorf("reconnect fingerprint = %s, want %s", third.fp, second.fp)
	}
}

// A renewal whose first tunnel failed leaves next-* on disk. The hub already
// admits only that leaf, so the next connect must use and promote it.
func TestPendingRenewalUsedOnConnect(t *testing.T) {
	h := newHarness(t, func(o *hopts) { o.noStart = true })

	_, certPEM, keyPEM := h.ca.IssueIdentity(t, h.cfg.Identity.Name, true, time.Now().Add(365*24*time.Hour))

	key, err := pki.ParseKeyPEM(keyPEM)
	if err != nil {
		t.Fatal(err)
	}

	store := pki.Store{Dir: h.cfg.Identity.Dir}
	if err := store.SaveNext(key, certPEM, h.ca.CertPEM); err != nil {
		t.Fatal(err)
	}

	_, next, err := store.LoadNext()
	if err != nil {
		t.Fatal(err)
	}

	h.start()

	first := h.hub.waitConn(t, 1)
	if first.fp != pki.Fingerprint(next) {
		t.Fatalf("connected with %s, want pending renewed leaf %s", first.fp, pki.Fingerprint(next))
	}

	if _, leaf, err := store.Load(); err != nil || pki.Fingerprint(leaf) != first.fp {
		t.Fatalf("pending identity not promoted: %v", err)
	}
}

func TestRenewalFailureKeepsIdentity(t *testing.T) {
	h := newHarness(t, func(o *hopts) { o.notAfter = 10 * 24 * time.Hour; o.noStart = true })
	h.hub.mu.Lock()
	h.hub.noRenew = true
	h.hub.mu.Unlock()
	h.start()

	first := h.hub.waitConn(t, 1)

	waitFor(t, "renewal warning", func() bool {
		st, ok := first.lastStatus()

		return ok && len(st.Warnings) > 0
	})

	if h.hub.connCount() != 1 {
		t.Errorf("connections = %d, want 1", h.hub.connCount())
	}

	store := pki.Store{Dir: h.cfg.Identity.Dir}

	if _, leaf, err := store.Load(); err != nil || pki.Fingerprint(leaf) != first.fp {
		t.Errorf("identity changed after failed renewal: %v", err)
	}
}

func TestFailedLookupKeepsSession(t *testing.T) {
	h := newHarness(t, func(o *hopts) { o.hubHost = "localhost" })
	h.hub.waitConn(t, 1)

	cur := h.agent.current()
	if cur == nil {
		waitFor(t, "current", func() bool { return h.agent.current() != nil })

		cur = h.agent.current()
	}

	ctx := context.Background()

	h.agent.lookupHost = func(context.Context, string) ([]netip.Addr, error) { return nil, errors.New("nxdomain") }
	h.agent.pathCheck(ctx, "test")

	h.agent.lookupHost = func(context.Context, string) ([]netip.Addr, error) { return nil, nil }
	h.agent.pathCheck(ctx, "test")

	h.agent.lookupHost = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{cur.peer}, nil
	}
	h.agent.pathCheck(ctx, "test")

	if h.agent.current() != cur || h.hub.connCount() != 1 {
		t.Fatalf("session replaced without cause (conns=%d)", h.hub.connCount())
	}

	// A successful non-empty answer without the current peer moves the tunnel.
	h.agent.lookupHost = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("10.9.9.9")}, nil
	}
	h.agent.pathCheck(ctx, "test")

	h.hub.waitConn(t, 2)

	if h.agent.current() == cur {
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

	if code, body := get(t, h.linkURL("/p")); code != 200 || body != "remote:/p" {
		t.Errorf("after switch got %d %q", code, body)
	}
}

func TestLocalAddrGoneReplacesSession(t *testing.T) {
	h := newHarness(t, nil)
	h.hub.waitConn(t, 1)

	h.agent.addrPresent = func(netip.Addr) bool { return false }
	h.agent.pathCheck(context.Background(), "test")
	h.agent.addrPresent = func(netip.Addr) bool { return true }

	h.hub.waitConn(t, 2)
}

func TestRunWithoutIdentity(t *testing.T) {
	h := newHarness(t, func(o *hopts) { o.noIdent = true; o.noStart = true })

	err := h.agent.Run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "enroll") {
		t.Fatalf("err = %v, want enroll hint", err)
	}
}

func TestEnroll(t *testing.T) {
	h := newHarness(t, func(o *hopts) { o.noIdent = true; o.noStart = true })
	h.hub.mu.Lock()
	h.hub.enrollToken = "secret"
	h.hub.mu.Unlock()

	ctx := context.Background()
	tlsCfg := &tls.Config{RootCAs: h.hub.pool, ServerName: "127.0.0.1"}

	err := Enroll(ctx, h.cfg, "wrong", tlsCfg)
	if err == nil || !strings.Contains(err.Error(), "bad token") {
		t.Fatalf("wrong token err = %v", err)
	}

	if (pki.Store{Dir: h.cfg.Identity.Dir}).Exists() {
		t.Fatal("identity stored after failed enrollment")
	}

	if err = Enroll(ctx, h.cfg, "secret", tlsCfg); err != nil {
		t.Fatal(err)
	}

	store := pki.Store{Dir: h.cfg.Identity.Dir}

	_, leaf, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}

	if id, _ := pki.CertIdentity(leaf); id != "agent-devbox" {
		t.Errorf("identity = %q", id)
	}

	fi, err := os.Stat(filepath.Join(h.cfg.Identity.Dir, "key.pem"))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("key mode = %v, %v", fi, err)
	}

	di, _ := os.Stat(h.cfg.Identity.Dir)
	if di.Mode().Perm() != 0o700 {
		t.Errorf("dir mode = %v", di.Mode().Perm())
	}

	// The enrolled identity runs the agent.
	h.start()
	h.hub.waitConn(t, 1)

	// Re-enrolling replaces the identity with a fresh key.
	if err = Enroll(ctx, h.cfg, "secret", tlsCfg); err != nil {
		t.Fatal(err)
	}

	if _, leaf2, err2 := store.Load(); err2 != nil || pki.Fingerprint(leaf2) == pki.Fingerprint(leaf) {
		t.Errorf("re-enroll did not replace identity: %v", err2)
	}
}

func TestEnrollRejectsOverrideless(t *testing.T) {
	h := newHarness(t, func(o *hopts) { o.noIdent = true; o.noStart = true })

	// Without the test trust override the hub certificate is not trusted.
	if err := Enroll(context.Background(), h.cfg, "x", nil); err == nil {
		t.Fatal("enrollment succeeded against an untrusted hub")
	}
}
