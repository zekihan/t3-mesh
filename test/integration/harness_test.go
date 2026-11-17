package integration

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zekihan/t3-mesh/internal/agent"
	"github.com/zekihan/t3-mesh/internal/agent/agentconfig"
	"github.com/zekihan/t3-mesh/internal/agent/state"
	"github.com/zekihan/t3-mesh/internal/hub"
	"github.com/zekihan/t3-mesh/internal/hub/enroll"
	"github.com/zekihan/t3-mesh/internal/hub/hubconfig"
	"github.com/zekihan/t3-mesh/internal/hub/issuer/issuertest"
	"github.com/zekihan/t3-mesh/internal/netwatch"
	"github.com/zekihan/t3-mesh/internal/pki"
	"github.com/zekihan/t3-mesh/internal/pki/pkitest"
)

const viewerDomain = "mesh.test"

func eventually(t *testing.T, d time.Duration, what string, cond func() bool) {
	t.Helper()

	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}

		time.Sleep(20 * time.Millisecond)
	}

	t.Fatalf("timed out after %s waiting for: %s", d, what)
}

func logger() *slog.Logger {
	if os.Getenv("T3_TEST_LOG") != "" {
		return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	}

	return slog.New(slog.DiscardHandler)
}

var (
	portMu    sync.Mutex
	portsUsed = map[int]bool{}
)

// freePort returns a port that is free on host and was not handed out before in
// this process, so parallel tests cannot pick the same one between probe and use.
func freePort(t *testing.T, host string) int {
	t.Helper()

	portMu.Lock()
	defer portMu.Unlock()

	for range 100 {
		ln, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
		if err != nil {
			t.Fatalf("free port: %v", err)
		}

		port := ln.Addr().(*net.TCPAddr).Port //nolint:forcetypeassert // tcp listener

		_ = ln.Close()

		if !portsUsed[port] {
			portsUsed[port] = true

			return port
		}
	}

	t.Fatal("no free port")

	return 0
}

// loopbackHello makes every agent advertise 127.0.0.1 (distinct ports) as its
// direct address, so direct scenarios run on hosts without a LAN address, such
// as CI runners. Set it to false to exercise the host's private LAN IPv4 instead.
const loopbackHello = true

const fixedGatewayMAC = "02:00:00:00:00:01"

// directAddr returns the address agents use for direct listeners, or the zero
// value when the host cannot provide one.
func directAddr() netip.Addr {
	if loopbackHello {
		return netip.MustParseAddr("127.0.0.1")
	}

	addrs, err := netwatch.LocalAddrs()
	if err != nil {
		return netip.Addr{}
	}

	for _, a := range addrs {
		if a.Is4() && a.IsPrivate() && !a.IsLinkLocalUnicast() {
			return a
		}
	}

	return netip.Addr{}
}

// ---- hub configuration ----

type hubCfg struct {
	release  string
	disabled []string
	blocked  []string
	// noRelayRule removes agent-a from the mesh-t3-b entry.
	noRelayRule bool
	home        []string
}

func (c hubCfg) yaml() string {
	rel := c.release
	if rel == "" {
		rel = "v0.3.0"
	}

	list := func(in []string) string { return "[" + strings.Join(in, ",") + "]" }
	quoted := make([]string, len(c.home))
	for i, h := range c.home {
		quoted[i] = `"` + h + `"`
	}

	bIDs := "z-phone, agent-a"
	if c.noRelayRule {
		bIDs = "z-phone"
	}

	return fmt.Sprintf(`
machines:
  a: {identity: agent-a, services: {t3: {kind: http}}}
  b: {identity: agent-b, services: {t3: {kind: http}}}
homeCIDRs: %s
viewerDomain: %s
release: {version: %s}
policy:
  entries:
    mesh-t3-a: {identities: [z-phone]}
    mesh-t3-b: {identities: [%s]}
  disabledIdentities: %s
  blockedFingerprints: %s
`, list(quoted), viewerDomain, rel, bIDs, list(c.disabled), list(c.blocked))
}

// ---- mesh (hub side) ----

// trackListener records accepted connections so tests can cut a tunnel.
type trackListener struct {
	net.Listener

	mu    sync.Mutex
	conns []net.Conn
}

func (l *trackListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil {
		l.mu.Lock()
		l.conns = append(l.conns, c)
		l.mu.Unlock()
	}

	return c, err //nolint:wrapcheck // passthrough
}

func (l *trackListener) count() int {
	l.mu.Lock()
	defer l.mu.Unlock()

	return len(l.conns)
}

func (l *trackListener) since(n int) []net.Conn {
	l.mu.Lock()
	defer l.mu.Unlock()

	return append([]net.Conn(nil), l.conns[n:]...)
}

type meshOpts struct {
	cfg hubCfg
	// extraCAs are in the trust bundle from the start.
	extraCAs []*pkitest.CA
}

type mesh struct {
	t       *testing.T
	ca      *pkitest.CA
	pool    *x509.CertPool
	dir     string
	paths   hubconfig.Paths
	watcher *hubconfig.Watcher
	srv     *hub.Server
	fake    *issuertest.Fake
	tokens  *enroll.Tokens
	tl      *trackListener
	hubAddr string
	viewer  *httptest.Server
	ops     *httptest.Server
	clock   atomic.Int64
	direct  netip.Addr
	stopHub func()
	cfg     hubCfg
}

func (m *mesh) now() time.Time { return time.Now().Add(time.Duration(m.clock.Load())) }

func writeAtomic(t *testing.T, tmpDir, path, content string) {
	t.Helper()

	tmp, err := os.CreateTemp(tmpDir, "w-*")
	if err != nil {
		t.Fatal(err)
	}

	if _, err = tmp.WriteString(content); err != nil {
		t.Fatal(err)
	}

	if err = tmp.Close(); err != nil {
		t.Fatal(err)
	}

	if err = os.Rename(tmp.Name(), path); err != nil {
		t.Fatal(err)
	}
}

func newMesh(t *testing.T, o meshOpts) *mesh {
	t.Helper()

	m := &mesh{t: t, ca: pkitest.NewCA(t, "clients"), dir: t.TempDir(), cfg: o.cfg, direct: directAddr()}
	m.pool = x509.NewCertPool()
	m.pool.AddCert(m.ca.Cert)
	m.paths = hubconfig.Paths{
		ConfigDir: filepath.Join(m.dir, "config"),
		TrustDir:  filepath.Join(m.dir, "trust"),
		CertDir:   filepath.Join(m.dir, "cert"),
	}

	for _, d := range []string{m.paths.ConfigDir, m.paths.TrustDir, m.paths.CertDir, filepath.Join(m.dir, "tmp")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	if m.cfg.home == nil {
		m.cfg.home = []string{"127.0.0.0/8"}
		if m.direct.IsValid() && !m.direct.IsLoopback() {
			m.cfg.home = append(m.cfg.home, m.direct.String()+"/32")
		}
	}

	m.writeConfig(m.cfg)
	m.writeTrust("trust-1", append([]*pkitest.CA{m.ca}, o.extraCAs...)...)

	srvCert := m.ca.IssueServer(t, "localhost", "127.0.0.1")

	keyDER, err := x509.MarshalPKCS8PrivateKey(srvCert.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}

	tmp := filepath.Join(m.dir, "tmp")
	writeAtomic(t, tmp, filepath.Join(m.paths.CertDir, hubconfig.CertFile),
		string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srvCert.Certificate[0]})))
	writeAtomic(t, tmp, filepath.Join(m.paths.CertDir, hubconfig.KeyFile),
		string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})))

	m.watcher, err = hubconfig.NewWatcher(m.paths, logger())
	if err != nil {
		t.Fatal(err)
	}

	m.fake = &issuertest.Fake{Sign: func(csr []byte) ([]byte, []byte, error) {
		return m.ca.SignCSR(csr, 365*24*time.Hour)
	}}
	m.tokens = enroll.NewTokens(m.now)

	m.srv, err = hub.New(hub.Options{
		Config: m.watcher, Issuer: m.fake, Tokens: m.tokens, Log: logger(), Now: m.now,
	})
	if err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	m.tl = &trackListener{Listener: ln}
	m.hubAddr = ln.Addr().String()

	ctx, cancel := context.WithCancel(context.Background())

	var wg sync.WaitGroup

	wg.Go(func() { _ = m.watcher.Run(ctx, m.srv.OnConfigChange) })
	wg.Go(func() { _ = m.srv.ServeTunnels(ctx, m.tl) })

	m.viewer = httptest.NewServer(m.srv.ViewerHandler())
	m.ops = httptest.NewServer(m.srv.OpsHandler())

	var once sync.Once

	m.stopHub = func() {
		once.Do(func() {
			cancel()

			done := make(chan struct{})

			go func() { wg.Wait(); close(done) }()

			select {
			case <-done:
			case <-time.After(15 * time.Second):
				t.Error("hub did not stop")
			}
		})
	}

	t.Cleanup(m.stopHub)
	t.Cleanup(func() {
		m.viewer.CloseClientConnections()
		m.viewer.Close()
		m.ops.Close()
	})

	eventually(t, 5*time.Second, "hub ready", m.srv.Ready)

	return m
}

func (m *mesh) writeConfig(c hubCfg) {
	m.t.Helper()
	m.cfg = c
	m.writeRaw(c.yaml())
}

func (m *mesh) writeRaw(content string) {
	m.t.Helper()
	writeAtomic(m.t, filepath.Join(m.dir, "tmp"), filepath.Join(m.paths.ConfigDir, hubconfig.ConfigFile), content)
}

func (m *mesh) writeTrust(rev string, cas ...*pkitest.CA) {
	m.t.Helper()

	var b strings.Builder
	for _, ca := range cas {
		b.Write(ca.CertPEM)
	}

	tmp := filepath.Join(m.dir, "tmp")
	writeAtomic(m.t, tmp, filepath.Join(m.paths.TrustDir, hubconfig.TrustFile), b.String())
	writeAtomic(m.t, tmp, filepath.Join(m.paths.TrustDir, hubconfig.RevFile), rev)
}

// update rewrites config.yaml and waits until the hub watcher loaded it.
func (m *mesh) update(f func(c *hubCfg)) {
	m.t.Helper()

	old := m.watcher.Current().Fingerprint
	c := m.cfg

	f(&c)
	m.writeConfig(c)

	eventually(m.t, 5*time.Second, "hub reloads config", func() bool { return m.watcher.Current().Fingerprint != old })
}

// ---- status ----

type machineStatus struct {
	Connected      bool
	Sessions       int
	OpenStreams    int64
	LinkStreams    int64
	DirectSessions int
	CertNotAfter   *time.Time
	Acked          struct{ Release, Rules, Revocations, TrustBundle string }
	Warnings       []string
	Alerts         map[string]bool
}

type statusDoc struct {
	PolicyRevision      string
	TrustBundleRevision string
	Release             struct{ Version, Revision string }
	Stale               bool
	ConfigError         string
	Machines            map[string]machineStatus
}

func (m *mesh) status() statusDoc {
	m.t.Helper()

	resp, err := http.Get(m.ops.URL + "/status")
	if err != nil {
		m.t.Fatalf("status: %v", err)
	}

	defer func() { _ = resp.Body.Close() }()

	var d statusDoc
	if err = json.NewDecoder(resp.Body).Decode(&d); err != nil {
		m.t.Fatalf("decode status: %v", err)
	}

	return d
}

func (m *mesh) opsGet(path string) (int, string) {
	m.t.Helper()

	resp, err := http.Get(m.ops.URL + path)
	if err != nil {
		m.t.Fatalf("GET %s: %v", path, err)
	}

	defer func() { _ = resp.Body.Close() }()

	b, _ := io.ReadAll(resp.Body)

	return resp.StatusCode, strings.TrimSpace(string(b))
}

func (m *mesh) waitConnected(machine string) {
	m.t.Helper()
	eventually(m.t, 10*time.Second, machine+" connected to hub", func() bool { return m.status().Machines[machine].Connected })
}

// rawDial opens a TLS connection to the hub without any protocol on top.
func (m *mesh) rawDial(cert *tls.Certificate, alpn string) (*tls.Conn, error) {
	cfg := &tls.Config{RootCAs: m.pool, ServerName: "localhost", MinVersion: tls.VersionTLS13, NextProtos: []string{alpn}}
	if cert != nil {
		cfg.Certificates = []tls.Certificate{*cert}
	}

	d := net.Dialer{Timeout: 5 * time.Second}

	raw, err := d.Dial("tcp", m.hubAddr)
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}

	c := tls.Client(raw, cfg)
	if err = c.Handshake(); err != nil {
		_ = raw.Close()

		return nil, fmt.Errorf("handshake: %w", err)
	}

	return c, nil
}

// ---- nodes (agent side) ----

type node struct {
	m          *mesh
	name       string
	identity   string
	t3         *httptest.Server
	t3stop     chan struct{}
	cfg        *agentconfig.Config
	cert       tls.Certificate
	linkPort   int
	directPort int
	clock      atomic.Int64
	hubConns   []net.Conn
	cancel     context.CancelFunc
	done       chan struct{}
}

type nodeOpts struct {
	ca       *pkitest.CA
	notAfter time.Time
	direct   bool
	// directPort 0 picks a free port on the LAN address.
	directPort int
	// links lists "svc.machine" link keys.
	links []string
	// noIdentity leaves the identity directory empty (for enrollment).
	noIdentity bool
	// noStart prepares the node without running the agent.
	noStart bool
	// cacheTTL overrides the direct cache window (default 1h).
	cacheTTL time.Duration
}

type healthStub struct{}

func (healthStub) Ready() error           { return nil }
func (healthStub) Alive() error           { return nil }
func (healthStub) Promote() error         { return nil }
func (healthStub) Fail(_, _ string) error { return nil }
func (healthStub) Restart() error         { return nil }

func (n *node) nowFn() time.Time { return time.Now().Add(time.Duration(n.clock.Load())) }

func (m *mesh) hubTLS() *tls.Config {
	return &tls.Config{RootCAs: m.pool, ServerName: "localhost"}
}

func (m *mesh) newNode(name string, o nodeOpts) *node {
	m.t.Helper()

	t := m.t
	n := &node{m: m, name: name, identity: "agent-" + name, t3stop: make(chan struct{}), done: make(chan struct{})}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		mt := 0

		for k := range r.Header {
			if strings.HasPrefix(strings.ToLower(k), "x-mtls-") {
				mt++
			}
		}

		_, _ = fmt.Fprintf(w, "t3@%s mtls=%d", name, mt)
	})
	mux.HandleFunc("/hold", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "first\n")
		w.(http.Flusher).Flush() //nolint:forcetypeassert // httptest ResponseWriter

		select {
		case <-r.Context().Done():
		case <-n.t3stop:
		case <-time.After(30 * time.Second):
		}
	})

	n.t3 = httptest.NewServer(mux)

	t.Cleanup(func() {
		close(n.t3stop)
		n.t3.CloseClientConnections()
		n.t3.Close()
	})

	dir := t.TempDir()
	n.linkPort = freePort(t, "127.0.0.1")

	links := map[string]string{}
	for _, k := range o.links {
		links[k] = fmt.Sprintf("127.0.0.1:%d", n.linkPort)
	}

	n.directPort = o.directPort
	if o.direct && n.directPort == 0 {
		n.directPort = freePort(t, m.direct.String())
	}

	n.cfg = &agentconfig.Config{
		Serve:      map[string]string{"t3": n.t3.Listener.Addr().String()},
		Links:      links,
		Identity:   agentconfig.Identity{Name: n.identity, Dir: filepath.Join(dir, "identity")},
		Direct:     agentconfig.Direct{Enabled: o.direct, Port: n.directPort, CacheTTL: cmpTTL(o.cacheTTL)},
		StateDir:   filepath.Join(dir, "state"),
		InstallDir: filepath.Join(dir, "install"),
		Hub:        m.hubAddr,
	}

	// A first start has no cached home prefixes, so the first Hello would list no
	// direct addresses. Seed them as an agent that has connected before would have.
	if o.direct {
		seed := &state.Cache{FormatVersion: state.FormatVersion, HomeCIDRs: m.cfg.home}
		if err := state.Save(n.cfg.StateDir, seed); err != nil {
			t.Fatal(err)
		}
	}

	if !o.noIdentity {
		ca := o.ca
		if ca == nil {
			ca = m.ca
		}

		notAfter := o.notAfter
		if notAfter.IsZero() {
			notAfter = time.Now().Add(365 * 24 * time.Hour)
		}

		cert, certPEM, _ := ca.IssueIdentity(t, n.identity, true, notAfter)
		store := pki.Store{Dir: n.cfg.Identity.Dir}

		if err := store.SaveKey(cert.PrivateKey.(*ecdsa.PrivateKey)); err != nil { //nolint:forcetypeassert // ECDSA from pkitest
			t.Fatal(err)
		}

		if err := store.SaveCert(certPEM, ca.CertPEM); err != nil {
			t.Fatal(err)
		}

		n.cert = cert
		m.fake.SetNewest(n.identity, pki.Fingerprint(cert.Leaf))
	}

	if !o.noStart {
		n.start()
	}

	return n
}

// start runs the agent and waits until the hub sees it.
func (n *node) start() {
	n.m.t.Helper()

	a, err := agent.New(agent.Options{
		Config: n.cfg, Version: "dev", Log: logger(), Now: n.nowFn,
		HubTLS: n.m.hubTLS(), Health: healthStub{},
		LocalAddrs: func() ([]netip.Addr, error) { return []netip.Addr{n.m.direct}, nil },
		GatewayMAC: func() (string, error) { return fixedGatewayMAC, nil },
	})
	if err != nil {
		n.m.t.Fatal(err)
	}

	before := n.m.tl.count()
	ctx, cancel := context.WithCancel(context.Background())
	n.cancel = cancel

	errc := make(chan error, 1)

	go func() {
		errc <- a.Run(ctx)

		close(n.done)
	}()

	n.m.t.Cleanup(func() {
		cancel()

		select {
		case <-n.done:
		case <-time.After(15 * time.Second):
			n.m.t.Errorf("agent %s did not stop", n.name)
		}
	})

	n.m.waitConnected(n.name)

	select {
	case err = <-errc:
		n.m.t.Fatalf("agent %s exited: %v", n.name, err)
	default:
	}

	n.hubConns = n.m.tl.since(before)
}

// dropTunnel closes the hub side of the TCP connections this node opened at start.
func (n *node) dropTunnel() {
	for _, c := range n.hubConns {
		_ = c.Close()
	}
}

func (n *node) linkURL(path string) string {
	return fmt.Sprintf("http://127.0.0.1:%d%s", n.linkPort, path)
}

// waitDirectListening waits until the node's direct port accepts TCP.
func (n *node) waitDirectListening() {
	n.m.t.Helper()

	addr := net.JoinHostPort(n.m.direct.String(), fmt.Sprint(n.directPort))

	eventually(n.m.t, 10*time.Second, n.name+" direct listener", func() bool {
		c, err := net.DialTimeout("tcp", addr, time.Second)
		if err != nil {
			return false
		}

		_ = c.Close()

		return true
	})
}

// ---- clients ----

var httpc = &http.Client{
	Timeout:   15 * time.Second,
	Transport: &http.Transport{DisableKeepAlives: true},
}

func get(t *testing.T, url string, hdr http.Header, host string) (int, string) {
	t.Helper()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}

	for k, v := range hdr {
		req.Header[k] = v
	}

	if host != "" {
		req.Host = host
	}

	resp, err := httpc.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}

	defer func() { _ = resp.Body.Close() }()

	b, _ := io.ReadAll(resp.Body)

	return resp.StatusCode, strings.TrimSpace(string(b))
}

// phone is a viewer identity as Traefik would present it to the hub.
type phone struct {
	cert tls.Certificate
	fp   string
}

func (m *mesh) newPhone() phone {
	m.t.Helper()

	cert, _, _ := m.ca.IssueIdentity(m.t, "z-phone", false, time.Now().Add(365*24*time.Hour))

	return phone{cert: cert, fp: pki.Fingerprint(cert.Leaf)}
}

func (p phone) headers() http.Header {
	h := http.Header{}
	h.Set("X-Mtls-Mesh-Viewer", "z-phone")
	h.Set("X-Mtls-Mesh-Fingerprint", p.fp)
	h.Set("X-Mtls-Mesh-Not-After", p.cert.Leaf.NotAfter.UTC().Format(time.RFC3339))

	return h
}

func (m *mesh) viewerGet(p phone, machine, path string) (int, string) {
	m.t.Helper()

	return get(m.t, m.viewer.URL+path, p.headers(), "t3."+machine+"."+viewerDomain)
}

// held is an open streaming response whose first chunk has been read. A
// goroutine drains the rest and closes ended when the stream stops.
type held struct {
	resp  *http.Response
	br    *bufio.Reader
	ended chan struct{}
}

func (h *held) close() { _ = h.resp.Body.Close() }

// waitEnd waits until the stream is cut (read error or EOF).
func (h *held) waitEnd(t *testing.T, d time.Duration) {
	t.Helper()

	select {
	case <-h.ended:
	case <-time.After(d):
		t.Fatalf("stream still open after %s", d)
	}
}

// isOpen reports whether the stream is still running after a short grace.
func (h *held) isOpen() bool {
	select {
	case <-h.ended:
		return false
	case <-time.After(300 * time.Millisecond):
		return true
	}
}

// tryHold opens a streaming request and reads its first chunk. The caller owns
// the returned stream.
func tryHold(url string, hdr http.Header, host string) (*held, error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("request: %w", err)
	}

	for k, v := range hdr {
		req.Header[k] = v
	}

	if host != "" {
		req.Host = host
	}

	c := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}

	resp, err := c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("open stream: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()

		return nil, fmt.Errorf("open stream: status %d", resp.StatusCode)
	}

	h := &held{resp: resp, br: bufio.NewReader(resp.Body), ended: make(chan struct{})}

	line, err := h.br.ReadString('\n')
	if err != nil || line != "first\n" {
		h.close()

		return nil, fmt.Errorf("first chunk: %q, %v", line, err)
	}

	go func() {
		_, _ = io.Copy(io.Discard, h.br)

		close(h.ended)
	}()

	return h, nil
}

func openHold(t *testing.T, url string, hdr http.Header, host string) *held {
	t.Helper()

	h, err := tryHold(url, hdr, host)
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(h.close)

	return h
}

// openViewerHold opens a streaming request through the viewer handler.
func (m *mesh) openViewerHold(p phone, machine string) *held {
	m.t.Helper()

	return openHold(m.t, m.viewer.URL+"/hold", p.headers(), "t3."+machine+"."+viewerDomain)
}

func cmpTTL(d time.Duration) time.Duration {
	if d == 0 {
		return time.Hour
	}

	return d
}
