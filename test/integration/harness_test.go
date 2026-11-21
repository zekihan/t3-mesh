package integration

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
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

var errOpenStream = errors.New("open stream: status")

const viewerDomain = "mesh.test"

func eventually(t *testing.T, dur time.Duration, what string, cond func() bool) {
	t.Helper()

	deadline := time.Now().Add(dur)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}

		<-time.After(20 * time.Millisecond)
	}

	t.Fatalf("timed out after %s waiting for: %s", dur, what)
}

func logger() *slog.Logger {
	if os.Getenv("T3_TEST_LOG") != "" {
		return slog.New(
			slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}),
		)
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
		ln, err := new(net.ListenConfig).Listen(t.Context(), "tcp", net.JoinHostPort(host, "0"))
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
	home     []string
	devices  []string
	// api lists the identities that may call the hub API.
	api []string
	// rulesA and rulesB add identities to the mesh-t3-a and mesh-t3-b rules.
	rulesA      []string
	rulesB      []string
	noRelayRule bool
	tcp         bool
	noTCPRule   bool
}

func (hc *hubCfg) yaml() string {
	rel := hc.release
	if rel == "" {
		rel = "v0.3.0"
	}

	list := func(in []string) string { return "[" + strings.Join(in, ",") + "]" }

	quoted := make([]string, len(hc.home))
	for i, h := range hc.home {
		quoted[i] = `"` + h + `"`
	}

	aIDs := append([]string{"z-phone"}, hc.rulesA...)

	bIDs := make([]string, 0, 2+len(hc.rulesB))
	bIDs = append(bIDs, "z-phone")

	if !hc.noRelayRule {
		bIDs = append(bIDs, "agent-a")
	}

	bIDs = append(bIDs, hc.rulesB...)

	var tcpService, tcpRule string
	if hc.tcp {
		tcpService = ", ssh: {kind: tcp}"

		if !hc.noTCPRule {
			tcpRule = "\n    mesh-ssh-b: {identities: [agent-a, z-phone]}"
		}
	}

	return fmt.Sprintf(`
machines:
  a: {identity: agent-a, services: {t3: {kind: http}}}
  b: {identity: agent-b, services: {t3: {kind: http}%s}}
homeCIDRs: %s
viewerDomain: %s
release: {version: %s}
api: {identities: %s}
devices: %s
policy:
  entries:
    mesh-t3-a: {identities: %s}
    mesh-t3-b: {identities: %s}%s
  disabledIdentities: %s
  blockedFingerprints: %s
`, tcpService, list(quoted), viewerDomain, rel, list(hc.api), list(hc.devices), list(aIDs), list(bIDs), tcpRule,
		list(hc.disabled), list(hc.blocked))
}

// ---- mesh (hub side) ----

// trackListener records accepted connections so tests can cut a tunnel.
type trackListener struct {
	net.Listener

	conns []net.Conn
	mu    sync.Mutex
	// refuse closes new connections at once, keeping agents that dial out.
	refuse atomic.Bool
}

func (lst *trackListener) Accept() (net.Conn, error) {
	for {
		conn, err := lst.Listener.Accept()
		if err == nil && lst.refuse.Load() {
			_ = conn.Close()

			continue
		}

		return lst.record(conn, err)
	}
}

func (lst *trackListener) record(conn net.Conn, err error) (net.Conn, error) {
	if err == nil {
		lst.mu.Lock()
		lst.conns = append(lst.conns, conn)
		lst.mu.Unlock()
	}

	return conn, err
}

func (lst *trackListener) count() int {
	lst.mu.Lock()
	defer lst.mu.Unlock()

	return len(lst.conns)
}

func (lst *trackListener) since(n int) []net.Conn {
	lst.mu.Lock()
	defer lst.mu.Unlock()

	return append([]net.Conn(nil), lst.conns[n:]...)
}

type meshOpts struct {
	extraCAs []*pkitest.CA
	cfg      hubCfg
}

type mesh struct {
	direct  netip.Addr
	ops     *httptest.Server
	viewer  *httptest.Server
	stopHub func()
	ca      *pkitest.CA
	watcher *hubconfig.Watcher
	srv     *hub.Server
	pool    *x509.CertPool
	t       *testing.T
	tl      *trackListener
	tokens  *enroll.Tokens
	fake    *issuertest.Fake
	paths   hubconfig.Paths
	hubAddr string
	dir     string
	cfg     hubCfg
	clock   atomic.Int64
}

func (msh *mesh) now() time.Time { return time.Now().Add(time.Duration(msh.clock.Load())) }

func writeAtomic(t *testing.T, tmpDir, path, content string) {
	t.Helper()

	tmp, err := os.CreateTemp(tmpDir, "w-*")
	if err != nil {
		t.Fatal(err)
	}

	_, err = tmp.WriteString(content)
	if err != nil {
		t.Fatal(err)
	}

	err = tmp.Close()
	if err != nil {
		t.Fatal(err)
	}

	err = os.Rename(tmp.Name(), path)
	if err != nil {
		t.Fatal(err)
	}
}

func newMesh(t *testing.T, opts *meshOpts) *mesh {
	t.Helper()

	msh := &mesh{
		t:      t,
		ca:     pkitest.NewCA(t, "clients"),
		dir:    t.TempDir(),
		cfg:    opts.cfg,
		direct: directAddr(),
	}
	msh.pool = x509.NewCertPool()
	msh.pool.AddCert(msh.ca.Cert)
	msh.paths = hubconfig.Paths{
		ConfigDir: filepath.Join(msh.dir, "config"),
		TrustDir:  filepath.Join(msh.dir, "trust"),
		CertDir:   filepath.Join(msh.dir, "cert"),
	}

	for _, d := range []string{msh.paths.ConfigDir, msh.paths.TrustDir, msh.paths.CertDir, filepath.Join(msh.dir, "tmp")} {
		err := os.MkdirAll(d, 0o755) //nolint:gosec // test directory is not secret
		if err != nil {
			t.Fatal(err)
		}
	}

	if msh.cfg.home == nil {
		msh.cfg.home = []string{"127.0.0.0/8"}
		if msh.direct.IsValid() && !msh.direct.IsLoopback() {
			msh.cfg.home = append(msh.cfg.home, msh.direct.String()+"/32")
		}
	}

	msh.writeConfig(&msh.cfg)
	msh.writeTrust("trust-1", append([]*pkitest.CA{msh.ca}, opts.extraCAs...)...)

	srvCert := msh.ca.IssueServer(t, "localhost", "127.0.0.1")

	keyDER, err := x509.MarshalPKCS8PrivateKey(srvCert.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}

	tmp := filepath.Join(msh.dir, "tmp")
	writeAtomic(t, tmp, filepath.Join(msh.paths.CertDir, hubconfig.CertFile),
		string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srvCert.Certificate[0]})))
	writeAtomic(t, tmp, filepath.Join(msh.paths.CertDir, hubconfig.KeyFile),
		string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})))

	msh.watcher, err = hubconfig.NewWatcher(msh.paths, logger())
	if err != nil {
		t.Fatal(err)
	}

	msh.fake = &issuertest.Fake{Sign: func(csr []byte) ([]byte, []byte, error) {
		return msh.ca.SignCSR(csr, 365*24*time.Hour)
	}}
	msh.tokens = enroll.NewTokens(msh.now)

	msh.srv, err = hub.New(hub.Options{
		Config: msh.watcher, Issuer: msh.fake, Tokens: msh.tokens, Log: logger(), Now: msh.now,
	})
	if err != nil {
		t.Fatal(err)
	}

	ln, err := new(net.ListenConfig).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	msh.tl = &trackListener{Listener: ln}
	msh.hubAddr = ln.Addr().String()

	ctx, cancel := context.WithCancel(t.Context())

	var wg sync.WaitGroup

	wg.Go(func() { _ = msh.watcher.Run(ctx, msh.srv.OnConfigChange) })
	wg.Go(func() { _ = msh.srv.ServeTunnels(ctx, msh.tl) })

	msh.viewer = httptest.NewServer(msh.srv.ViewerHandler())
	msh.ops = httptest.NewServer(msh.srv.OpsHandler())

	var once sync.Once

	msh.stopHub = func() {
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

	t.Cleanup(msh.stopHub)
	t.Cleanup(func() {
		msh.viewer.CloseClientConnections()
		msh.viewer.Close()
		msh.ops.Close()
	})

	eventually(t, 5*time.Second, "hub ready", msh.srv.Ready)

	return msh
}

func (msh *mesh) writeConfig(c *hubCfg) {
	msh.t.Helper()
	msh.cfg = *c
	msh.writeRaw(c.yaml())
}

func (msh *mesh) writeRaw(content string) {
	msh.t.Helper()
	writeAtomic(
		msh.t,
		filepath.Join(msh.dir, "tmp"),
		filepath.Join(msh.paths.ConfigDir, hubconfig.ConfigFile),
		content,
	)
}

func (msh *mesh) writeTrust(rev string, cas ...*pkitest.CA) {
	msh.t.Helper()

	var b strings.Builder
	for _, ca := range cas {
		b.Write(ca.CertPEM)
	}

	tmp := filepath.Join(msh.dir, "tmp")
	writeAtomic(msh.t, tmp, filepath.Join(msh.paths.TrustDir, hubconfig.TrustFile), b.String())
	writeAtomic(msh.t, tmp, filepath.Join(msh.paths.TrustDir, hubconfig.RevFile), rev)
}

// update rewrites config.yaml and waits until the hub watcher loaded it.
func (msh *mesh) update(f func(c *hubCfg)) {
	msh.t.Helper()

	old := msh.watcher.Current().Fingerprint
	c := msh.cfg

	f(&c)
	msh.writeConfig(&c)

	eventually(
		msh.t,
		5*time.Second,
		"hub reloads config",
		func() bool { return msh.watcher.Current().Fingerprint != old },
	)
}

// ---- status ----

type machineStatus struct {
	CertNotAfter *time.Time      `json:"certNotAfter"`
	Alerts       map[string]bool `json:"alerts"`
	Acked        struct {
		Release     string `json:"release"`
		Rules       string `json:"rules"`
		Revocations string `json:"revocations"`
		TrustBundle string `json:"trustBundle"`
	} `json:"acked"`
	Warnings       []string `json:"warnings"`
	Sessions       int      `json:"sessions"`
	OpenStreams    int64    `json:"openStreams"`
	LinkStreams    int64    `json:"linkStreams"`
	DirectSessions int      `json:"directSessions"`
	Connected      bool     `json:"connected"`
}

type statusDoc struct {
	Machines map[string]machineStatus `json:"machines"`
	Release  struct {
		Version  string `json:"version"`
		Revision string `json:"revision"`
	} `json:"release"`
	PolicyRevision      string `json:"policyRevision"`
	TrustBundleRevision string `json:"trustBundleRevision"`
	ConfigError         string `json:"configError"`
	Stale               bool   `json:"stale"`
}

// get issues a GET bound to the test's context.
func (msh *mesh) get(url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(msh.t.Context(), http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}

	return resp, nil
}

func (msh *mesh) status() statusDoc {
	msh.t.Helper()

	resp, err := msh.get(msh.ops.URL + "/status")
	if err != nil {
		msh.t.Fatalf("status: %v", err)
	}

	defer func() { _ = resp.Body.Close() }()

	var doc statusDoc

	err = json.NewDecoder(resp.Body).Decode(&doc)
	if err != nil {
		msh.t.Fatalf("decode status: %v", err)
	}

	return doc
}

func (msh *mesh) opsGet(path string) (int, string) {
	msh.t.Helper()

	resp, err := msh.get(msh.ops.URL + path)
	if err != nil {
		msh.t.Fatalf("GET %s: %v", path, err)
	}

	defer func() { _ = resp.Body.Close() }()

	b, _ := io.ReadAll(resp.Body)

	return resp.StatusCode, strings.TrimSpace(string(b))
}

func (msh *mesh) waitConnected(machine string) {
	msh.t.Helper()
	eventually(
		msh.t,
		10*time.Second,
		machine+" connected to hub",
		func() bool { return msh.status().Machines[machine].Connected },
	)
}

// rawDial opens a TLS connection to the hub without any protocol on top.
func (msh *mesh) rawDial(cert *tls.Certificate, alpn string) (*tls.Conn, error) {
	cfg := &tls.Config{
		RootCAs:    msh.pool,
		ServerName: "localhost",
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{alpn},
	}
	if cert != nil {
		cfg.Certificates = []tls.Certificate{*cert}
	}

	d := net.Dialer{Timeout: 5 * time.Second}

	raw, err := d.Dial("tcp", msh.hubAddr)
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}

	conn := tls.Client(raw, cfg)

	err = conn.HandshakeContext(msh.t.Context())
	if err != nil {
		_ = raw.Close()

		return nil, fmt.Errorf("handshake: %w", err)
	}

	return conn, nil
}

// ---- nodes (agent side) ----

type node struct {
	cert   tls.Certificate
	t3     *httptest.Server
	m      *mesh
	t3stop chan struct{}
	cfg    *agentconfig.Config
	cancel context.CancelFunc
	done   chan struct{}
	// netCh feeds the agent's network events when nodeOpts.fakeNet is set. It is
	// unbuffered: once a second send returns, the first event has been handled.
	netCh  chan netwatch.Event
	lookup atomic.Pointer[lookupFn]
	// gateway is the default gateway's MAC the agent sees; tests move the machine to
	// another network by changing it.
	gateway     atomic.Value
	identity    string
	name        string
	hubConns    []net.Conn
	linkPort    int
	directPort  int
	devicePort  int
	clock       atomic.Int64
	lookupCalls atomic.Int64
	dnsRecheck  time.Duration
	localGone   atomic.Bool
	fakeNetwork bool
}

type lookupFn func(ctx context.Context, host string) ([]string, error)

type nodeOpts struct {
	ca       *pkitest.CA
	notAfter time.Time
	// hubName dials the hub by this name instead of 127.0.0.1, so the agent
	// runs the DNS re-resolve check.
	hubName string
	// t3Addr is the host:port of a real T3 server to serve, in place of the
	// stand-in the node starts otherwise.
	t3Addr     string
	tcpAddr    string
	links      []string
	directPort int
	cacheTTL   time.Duration
	dnsRecheck time.Duration
	direct     bool
	// devices turns on the listener for enrolled devices, which needs direct.
	devices    bool
	noIdentity bool
	noStart    bool
	// fakeNet replaces the OS network watcher, the hub lookup and the local
	// address check with test-controlled ones.
	fakeNet bool
}

type healthStub struct{}

func (healthStub) Ready() error           { return nil }
func (healthStub) Alive() error           { return nil }
func (healthStub) Promote() error         { return nil }
func (healthStub) Fail(_, _ string) error { return nil }
func (healthStub) Restart() error         { return nil }

func (nd *node) nowFn() time.Time { return time.Now().Add(time.Duration(nd.clock.Load())) }

func (msh *mesh) hubTLS() *tls.Config {
	return &tls.Config{RootCAs: msh.pool, ServerName: "localhost"}
}

func (msh *mesh) newNode(name string, opts *nodeOpts) *node {
	msh.t.Helper()

	t := msh.t
	nd := &node{
		m:        msh,
		name:     name,
		identity: "agent-" + name,
		t3stop:   make(chan struct{}),
		done:     make(chan struct{}),
	}

	t3Addr := opts.t3Addr
	if t3Addr == "" {
		nd.startT3(name)

		t3Addr = nd.t3.Listener.Addr().String()
	}

	dir := t.TempDir()
	nd.linkPort = freePort(t, "127.0.0.1")

	links := map[string]string{}
	for _, k := range opts.links {
		links[k] = fmt.Sprintf("127.0.0.1:%d", nd.linkPort)
	}

	nd.directPort = opts.directPort
	if opts.direct && nd.directPort == 0 {
		nd.directPort = freePort(t, msh.direct.String())
	}

	nd.gateway.Store(fixedGatewayMAC)

	if opts.direct && opts.devices {
		nd.devicePort = freePort(t, msh.direct.String())
	}

	nd.cfg = &agentconfig.Config{
		Serve:    map[string]string{"t3": t3Addr},
		Links:    links,
		Identity: agentconfig.Identity{Name: nd.identity, Dir: filepath.Join(dir, "identity")},
		Direct: agentconfig.Direct{
			Enabled:  opts.direct,
			Port:     nd.directPort,
			CacheTTL: cmpTTL(opts.cacheTTL),
			Devices:  agentconfig.Devices{Enabled: opts.devices, Port: nd.devicePort},
		},
		StateDir:   filepath.Join(dir, "state"),
		InstallDir: filepath.Join(dir, "install"),
		Hub:        msh.hubAddr,
	}

	if opts.tcpAddr != "" {
		nd.cfg.Serve["ssh"] = opts.tcpAddr
	}

	if opts.hubName != "" {
		nd.cfg.Hub = net.JoinHostPort(opts.hubName, msh.hubPort())
	}

	nd.fakeNetwork = opts.fakeNet
	nd.dnsRecheck = opts.dnsRecheck
	nd.netCh = make(chan netwatch.Event)

	// A first start has no cached home prefixes, so the first Hello would list no
	// direct addresses. Seed them as an agent that has connected before would have.
	if opts.direct {
		seed := &state.Cache{FormatVersion: state.FormatVersion, HomeCIDRs: msh.cfg.home}

		err := state.Save(nd.cfg.StateDir, seed)
		if err != nil {
			t.Fatal(err)
		}
	}

	if !opts.noIdentity {
		msh.seedIdentity(nd, opts)
	}

	if !opts.noStart {
		nd.start()
	}

	return nd
}

// startT3 runs the node's stand-in for the local T3.
func (nd *node) startT3(name string) {
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
	// /headers describes the request as T3 got it.
	mux.HandleFunc("/headers", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		_ = json.NewEncoder(w).Encode(struct {
			Header http.Header `json:"headers"`
			Host   string      `json:"host"`
			Method string      `json:"method"`
		}{Header: r.Header, Host: r.Host, Method: r.Method})
	})
	// /ws echoes what follows an upgrade.
	mux.HandleFunc("/ws", func(w http.ResponseWriter, _ *http.Request) {
		conn, _, err := http.NewResponseController(w).Hijack()
		if err != nil {
			return
		}

		defer func() { _ = conn.Close() }()

		_, _ = io.WriteString(
			conn,
			"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n"+
				"X-Stand-In: t3\r\n\r\n",
		)
		_, _ = io.Copy(conn, conn)
	})
	mux.HandleFunc("/hold", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "first\n")
		w.(http.Flusher).Flush() //nolint:forcetypeassert // httptest ResponseWriter

		select {
		case <-r.Context().Done():
		case <-nd.t3stop:
		case <-time.After(30 * time.Second):
		}
	})

	nd.t3 = httptest.NewServer(mux)

	nd.m.t.Cleanup(func() {
		close(nd.t3stop)
		nd.t3.CloseClientConnections()
		nd.t3.Close()
	})
}

// seedIdentity issues the node's identity certificate and stores it.
func (msh *mesh) seedIdentity(nd *node, opts *nodeOpts) {
	t := msh.t

	ca := opts.ca
	if ca == nil {
		ca = msh.ca
	}

	notAfter := opts.notAfter
	if notAfter.IsZero() {
		notAfter = time.Now().Add(365 * 24 * time.Hour)
	}

	cert, certPEM, _ := ca.IssueIdentity(t, nd.identity, true, notAfter)
	store := pki.Store{Dir: nd.cfg.Identity.Dir}

	key, ok := cert.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("identity key is %T, want *ecdsa.PrivateKey", cert.PrivateKey)
	}

	err := store.SaveKey(key)
	if err != nil {
		t.Fatal(err)
	}

	err = store.SaveCert(certPEM, ca.CertPEM)
	if err != nil {
		t.Fatal(err)
	}

	nd.cert = cert
	msh.fake.SetNewest(nd.identity, pki.Fingerprint(cert.Leaf))
}

// start runs the agent and waits until the hub sees it.
func (nd *node) start() {
	nd.m.t.Helper()

	before := nd.m.tl.count()
	errc := nd.launch()

	nd.m.waitConnected(nd.name)

	select {
	case err := <-errc:
		nd.m.t.Fatalf("agent %s exited: %v", nd.name, err)
	default:
	}

	nd.hubConns = nd.m.tl.since(before)
}

// launch runs the agent without waiting for the hub, as after a reboot during an
// outage. The returned channel carries its exit error.
func (nd *node) launch() <-chan error {
	nd.m.t.Helper()

	done := make(chan struct{})
	nd.done = done

	aopts := agent.Options{
		Config: nd.cfg, Version: "dev", Log: logger(), Now: nd.nowFn,
		HubTLS: nd.m.hubTLS(), Health: healthStub{},
		LocalAddrs: func() ([]netip.Addr, error) { return []netip.Addr{nd.m.direct}, nil },
		GatewayMAC: func() (string, error) {
			mac, _ := nd.gateway.Load().(string)

			return mac, nil
		},
	}

	if nd.fakeNetwork {
		aopts.NetEvents = nd.netCh
		aopts.LookupHost = nd.doLookup
		aopts.AddrPresent = func(netip.Addr) bool { return !nd.localGone.Load() }
		aopts.DNSRecheckInterval = nd.dnsRecheck
	}

	agt, err := agent.New(aopts)
	if err != nil {
		nd.m.t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	nd.cancel = cancel

	errc := make(chan error, 1)

	go func() {
		errc <- agt.Run(ctx)

		close(done)
	}()

	nd.m.t.Cleanup(func() {
		cancel()

		select {
		case <-done:
		case <-time.After(15 * time.Second):
			nd.m.t.Errorf("agent %s did not stop", nd.name)
		}
	})

	return errc
}

// stop ends the agent and waits for it to finish; start or launch runs it again.
func (nd *node) stop() {
	nd.m.t.Helper()

	nd.cancel()

	select {
	case <-nd.done:
	case <-time.After(15 * time.Second):
		nd.m.t.Fatalf("agent %s did not stop", nd.name)
	}
}

// dropTunnel closes the hub side of the TCP connections this node opened at start.
func (nd *node) dropTunnel() {
	for _, c := range nd.hubConns {
		_ = c.Close()
	}
}

func (nd *node) linkURL(path string) string {
	return fmt.Sprintf("http://127.0.0.1:%d%s", nd.linkPort, path)
}

// waitDirectListening waits until the node's direct port accepts TCP.
func (nd *node) waitDirectListening() {
	nd.m.t.Helper()

	addr := net.JoinHostPort(nd.m.direct.String(), strconv.Itoa(nd.directPort))

	eventually(nd.m.t, 10*time.Second, nd.name+" direct listener", func() bool {
		c, err := (&net.Dialer{Timeout: time.Second}).DialContext(nd.m.t.Context(), "tcp", addr)
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

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, url, http.NoBody)
	if err != nil {
		t.Fatal(err)
	}

	maps.Copy(req.Header, hdr)

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

func (msh *mesh) newPhone() phone {
	msh.t.Helper()

	cert, _, _ := msh.ca.IssueIdentity(msh.t, "z-phone", false, time.Now().Add(365*24*time.Hour))

	return phone{cert: cert, fp: pki.Fingerprint(cert.Leaf)}
}

func (p *phone) headers() http.Header {
	h := http.Header{}
	h.Set("X-Mtls-Mesh-Viewer", "urn:noqer:mtls:clients:z-phone")
	h.Set("X-Mtls-Mesh-Fingerprint", p.fp)
	h.Set("X-Mtls-Mesh-Not-After", p.cert.Leaf.NotAfter.UTC().Format(time.RFC3339))

	return h
}

func (msh *mesh) viewerGet(p *phone, machine, path string) (int, string) {
	msh.t.Helper()

	return get(msh.t, msh.viewer.URL+path, p.headers(), "t3."+machine+"."+viewerDomain)
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
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("request: %w", err)
	}

	maps.Copy(req.Header, hdr)

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

		return nil, fmt.Errorf("%w %d", errOpenStream, resp.StatusCode)
	}

	hold := &held{resp: resp, br: bufio.NewReader(resp.Body), ended: make(chan struct{})}

	line, err := hold.br.ReadString('\n')
	if err != nil || line != "first\n" {
		hold.close()

		return nil, fmt.Errorf("first chunk: %q, %w", line, err)
	}

	go func() {
		_, _ = io.Copy(io.Discard, hold.br)

		close(hold.ended)
	}()

	return hold, nil
}

func openHold(t *testing.T, url string, hdr http.Header, host string) *held {
	t.Helper()

	hold, err := tryHold(url, hdr, host)
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(hold.close)

	return hold
}

// openViewerHold opens a streaming request through the viewer handler.
func (msh *mesh) openViewerHold(p *phone, machine string) *held {
	msh.t.Helper()

	return openHold(msh.t, msh.viewer.URL+"/hold", p.headers(), "t3."+machine+"."+viewerDomain)
}

func cmpTTL(d time.Duration) time.Duration {
	if d == 0 {
		return time.Hour
	}

	return d
}

func (msh *mesh) hubPort() string {
	_, port, err := net.SplitHostPort(msh.hubAddr)
	if err != nil {
		msh.t.Fatal(err)
	}

	return port
}

// doLookup is the agent's hub lookup; setLookup chooses the answer.
func (nd *node) doLookup(ctx context.Context, host string) ([]string, error) {
	nd.lookupCalls.Add(1)

	fn := nd.lookup.Load()
	if fn == nil {
		return []string{"127.0.0.1"}, nil
	}

	return (*fn)(ctx, host)
}

func (nd *node) setLookup(fn lookupFn) { nd.lookup.Store(&fn) }

// netEvent delivers ev to the agent and returns once the agent has handled it:
// the loop is single-threaded, so a second send only completes after the first
// event's path check finished.
func (nd *node) netEvent(kind netwatch.EventKind) { nd.sendNetEvents(kind, 2) }

// sendNetEvents sends n events back to back.
func (nd *node) sendNetEvents(kind netwatch.EventKind, count int) {
	nd.m.t.Helper()

	for range count {
		select {
		case nd.netCh <- netwatch.Event{At: time.Now(), Kind: kind}:
		case <-time.After(10 * time.Second):
			nd.m.t.Fatal("agent did not take the network event")
		}
	}
}
