package hub

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
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/yamux"

	"github.com/zekihan/t3-mesh/internal/hub/hubconfig"
	"github.com/zekihan/t3-mesh/internal/hub/issuer/issuertest"
	"github.com/zekihan/t3-mesh/internal/pki"
	"github.com/zekihan/t3-mesh/internal/pki/pkitest"
	"github.com/zekihan/t3-mesh/internal/policy"
	"github.com/zekihan/t3-mesh/internal/proto"
	"github.com/zekihan/t3-mesh/internal/tunnel"
)

const viewerFP = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

type cfgOpts struct {
	release  string
	disabled []string
	blocked  []string
	api      []string
	devices  []string
	noCIDRs  bool
}

//nolint:gocritic // test options are passed by value so call sites stay literals
func (opts cfgOpts) yaml() string {
	rel := opts.release
	if rel == "" {
		rel = "v0.3.0"
	}

	dis, blk := "[]", "[]"
	if len(opts.disabled) > 0 {
		dis = "[" + strings.Join(opts.disabled, ",") + "]"
	}

	if len(opts.blocked) > 0 {
		blk = "[" + strings.Join(opts.blocked, ",") + "]"
	}

	apiIDs := "[]"
	if len(opts.api) > 0 {
		apiIDs = "[" + strings.Join(opts.api, ",") + "]"
	}

	devices := "[]"
	if len(opts.devices) > 0 {
		devices = "[" + strings.Join(opts.devices, ",") + "]"
	}

	cidrs := "[127.0.0.0/8]"
	if opts.noCIDRs {
		cidrs = "[]"
	}

	return fmt.Sprintf(`
machines:
  devbox: {identity: agent-devbox, services: {t3: {kind: http}}}
  z-arch: {identity: agent-z-arch, services: {t3: {kind: http}}}
homeCIDRs: %s
viewerDomain: mesh.test
release: {version: %s}
api: {identities: %s}
devices: %s
policy:
  entries:
    mesh-t3-devbox: {identities: [z-phone, z-viewer, agent-z-arch, device-z-phone-mesh, device-z-tablet-mesh]}
    mesh-t3-z-arch: {identities: [z-phone, device-z-phone-mesh]}
  disabledIdentities: %s
  blockedFingerprints: %s
`, cidrs, rel, apiIDs, devices, dis, blk)
}

type env struct {
	t       *testing.T
	ca      *pkitest.CA
	watcher *hubconfig.Watcher
	fake    *issuertest.Fake
	srv     *Server
	viewer  *httptest.Server
	ops     *httptest.Server
	pool    *x509.CertPool
	paths   hubconfig.Paths
	dir     string
	addr    string
	offset  atomic.Int64
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()

	err := os.WriteFile(path, []byte(content), 0o600)
	if err != nil {
		t.Fatal(err)
	}
}

func newEnv(t *testing.T) *env {
	t.Helper()

	harness := &env{t: t, ca: pkitest.NewCA(t, "clients"), dir: t.TempDir()}
	harness.paths = hubconfig.Paths{
		ConfigDir: filepath.Join(harness.dir, "config"),
		TrustDir:  filepath.Join(harness.dir, "trust"),
		CertDir:   filepath.Join(harness.dir, "cert"),
	}

	for _, d := range []string{harness.paths.ConfigDir, harness.paths.TrustDir, harness.paths.CertDir} {
		err := os.MkdirAll(d, 0o750)
		if err != nil {
			t.Fatal(err)
		}
	}

	writeFile(t, filepath.Join(harness.paths.ConfigDir, hubconfig.ConfigFile), cfgOpts{}.yaml())
	writeFile(
		t,
		filepath.Join(harness.paths.TrustDir, hubconfig.TrustFile),
		string(harness.ca.CertPEM),
	)
	writeFile(t, filepath.Join(harness.paths.TrustDir, hubconfig.RevFile), "trust-1")

	srvCert := harness.ca.IssueServer(t, "localhost", "127.0.0.1")

	keyDER, err := x509.MarshalPKCS8PrivateKey(srvCert.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}

	writeFile(t, filepath.Join(harness.paths.CertDir, hubconfig.CertFile),
		string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srvCert.Certificate[0]})))
	writeFile(t, filepath.Join(harness.paths.CertDir, hubconfig.KeyFile),
		string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})))

	harness.watcher, err = hubconfig.NewWatcher(harness.paths, nil)
	if err != nil {
		t.Fatal(err)
	}

	harness.fake = &issuertest.Fake{
		Sign: func(csr []byte) ([]byte, []byte, error) { return harness.ca.SignCSR(csr, 24*time.Hour) },
	}
	harness.pool = x509.NewCertPool()
	harness.pool.AddCert(harness.ca.Cert)

	harness.srv, err = New(Options{
		Config: harness.watcher, Issuer: harness.fake,
		Now: func() time.Time { return time.Now().Add(time.Duration(harness.offset.Load())) },
	})
	if err != nil {
		t.Fatal(err)
	}

	harness.srv.sweepInt = 100 * time.Millisecond

	var lc net.ListenConfig

	ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	harness.addr = ln.Addr().String()

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)

	go func() { done <- harness.srv.ServeTunnels(ctx, ln) }()

	harness.viewer = httptest.NewServer(harness.srv.ViewerHandler())
	harness.ops = httptest.NewServer(harness.srv.OpsHandler())

	t.Cleanup(func() {
		harness.viewer.Close()
		harness.ops.Close()
		cancel()

		select {
		case err := <-done:
			if err != nil {
				t.Errorf("ServeTunnels: %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Error("ServeTunnels did not stop")
		}
	})

	eventually(t, func() bool { return harness.srv.Ready() })

	return harness
}

//nolint:gocritic // test options are passed by value so call sites stay literals
func (harness *env) setConfig(o cfgOpts) {
	harness.t.Helper()
	writeFile(harness.t, filepath.Join(harness.paths.ConfigDir, hubconfig.ConfigFile), o.yaml())
	harness.watcher.Reload(harness.srv.OnConfigChange)
}

func eventually(t *testing.T, cond func() bool) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)

	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()

	for time.Now().Before(deadline) {
		if cond() {
			return
		}

		<-tick.C
	}

	t.Fatal("condition not met in time")
}

type agent struct {
	ack      proto.HelloAck
	cert     tls.Certificate
	t        *testing.T
	conn     *tls.Conn
	ymx      *yamux.Session
	ctrl     *tunnel.Control
	msgs     chan proto.Message
	backend  *httptest.Server
	identity string
	fp       string
}

func backendHandler(body string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/hdr", func(w http.ResponseWriter, r *http.Request) {
		var mt []string

		for k := range r.Header {
			if strings.HasPrefix(strings.ToLower(k), "x-mtls-") {
				mt = append(mt, k)
			}
		}

		//nolint:gosec // test backend echoing fixed strings and request metadata, not served to browsers
		_, _ = fmt.Fprintf(
			w,
			"%s host=%s origin=%s mtls=%d proto=%s",
			body,
			r.Host,
			r.Header.Get("Origin"),
			len(mt),
			r.Header.Get("X-Forwarded-Proto"),
		)
	})
	mux.HandleFunc("/stream", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "first\n")
		_ = http.NewResponseController(w).Flush()

		select {
		case <-r.Context().Done():
		case <-time.After(10 * time.Second):
		}
	})
	// /sink and /ws-hold model a backend that ignores the hub closing its side:
	// revocation must not depend on the backend hanging up.
	mux.HandleFunc("/sink", func(_ http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)

		<-time.After(6 * time.Second)
	})
	mux.HandleFunc("/ws-hold", func(w http.ResponseWriter, _ *http.Request) {
		conn, _, err := http.NewResponseController(w).Hijack()
		if err != nil {
			return
		}

		defer func() { _ = conn.Close() }()

		_, _ = io.WriteString(
			conn,
			"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
		)
		_, _ = io.Copy(io.Discard, conn)

		<-time.After(6 * time.Second)
	})
	mux.HandleFunc("/ws", func(w http.ResponseWriter, _ *http.Request) {
		conn, _, err := http.NewResponseController(w).Hijack()
		if err != nil {
			return
		}

		defer func() { _ = conn.Close() }()

		_, _ = io.WriteString(
			conn,
			"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
		)
		_, _ = io.Copy(conn, conn)
	})

	return mux
}

// dial connects without completing the tunnel protocol.
func (harness *env) dial(cert *tls.Certificate, alpn string) (*tls.Conn, error) {
	cfg := &tls.Config{
		RootCAs:    harness.pool,
		ServerName: "localhost",
		MinVersion: tls.VersionTLS13,
	}
	if alpn != "" {
		cfg.NextProtos = []string{alpn}
	}

	if cert != nil {
		cfg.Certificates = []tls.Certificate{*cert}
	}

	dialer := &tls.Dialer{Config: cfg}

	conn, err := dialer.DialContext(harness.t.Context(), "tcp", harness.addr)
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}

	tc, ok := conn.(*tls.Conn)
	if !ok {
		_ = conn.Close()

		return nil, errNotTLSConn
	}

	return tc, nil
}

func (harness *env) newCert(identity string, notAfter time.Time) tls.Certificate {
	harness.t.Helper()

	cert, _, _ := harness.ca.IssueIdentity(harness.t, identity, true, notAfter)
	fp := pki.Fingerprint(cert.Leaf)
	harness.fake.SetNewest(identity, fp)

	return cert
}

// connect opens a tunnel with a fresh leaf and the given backend body.
func (harness *env) connect(identity, body string) *agent {
	harness.t.Helper()

	cert := harness.newCert(identity, time.Now().Add(365*24*time.Hour))

	a, err := harness.connectWith(identity, &cert, body)
	if err != nil {
		harness.t.Fatalf("connect %s: %v", identity, err)
	}

	return a
}

var (
	errNotTLSConn        = errors.New("dial did not return a TLS connection")
	errNoHelloAck        = errors.New("control closed before HelloAck")
	errUnexpectedMessage = errors.New("unexpected message")
	errHelloAckTimeout   = errors.New("timeout waiting for HelloAck")
)

type rejectError struct{ proto.Reject }

func (r *rejectError) Error() string { return "rejected: " + r.Reason }

func (harness *env) connectWith(
	identity string,
	cert *tls.Certificate,
	body string,
) (*agent, error) {
	harness.t.Helper()

	conn, err := harness.dial(cert, proto.TunnelALPN(1))
	if err != nil {
		return nil, err
	}

	ymx, err := yamux.Client(conn, tunnel.YamuxConfig())
	if err != nil {
		return nil, fmt.Errorf("yamux: %w", err)
	}

	st, err := ymx.OpenStream()
	if err != nil {
		return nil, fmt.Errorf("open control: %w", err)
	}

	fakeAgent := &agent{
		t:        harness.t,
		identity: identity,
		cert:     *cert,
		fp:       pki.Fingerprint(cert.Leaf),
		conn:     conn,
		ymx:      ymx,
		ctrl:     tunnel.NewControl(st),
		msgs:     make(chan proto.Message, 64),
		backend:  httptest.NewServer(backendHandler(body)),
	}
	harness.t.Cleanup(func() { fakeAgent.close() })

	err = fakeAgent.ctrl.Send(proto.Hello{
		Version: "v0.3.0", Services: []string{"t3"}, LANAddrs: []string{"192.168.1.5"},
		DirectPort: 27400, CertFingerprint: fakeAgent.fp,
	})
	if err != nil {
		return nil, fmt.Errorf("send hello: %w", err)
	}

	select {
	case msg, ok := <-fakeAgent.ctrl.Messages():
		if !ok {
			return nil, errNoHelloAck
		}

		switch m := msg.(type) {
		case proto.HelloAck:
			fakeAgent.ack = m
		case proto.Reject:
			return nil, &rejectError{m}
		default:
			return nil, fmt.Errorf("%w: %s", errUnexpectedMessage, msg.MessageType())
		}
	case <-time.After(5 * time.Second):
		return nil, errHelloAckTimeout
	}

	go func() {
		for m := range fakeAgent.ctrl.Messages() {
			fakeAgent.msgs <- m
		}

		close(fakeAgent.msgs)
	}()

	go fakeAgent.acceptLoop()

	return fakeAgent, nil
}

func (fakeAgent *agent) close() {
	_ = fakeAgent.ymx.Close()
	fakeAgent.backend.Close()
}

func (fakeAgent *agent) acceptLoop() {
	for {
		st, err := fakeAgent.ymx.AcceptStream()
		if err != nil {
			return
		}

		go func() {
			var hdr proto.StreamHeader

			err := proto.ReadLine(st, &hdr)
			if err != nil {
				_ = st.Close()

				return
			}

			if hdr.From != "" {
				err = proto.WriteLine(st, proto.StreamReply{OK: true})
				if err != nil {
					return
				}
			}

			var dialer net.Dialer

			backendConn, err := dialer.DialContext(
				fakeAgent.t.Context(),
				"tcp",
				fakeAgent.backend.Listener.Addr().String(),
			)
			if err != nil {
				_ = st.Close()

				return
			}

			tunnel.Join(st, backendConn)
		}()
	}
}

//nolint:ireturn // returns the decoded wire message, whose concrete type the caller inspects
func (fakeAgent *agent) next(match func(proto.Message) bool) proto.Message {
	fakeAgent.t.Helper()

	timeout := time.After(5 * time.Second)

	for {
		select {
		case m, ok := <-fakeAgent.msgs:
			if !ok {
				fakeAgent.t.Fatal("control closed while waiting for message")
			}

			if match(m) {
				return m
			}
		case <-timeout:
			fakeAgent.t.Fatal("timeout waiting for message")
		}
	}
}

func (fakeAgent *agent) waitClosed() {
	fakeAgent.t.Helper()

	select {
	case <-fakeAgent.ymx.CloseChan():
	case <-time.After(5 * time.Second):
		fakeAgent.t.Fatal("session not closed")
	}
}

func (harness *env) get(
	host, viewer, fp string,
	notAfter time.Time,
	path string,
) (int, string) {
	harness.t.Helper()

	req, _ := http.NewRequestWithContext(
		harness.t.Context(),
		http.MethodGet,
		harness.viewer.URL+path,
		http.NoBody,
	)
	req.Host = host
	setViewerHeaders(req.Header, viewer, fp, notAfter)
	req.Header.Set("Origin", "https://"+host)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		harness.t.Fatal(err)
	}

	defer func() { _ = resp.Body.Close() }()

	b, _ := io.ReadAll(resp.Body)

	return resp.StatusCode, string(b)
}

// setViewerHeaders sets the headers traefik-mtls-authz forwards. viewer is an
// identity name sent as its URI SAN; a leading "=" sends the rest verbatim.
func setViewerHeaders(header http.Header, viewer, fp string, notAfter time.Time) {
	if raw, ok := strings.CutPrefix(viewer, "="); ok {
		header.Set(HeaderViewer, raw)
	} else if viewer != "" {
		header.Set(HeaderViewer, policy.IdentityURI(viewer))
	}

	if fp != "" {
		header.Set(HeaderFingerprint, fp)
	}

	if !notAfter.IsZero() {
		header.Set(HeaderNotAfter, notAfter.Format(time.RFC3339))
	}
}

var farFuture = time.Now().Add(24 * time.Hour)

func TestViewerProxy(t *testing.T) {
	e := newEnv(t)
	e.connect("agent-devbox", "devbox-body")

	req, _ := http.NewRequestWithContext(
		t.Context(),
		http.MethodGet,
		e.viewer.URL+"/hdr",
		http.NoBody,
	)
	req.Host = "t3.devbox.mesh.test"
	setViewerHeaders(req.Header, "z-phone", viewerFP, farFuture)
	req.Header.Set("X-Mtls-Other", "x")
	req.Header.Set("Origin", "https://t3.devbox.mesh.test")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = resp.Body.Close() }()

	b, _ := io.ReadAll(resp.Body)

	want := "devbox-body host=t3.devbox.mesh.test origin=https://t3.devbox.mesh.test mtls=0 proto=https"
	if resp.StatusCode != http.StatusOK || string(b) != want {
		t.Fatalf("got %d %q, want %q", resp.StatusCode, b, want)
	}
}

func TestViewerUpgrade(t *testing.T) {
	e := newEnv(t)
	e.connect("agent-devbox", "devbox-body")

	var dialer net.Dialer

	conn, err := dialer.DialContext(t.Context(), "tcp", e.viewer.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	hdr := http.Header{}
	setViewerHeaders(hdr, "z-phone", viewerFP, farFuture)

	var sb strings.Builder
	sb.WriteString(
		"GET /ws HTTP/1.1\r\nHost: t3.devbox.mesh.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n",
	)
	_ = hdr.Write(&sb)
	sb.WriteString("\r\n")

	_, err = io.WriteString(conn, sb.String())
	if err != nil {
		t.Fatal(err)
	}

	br := bufio.NewReader(conn)

	resp, err := http.ReadResponse(br, nil)
	if err != nil || resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade: %v %v", resp, err)
	}

	defer func() { _ = resp.Body.Close() }()

	_, _ = io.WriteString(conn, "hello\n")

	line, err := br.ReadString('\n')
	if err != nil || line != "hello\n" {
		t.Fatalf("echo = %q, %v", line, err)
	}
}

func TestViewerRejections(t *testing.T) {
	harness := newEnv(t)
	harness.connect("agent-devbox", "devbox-body")

	cases := []struct {
		notAfter time.Time
		name     string
		host     string
		viewer   string
		fp       string
		want     int
	}{
		{
			name:     "no viewer",
			host:     "t3.devbox.mesh.test",
			viewer:   "",
			fp:       viewerFP,
			notAfter: farFuture,
			want:     403,
		},
		{
			name:     "no fingerprint",
			host:     "t3.devbox.mesh.test",
			viewer:   "z-phone",
			fp:       "",
			notAfter: farFuture,
			want:     403,
		},
		{
			name:     "no not-after",
			host:     "t3.devbox.mesh.test",
			viewer:   "z-phone",
			fp:       viewerFP,
			notAfter: time.Time{},
			want:     403,
		},
		{
			name:     "bad fingerprint",
			host:     "t3.devbox.mesh.test",
			viewer:   "z-phone",
			fp:       "xyz",
			notAfter: farFuture,
			want:     403,
		},
		{
			name:     "bare name",
			host:     "t3.devbox.mesh.test",
			viewer:   "=z-phone",
			fp:       viewerFP,
			notAfter: farFuture,
			want:     403,
		},
		{
			name:     "foreign URI",
			host:     "t3.devbox.mesh.test",
			viewer:   "=urn:other:z-phone",
			fp:       viewerFP,
			notAfter: farFuture,
			want:     403,
		},
		{
			name:     "agent as viewer",
			host:     "t3.devbox.mesh.test",
			viewer:   "agent-z-arch",
			fp:       viewerFP,
			notAfter: farFuture,
			want:     403,
		},
		{
			name:     "unknown host",
			host:     "t3.nope.mesh.test",
			viewer:   "z-phone",
			fp:       viewerFP,
			notAfter: farFuture,
			want:     404,
		},
		{
			name:     "not allowed",
			host:     "t3.devbox.mesh.test",
			viewer:   "z-other",
			fp:       viewerFP,
			notAfter: farFuture,
			want:     403,
		},
		{
			name:     "expired",
			host:     "t3.devbox.mesh.test",
			viewer:   "z-phone",
			fp:       viewerFP,
			notAfter: time.Now().Add(-time.Minute),
			want:     403,
		},
		{
			name:     "offline",
			host:     "t3.z-arch.mesh.test",
			viewer:   "z-phone",
			fp:       viewerFP,
			notAfter: farFuture,
			want:     502,
		},
	}

	for _, c := range cases {
		status, body := harness.get(c.host, c.viewer, c.fp, c.notAfter, "/hdr")
		if status != c.want {
			t.Errorf("%s: status %d, want %d", c.name, status, c.want)
		}

		if c.name == "offline" && !strings.Contains(body, "z-arch") {
			t.Errorf("offline page does not name the machine: %q", body)
		}
	}
}

func TestNonAgentAndCertlessRefused(t *testing.T) {
	harness := newEnv(t)

	dead := func(conn *tls.Conn, err error) {
		t.Helper()

		if err != nil {
			return
		}

		defer func() { _ = conn.Close() }()

		_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))

		_, rerr := conn.Read(make([]byte, 1))

		var ne net.Error
		if rerr == nil || (errors.As(rerr, &ne) && ne.Timeout()) {
			t.Fatalf("connection was not refused: %v", rerr)
		}
	}

	phone, _, _ := harness.ca.IssueIdentity(t, "z-phone", false, farFuture)
	harness.fake.SetNewest("z-phone", pki.Fingerprint(phone.Leaf))
	dead(harness.dial(&phone, proto.TunnelALPN(1)))
	dead(harness.dial(nil, proto.TunnelALPN(1)))
	dead(harness.dial(nil, proto.ALPNEnroll))

	// An unconfigured agent-looking identity is refused too.
	rogue, _, _ := harness.ca.IssueIdentity(t, "agent-rogue", true, farFuture)
	dead(harness.dial(&rogue, proto.TunnelALPN(1)))

	// A phone cert through the full client flow gets no session.
	_, err := harness.connectWith("z-phone", &phone, "x")
	if err == nil {
		t.Fatal("phone certificate opened a tunnel")
	}

	// With a token outstanding the enroll ALPN is accepted without a cert.
	_, _, err = harness.srv.tokens.Create("agent-devbox")
	if err != nil {
		t.Fatal(err)
	}

	conn, err := harness.dial(nil, proto.ALPNEnroll)
	if err != nil {
		t.Fatal(err)
	}

	_ = conn.Close()
}

func TestPlainTLSProbe(t *testing.T) {
	harness := newEnv(t)

	closed := func(cert *tls.Certificate) {
		t.Helper()

		conn, err := harness.dial(cert, "")
		if err != nil {
			t.Fatalf("probe handshake: %v", err)
		}

		defer func() { _ = conn.Close() }()

		if len(conn.ConnectionState().PeerCertificates) == 0 {
			t.Fatal("probe saw no serving certificate")
		}

		_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))

		_, err = conn.Read(make([]byte, 1))
		if !errors.Is(err, io.EOF) {
			t.Fatalf("probe read = %v, want EOF", err)
		}
	}

	closed(nil)

	phone, _, _ := harness.ca.IssueIdentity(t, "z-phone", false, farFuture)
	closed(&phone)

	// A client that offers only an unknown protocol still fails the handshake.
	conn, err := harness.dial(nil, "h2")
	if err == nil {
		_ = conn.Close()

		t.Fatal("unknown ALPN completed the handshake")
	}
}

func TestRelayAllowedAndDenied(t *testing.T) {
	harness := newEnv(t)
	harness.connect("agent-devbox", "devbox-body")
	arch := harness.connect("agent-z-arch", "arch-body")

	open := func(a *agent, to string) (net.Conn, proto.StreamReply) {
		st, err := a.ymx.OpenStream()
		if err != nil {
			t.Fatal(err)
		}

		_ = st.SetDeadline(time.Now().Add(5 * time.Second))

		err = proto.WriteLine(st, proto.StreamHeader{To: to})
		if err != nil {
			t.Fatal(err)
		}

		var reply proto.StreamReply

		err = proto.ReadLine(st, &reply)
		if err != nil {
			t.Fatal(err)
		}

		return st, reply
	}

	st, reply := open(arch, "t3.devbox")
	if !reply.OK {
		t.Fatalf("relay refused: %+v", reply)
	}

	_, _ = io.WriteString(st, "GET /hdr HTTP/1.0\r\nHost: x\r\n\r\n")

	b, _ := io.ReadAll(st)
	if !strings.Contains(string(b), "devbox-body") {
		t.Fatalf("relayed response = %q", b)
	}

	// devbox may not reach z-arch (only z-phone is listed).
	devbox := harness.connect("agent-devbox", "devbox-2")
	if _, reply := open(devbox, "t3.z-arch"); reply.OK {
		t.Fatal("relay allowed against rules")
	}

	if _, reply := open(arch, "t3.nowhere"); reply.OK {
		t.Fatal("relay to unknown target allowed")
	}
}

func TestNewestSessionWins(t *testing.T) {
	harness := newEnv(t)
	harness.connect("agent-devbox", "first")
	harness.connect("agent-devbox", "second")

	_, body := harness.get("t3.devbox.mesh.test", "z-phone", viewerFP, farFuture, "/hdr")
	if !strings.HasPrefix(body, "second ") {
		t.Fatalf("body = %q, want second session", body)
	}

	var st statusDoc
	getJSON(t, harness.ops.URL+"/status", &st)

	if st.Machines["devbox"].Sessions != 2 || !st.Machines["devbox"].Connected ||
		st.Machines["devbox"].Path != "LAN" {
		t.Fatalf("status = %+v", st.Machines["devbox"])
	}
}

// httpGet fetches target and returns the status code and body.
func httpGet(t *testing.T, target string) (int, []byte) {
	t.Helper()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, target, http.NoBody)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	return resp.StatusCode, body
}

func getJSON(t *testing.T, target string, out any) {
	t.Helper()

	_, body := httpGet(t, target)

	err := json.Unmarshal(body, out)
	if err != nil {
		t.Fatal(err)
	}
}

func openStream(t *testing.T, e *env, path string, notAfter time.Time) (io.Reader, func()) {
	t.Helper()

	return openStreamAs(t, e, "z-phone", viewerFP, path, notAfter)
}

func openStreamAs(
	t *testing.T,
	harness *env,
	viewer, fp, path string,
	notAfter time.Time,
) (io.Reader, func()) {
	t.Helper()

	req, _ := http.NewRequestWithContext(
		t.Context(),
		http.MethodGet,
		harness.viewer.URL+path,
		http.NoBody,
	)
	req.Host = "t3.devbox.mesh.test"
	setViewerHeaders(req.Header, viewer, fp, notAfter)

	//nolint:bodyclose // the returned func closes the body once the caller is done streaming
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	br := bufio.NewReader(resp.Body)

	line, err := br.ReadString('\n')
	if err != nil || line != "first\n" {
		t.Fatalf("first chunk = %q, %v", line, err)
	}

	return br, func() { _ = resp.Body.Close() }
}

func expectStreamClosed(t *testing.T, r io.Reader) {
	t.Helper()

	done := make(chan error, 1)

	go func() {
		_, err := io.Copy(io.Discard, r)
		done <- err
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("stream still open")
	}
}

func TestRevocationBlockedViewerLeaf(t *testing.T) {
	harness := newEnv(t)
	harness.connect("agent-devbox", "devbox-body")

	r, closeFn := openStream(t, harness, "/stream", farFuture)
	defer closeFn()

	harness.setConfig(cfgOpts{blocked: []string{viewerFP}})
	expectStreamClosed(t, r)

	if code, _ := harness.get(
		"t3.devbox.mesh.test",
		"z-phone",
		viewerFP,
		farFuture,
		"/hdr",
	); code != http.StatusForbidden {
		t.Fatalf("blocked viewer got %d", code)
	}
}

// rawViewer opens a viewer connection and sends head, returning the conn and
// a reader on it.
func rawViewer(t *testing.T, e *env, head string) (net.Conn, *bufio.Reader) {
	t.Helper()

	var dialer net.Dialer

	conn, err := dialer.DialContext(t.Context(), "tcp", e.viewer.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = conn.Close() })

	hdr := http.Header{}
	setViewerHeaders(hdr, "z-phone", viewerFP, farFuture)

	var sb strings.Builder
	sb.WriteString(head)
	_ = hdr.Write(&sb)
	sb.WriteString("\r\n")

	_, err = io.WriteString(conn, sb.String())
	if err != nil {
		t.Fatal(err)
	}

	return conn, bufio.NewReader(conn)
}

// expectViewerEnds waits until the viewer connection gets a response or is
// closed, ignoring anything already read.
func expectViewerEnds(t *testing.T, conn net.Conn, br *bufio.Reader) {
	t.Helper()

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	_, err := br.ReadByte()

	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		t.Fatal("viewer connection still open after revocation")
	}
}

func TestRevocationClosesUpgradedViewer(t *testing.T) {
	harness := newEnv(t)
	harness.connect("agent-devbox", "devbox-body")

	conn, br := rawViewer(
		t,
		harness,
		"GET /ws-hold HTTP/1.1\r\nHost: t3.devbox.mesh.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n",
	)

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	resp, err := http.ReadResponse(br, nil)
	if err != nil || resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade: %v %v", resp, err)
	}

	_ = resp.Body.Close()

	harness.setConfig(cfgOpts{blocked: []string{viewerFP}})
	expectViewerEnds(t, conn, br)
}

func TestRevocationEndsPendingViewerRequest(t *testing.T) {
	harness := newEnv(t)
	harness.connect("agent-devbox", "devbox-body")

	conn, br := rawViewer(t, harness,
		"POST /sink HTTP/1.1\r\nHost: t3.devbox.mesh.test\r\nContent-Length: 100000\r\n")

	// The body is still being uploaded when the leaf is blocked.
	_, err := io.WriteString(conn, "partial body")
	if err != nil {
		t.Fatal(err)
	}

	<-time.After(200 * time.Millisecond)

	harness.setConfig(cfgOpts{blocked: []string{viewerFP}})
	expectViewerEnds(t, conn, br)
}

func TestRevocationViewerRuleRemoved(t *testing.T) {
	e := newEnv(t)
	e.connect("agent-devbox", "devbox-body")

	r, closeFn := openStream(t, e, "/stream", farFuture)
	defer closeFn()

	e.setConfig(cfgOpts{disabled: []string{"z-phone"}})
	expectStreamClosed(t, r)
}

func TestStreamClosesAtNotAfter(t *testing.T) {
	e := newEnv(t)
	e.connect("agent-devbox", "devbox-body")

	r, closeFn := openStream(t, e, "/stream", time.Now().Add(2500*time.Millisecond))
	defer closeFn()

	expectStreamClosed(t, r)
}

func TestDisableAgentClosesTunnel(t *testing.T) {
	harness := newEnv(t)
	fakeAgent := harness.connect("agent-devbox", "devbox-body")

	harness.setConfig(cfgOpts{disabled: []string{"agent-devbox"}})

	m := fakeAgent.next(func(m proto.Message) bool {
		_, ok := m.(proto.Reject)

		return ok
	})
	if asReject(t, m).Reason != proto.RejectIdentityDisabled {
		t.Fatalf("reject = %+v", m)
	}

	fakeAgent.waitClosed()

	_, err := harness.connectWith("agent-devbox", &fakeAgent.cert, "again")
	if err == nil {
		t.Fatal("disabled agent reconnected")
	}
}

func TestBlockedAgentLeaf(t *testing.T) {
	e := newEnv(t)
	fakeAgent := e.connect("agent-devbox", "devbox-body")

	e.setConfig(cfgOpts{blocked: []string{fakeAgent.fp}})
	fakeAgent.next(func(m proto.Message) bool {
		_, ok := m.(proto.Reject)

		return ok
	})
	fakeAgent.waitClosed()
}

func TestLeafNotNewestRejected(t *testing.T) {
	e := newEnv(t)

	cert := e.newCert("agent-devbox", farFuture)
	e.fake.SetNewest("agent-devbox", strings.Repeat("b", 64))

	_, err := e.connectWith("agent-devbox", &cert, "x")

	var rj *rejectError
	if !errors.As(err, &rj) || rj.Reason != proto.RejectLeafNotNewest {
		t.Fatalf("err = %v, want leaf-not-newest", err)
	}
}

func TestNoIssuanceRecordAdmitted(t *testing.T) {
	e := newEnv(t)

	cert, _, _ := e.ca.IssueIdentity(t, "agent-devbox", true, farFuture)

	_, err := e.connectWith("agent-devbox", &cert, "x")
	if err != nil {
		t.Fatalf("leaf without record refused: %v", err)
	}
}

//nolint:ireturn // returns the decoded wire message, whose concrete type the caller inspects
func (fakeAgent *agent) renew(key *ecdsa.PrivateKey, identity string) proto.Message {
	fakeAgent.t.Helper()

	csr, err := pki.CreateCSR(key, identity)
	if err != nil {
		fakeAgent.t.Fatal(err)
	}

	err = fakeAgent.ctrl.Send(proto.Renew{CSR: string(csr)})
	if err != nil {
		fakeAgent.t.Fatal(err)
	}

	return fakeAgent.next(func(m proto.Message) bool {
		switch m.(type) {
		case proto.Renewed, proto.Reject:
			return true
		}

		return false
	})
}

func TestRenewal(t *testing.T) {
	harness := newEnv(t)
	fakeAgent := harness.connect("agent-devbox", "devbox-body")

	// Same key, wrong identity: rejected, session stays up.
	if rj, ok := fakeAgent.renew(fakeAgent.cert.PrivateKey.(*ecdsa.PrivateKey), "agent-devbox").(proto.Reject); !ok ||
		rj.Reason != proto.RejectRenewFailed {
		t.Fatalf("same-key renewal = %+v", rj)
	}

	key, err := pki.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	if rj, ok := fakeAgent.renew(key, "agent-z-arch").(proto.Reject); !ok ||
		rj.Reason != proto.RejectRenewFailed {
		t.Fatalf("foreign-identity renewal = %+v", rj)
	}

	renewed, ok := fakeAgent.renew(key, "agent-devbox").(proto.Renewed)
	if !ok {
		t.Fatal("renewal failed")
	}

	certs, err := pki.ParseCertsPEM([]byte(renewed.Certificate))
	if err != nil {
		t.Fatal(err)
	}

	eventually(t, func() bool {
		return slices.Contains(
			harness.fake.PruneCalls(),
			issuertest.PruneCall{Identity: "agent-devbox", Keep: 2},
		)
	})

	newest, _ := harness.fake.Newest(t.Context(), "agent-devbox")
	if newest != pki.Fingerprint(certs[0]) {
		t.Fatal("newest leaf not updated")
	}

	// Session still works; the new leaf is admitted, the old one is not.
	if _, body := harness.get(
		"t3.devbox.mesh.test",
		"z-phone",
		viewerFP,
		farFuture,
		"/hdr",
	); !strings.HasPrefix(
		body,
		"devbox-body",
	) {
		t.Fatalf("session broken after renewal: %q", body)
	}

	newCert := tls.Certificate{Certificate: [][]byte{certs[0].Raw}, PrivateKey: key, Leaf: certs[0]}

	_, err = harness.connectWith("agent-devbox", &newCert, "new")
	if err != nil {
		t.Fatalf("new leaf refused: %v", err)
	}

	_, err = harness.connectWith("agent-devbox", &fakeAgent.cert, "old")

	var rj *rejectError
	if !errors.As(err, &rj) || rj.Reason != proto.RejectLeafNotNewest {
		t.Fatalf("old leaf err = %v", err)
	}
}

func asReject(t *testing.T, msg proto.Message) proto.Reject {
	t.Helper()

	rej, ok := msg.(proto.Reject)
	if !ok {
		t.Fatalf("message %T is not a Reject", msg)
	}

	return rej
}

func asUpdate(t *testing.T, msg proto.Message) proto.Update {
	t.Helper()

	upd, ok := msg.(proto.Update)
	if !ok {
		t.Fatalf("message %T is not an Update", msg)
	}

	return upd
}

func asRelease(t *testing.T, msg proto.Message) proto.Release {
	t.Helper()

	rel, ok := msg.(proto.Release)
	if !ok {
		t.Fatalf("message %T is not a Release", msg)
	}

	return rel
}

func assertInitialAck(t *testing.T, arch *agent) {
	t.Helper()

	if len(arch.ack.Peers.Peers) != 1 || arch.ack.Peers.Peers[0].Machine != "devbox" ||
		arch.ack.Peers.Peers[0].Home {
		t.Fatalf("initial peers = %+v", arch.ack.Peers)
	}

	if !arch.ack.Home || len(arch.ack.HomeCIDRs) != 1 || arch.ack.Release.Version != "v0.3.0" ||
		arch.ack.Machine != "z-arch" {
		t.Fatalf("ack = %+v", arch.ack)
	}
}

func TestUpdatesPeersAndRelease(t *testing.T) {
	harness := newEnv(t)
	arch := harness.connect("agent-z-arch", "arch-body")

	assertInitialAck(t, arch)

	harness.connect("agent-devbox", "devbox-body")

	msg := arch.next(
		func(m proto.Message) bool {
			u, ok := m.(proto.Update)

			return ok && u.Peers != nil
		},
	)

	p := asUpdate(t, msg).Peers.Peers[0]
	if !p.Home || p.DirectPort != 27400 || len(p.LANAddrs) != 1 || p.LANAddrs[0] != "192.168.1.5" {
		t.Fatalf("peer = %+v", p)
	}

	harness.setConfig(cfgOpts{release: "v0.4.0"})

	rel := asRelease(t, arch.next(func(m proto.Message) bool {
		_, ok := m.(proto.Release)

		return ok
	}))
	if rel.Version != "v0.4.0" {
		t.Fatalf("release = %+v", rel)
	}

	harness.setConfig(cfgOpts{release: "v0.4.0", disabled: []string{"z-old"}})
	arch.next(
		func(m proto.Message) bool {
			u, ok := m.(proto.Update)

			return ok && u.Revocations != nil
		},
	)
}

func status(t *testing.T, e *env, name string) int {
	t.Helper()

	code, _ := httpGet(t, e.ops.URL+"/alerts/"+name)

	return code
}

func assertOpsEndpoints(t *testing.T, harness *env) {
	t.Helper()

	for path, want := range map[string]int{"/healthz": 200, "/readyz": 200, "/status": 200} {
		code, _ := httpGet(t, harness.ops.URL+path)
		if code != want {
			t.Errorf("%s = %d", path, code)
		}
	}

	if got := status(t, harness, "nonsense"); got != 404 {
		t.Errorf("unknown alert = %d", got)
	}

	if got := status(t, harness, "agent-ghost-disconnected"); got != 404 {
		t.Errorf("unknown machine alert = %d", got)
	}
}

func TestAlerts(t *testing.T) {
	harness := newEnv(t)

	assertOpsEndpoints(t, harness)

	// Short-lived leaf: cert-expiry fires for it only.
	cert := harness.newCert("agent-devbox", time.Now().Add(10*24*time.Hour))

	fakeAgent, err := harness.connectWith("agent-devbox", &cert, "devbox-body")
	if err != nil {
		t.Fatal(err)
	}

	harness.offset.Store(int64(11 * time.Minute))

	checks := map[string]int{
		"agent-devbox-disconnected":  200,
		"agent-z-arch-disconnected":  503,
		"agent-devbox-cert-expiry":   503,
		"agent-z-arch-cert-expiry":   200,
		"agent-devbox-update-failed": 200,
		"stale-config":               200,
	}
	for name, want := range checks {
		if got := status(t, harness, name); got != want {
			t.Errorf("%s = %d, want %d", name, got, want)
		}
	}

	err = fakeAgent.ctrl.Send(proto.Status{
		Version:       "v0.3.0",
		FailedUpdates: []proto.FailedUpdate{{Version: "v0.3.0", Reason: "crash", Attempts: 1}},
		RulesRevision: "r1",
	})
	if err != nil {
		t.Fatal(err)
	}

	eventually(t, func() bool { return status(t, harness, "agent-devbox-update-failed") == 503 })

	var st statusDoc
	getJSON(t, harness.ops.URL+"/status", &st)

	if st.Machines["devbox"].Acked.Rules != "r1" || len(st.Machines["devbox"].FailedUpdates) != 1 {
		t.Fatalf("status = %+v", st.Machines["devbox"])
	}

	// Stale config: an invalid mounted config that cannot be loaded.
	writeFile(t, filepath.Join(harness.paths.ConfigDir, hubconfig.ConfigFile), "not: [valid")
	harness.watcher.Reload(harness.srv.OnConfigChange)
	harness.offset.Store(int64(20 * time.Minute))

	if got := status(t, harness, "stale-config"); got != 503 {
		t.Errorf("stale-config = %d", got)
	}

	code, _ := httpGet(t, harness.ops.URL+"/readyz")
	if code != http.StatusOK {
		t.Errorf("readyz must not fail on stale config: status %d", code)
	}
}

func TestVersionLagAlert(t *testing.T) {
	harness := newEnv(t)
	harness.connect("agent-devbox", "devbox-body")
	harness.setConfig(cfgOpts{release: "v0.5.0"})

	if got := status(t, harness, "agent-devbox-update-failed"); got != 200 {
		t.Fatalf("fresh mismatch fires: %d", got)
	}

	harness.offset.Store(int64(61 * time.Minute))

	if got := status(t, harness, "agent-devbox-update-failed"); got != 503 {
		t.Fatalf("lagging agent = %d", got)
	}
}

func TestEmptyHomeCIDRsPushed(t *testing.T) {
	harness := newEnv(t)
	arch := harness.connect("agent-z-arch", "arch-body")

	if len(arch.ack.HomeCIDRs) != 1 {
		t.Fatalf("ack cidrs = %v", arch.ack.HomeCIDRs)
	}

	harness.setConfig(cfgOpts{noCIDRs: true})

	upd := asUpdate(t, arch.next(func(m proto.Message) bool {
		u, ok := m.(proto.Update)

		return ok && u.HomeCIDRs != nil
	}))
	if len(*upd.HomeCIDRs) != 0 {
		t.Fatalf("cidrs = %v", *upd.HomeCIDRs)
	}
}

func TestOfflinePeerKeepsLastAddrs(t *testing.T) {
	harness := newEnv(t)
	arch := harness.connect("agent-z-arch", "arch-body")
	devbox := harness.connect("agent-devbox", "devbox-body")

	arch.next(func(m proto.Message) bool {
		u, ok := m.(proto.Update)

		return ok && u.Peers != nil && u.Peers.Peers[0].Home
	})

	devbox.close()

	upd := asUpdate(t, arch.next(func(m proto.Message) bool {
		u, ok := m.(proto.Update)

		return ok && u.Peers != nil && !u.Peers.Peers[0].Home
	}))

	p := upd.Peers.Peers[0]
	if p.DirectPort != 27400 || len(p.LANAddrs) != 1 || p.LANAddrs[0] != "192.168.1.5" {
		t.Fatalf("offline peer = %+v", p)
	}

	// A reconnecting agent receives the same last-known addresses in its ack.
	again := harness.connect("agent-z-arch", "arch-body")

	q := again.ack.Peers.Peers[0]
	if q.Home || q.DirectPort != 27400 || len(q.LANAddrs) != 1 {
		t.Fatalf("ack peer = %+v", q)
	}
}
