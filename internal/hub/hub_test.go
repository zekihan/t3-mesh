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
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/yamux"

	"github.com/zekihan/t3-mesh/internal/hub/hubconfig"
	"github.com/zekihan/t3-mesh/internal/hub/issuer/issuertest"
	"github.com/zekihan/t3-mesh/internal/pki"
	"github.com/zekihan/t3-mesh/internal/pki/pkitest"
	"github.com/zekihan/t3-mesh/internal/proto"
	"github.com/zekihan/t3-mesh/internal/tunnel"
)

const viewerFP = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

type cfgOpts struct {
	disabled []string
	blocked  []string
	release  string
}

func (o cfgOpts) yaml() string {
	rel := o.release
	if rel == "" {
		rel = "v0.3.0"
	}

	dis, blk := "[]", "[]"
	if len(o.disabled) > 0 {
		dis = "[" + strings.Join(o.disabled, ",") + "]"
	}

	if len(o.blocked) > 0 {
		blk = "[" + strings.Join(o.blocked, ",") + "]"
	}

	return fmt.Sprintf(`
machines:
  devbox: {identity: agent-devbox, services: {t3: {kind: http}}}
  z-arch: {identity: agent-z-arch, services: {t3: {kind: http}}}
homeCIDRs: [127.0.0.0/8]
viewerDomain: mesh.test
release: {version: %s}
policy:
  entries:
    mesh-t3-devbox: {identities: [z-phone, agent-z-arch]}
    mesh-t3-z-arch: {identities: [z-phone]}
  disabledIdentities: %s
  blockedFingerprints: %s
`, rel, dis, blk)
}

type env struct {
	t       *testing.T
	ca      *pkitest.CA
	dir     string
	paths   hubconfig.Paths
	watcher *hubconfig.Watcher
	fake    *issuertest.Fake
	srv     *Server
	addr    string
	viewer  *httptest.Server
	ops     *httptest.Server
	offset  atomic.Int64
	pool    *x509.CertPool
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()

	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func newEnv(t *testing.T) *env {
	t.Helper()

	e := &env{t: t, ca: pkitest.NewCA(t, "clients"), dir: t.TempDir()}
	e.paths = hubconfig.Paths{
		ConfigDir: filepath.Join(e.dir, "config"),
		TrustDir:  filepath.Join(e.dir, "trust"),
		CertDir:   filepath.Join(e.dir, "cert"),
	}

	for _, d := range []string{e.paths.ConfigDir, e.paths.TrustDir, e.paths.CertDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	writeFile(t, filepath.Join(e.paths.ConfigDir, hubconfig.ConfigFile), cfgOpts{}.yaml())
	writeFile(t, filepath.Join(e.paths.TrustDir, hubconfig.TrustFile), string(e.ca.CertPEM))
	writeFile(t, filepath.Join(e.paths.TrustDir, hubconfig.RevFile), "trust-1")

	srvCert := e.ca.IssueServer(t, "localhost", "127.0.0.1")
	keyDER, err := x509.MarshalPKCS8PrivateKey(srvCert.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}

	writeFile(t, filepath.Join(e.paths.CertDir, hubconfig.CertFile),
		string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srvCert.Certificate[0]})))
	writeFile(t, filepath.Join(e.paths.CertDir, hubconfig.KeyFile),
		string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})))

	e.watcher, err = hubconfig.NewWatcher(e.paths, nil)
	if err != nil {
		t.Fatal(err)
	}

	e.fake = &issuertest.Fake{Sign: func(csr []byte) ([]byte, []byte, error) { return e.ca.SignCSR(csr, 24*time.Hour) }}
	e.pool = x509.NewCertPool()
	e.pool.AddCert(e.ca.Cert)

	e.srv, err = New(Options{
		Config: e.watcher, Issuer: e.fake,
		Now: func() time.Time { return time.Now().Add(time.Duration(e.offset.Load())) },
	})
	if err != nil {
		t.Fatal(err)
	}

	e.srv.sweepInt = 100 * time.Millisecond

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	e.addr = ln.Addr().String()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)

	go func() { done <- e.srv.ServeTunnels(ctx, ln) }()

	e.viewer = httptest.NewServer(e.srv.ViewerHandler())
	e.ops = httptest.NewServer(e.srv.OpsHandler())

	t.Cleanup(func() {
		e.viewer.Close()
		e.ops.Close()
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

	eventually(t, func() bool { return e.srv.Ready() })

	return e
}

func (e *env) setConfig(o cfgOpts) {
	e.t.Helper()
	writeFile(e.t, filepath.Join(e.paths.ConfigDir, hubconfig.ConfigFile), o.yaml())
	e.watcher.Reload(e.srv.OnConfigChange)
}

func eventually(t *testing.T, cond func() bool) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}

		time.Sleep(10 * time.Millisecond)
	}

	t.Fatal("condition not met in time")
}

type agent struct {
	t        *testing.T
	identity string
	cert     tls.Certificate
	fp       string
	conn     *tls.Conn
	ymx      *yamux.Session
	ctrl     *tunnel.Control
	ack      proto.HelloAck
	msgs     chan proto.Message
	backend  *httptest.Server
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

		_, _ = fmt.Fprintf(w, "%s host=%s origin=%s mtls=%d", body, r.Host, r.Header.Get("Origin"), len(mt))
	})
	mux.HandleFunc("/stream", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "first\n")
		w.(http.Flusher).Flush()

		select {
		case <-r.Context().Done():
		case <-time.After(10 * time.Second):
		}
	})
	mux.HandleFunc("/ws", func(w http.ResponseWriter, _ *http.Request) {
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}

		defer func() { _ = conn.Close() }()

		_, _ = io.WriteString(conn, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
		_, _ = io.Copy(conn, conn)
	})

	return mux
}

// dial connects without completing the tunnel protocol.
func (e *env) dial(cert *tls.Certificate, alpn string) (*tls.Conn, error) {
	cfg := &tls.Config{RootCAs: e.pool, ServerName: "localhost", MinVersion: tls.VersionTLS13, NextProtos: []string{alpn}}
	if cert != nil {
		cfg.Certificates = []tls.Certificate{*cert}
	}

	c, err := tls.Dial("tcp", e.addr, cfg)
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}

	return c, nil
}

func (e *env) newCert(identity string, notAfter time.Time) (tls.Certificate, string) {
	e.t.Helper()

	cert, _, _ := e.ca.IssueIdentity(e.t, identity, true, notAfter)
	fp := pki.Fingerprint(cert.Leaf)
	e.fake.SetNewest(identity, fp)

	return cert, fp
}

// connect opens a tunnel with a fresh leaf and the given backend body.
func (e *env) connect(identity, body string) *agent {
	e.t.Helper()

	cert, _ := e.newCert(identity, time.Now().Add(365*24*time.Hour))
	a, err := e.connectWith(identity, cert, body)
	if err != nil {
		e.t.Fatalf("connect %s: %v", identity, err)
	}

	return a
}

type rejectError struct{ proto.Reject }

func (r *rejectError) Error() string { return "rejected: " + r.Reason }

func (e *env) connectWith(identity string, cert tls.Certificate, body string) (*agent, error) {
	e.t.Helper()

	conn, err := e.dial(&cert, proto.TunnelALPN(1))
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

	a := &agent{
		t: e.t, identity: identity, cert: cert, fp: pki.Fingerprint(cert.Leaf), conn: conn, ymx: ymx,
		ctrl: tunnel.NewControl(st), msgs: make(chan proto.Message, 64),
		backend: httptest.NewServer(backendHandler(body)),
	}
	e.t.Cleanup(func() { a.close() })

	err = a.ctrl.Send(proto.Hello{
		Version: "v0.3.0", Services: []string{"t3"}, LANAddrs: []string{"192.168.1.5"},
		DirectPort: 27400, CertFingerprint: a.fp,
	})
	if err != nil {
		return nil, fmt.Errorf("send hello: %w", err)
	}

	select {
	case msg, ok := <-a.ctrl.Messages():
		if !ok {
			return nil, errors.New("control closed before HelloAck")
		}

		switch m := msg.(type) {
		case proto.HelloAck:
			a.ack = m
		case proto.Reject:
			return nil, &rejectError{m}
		default:
			return nil, fmt.Errorf("unexpected %s", msg.MessageType())
		}
	case <-time.After(5 * time.Second):
		return nil, errors.New("timeout waiting for HelloAck")
	}

	go func() {
		for m := range a.ctrl.Messages() {
			a.msgs <- m
		}

		close(a.msgs)
	}()

	go a.acceptLoop()

	return a, nil
}

func (a *agent) close() {
	_ = a.ymx.Close()
	a.backend.Close()
}

func (a *agent) acceptLoop() {
	for {
		st, err := a.ymx.AcceptStream()
		if err != nil {
			return
		}

		go func() {
			var hdr proto.StreamHeader
			if err := proto.ReadLine(st, &hdr); err != nil {
				_ = st.Close()

				return
			}

			if hdr.From != "" {
				if err := proto.WriteLine(st, proto.StreamReply{OK: true}); err != nil {
					return
				}
			}

			c, err := net.Dial("tcp", a.backend.Listener.Addr().String())
			if err != nil {
				_ = st.Close()

				return
			}

			tunnel.Join(st, c)
		}()
	}
}

func (a *agent) next(match func(proto.Message) bool) proto.Message {
	a.t.Helper()

	timeout := time.After(5 * time.Second)

	for {
		select {
		case m, ok := <-a.msgs:
			if !ok {
				a.t.Fatal("control closed while waiting for message")
			}

			if match(m) {
				return m
			}
		case <-timeout:
			a.t.Fatal("timeout waiting for message")
		}
	}
}

func (a *agent) waitClosed() {
	a.t.Helper()

	select {
	case <-a.ymx.CloseChan():
	case <-time.After(5 * time.Second):
		a.t.Fatal("session not closed")
	}
}

func (e *env) get(host, viewer, fp string, notAfter time.Time, path string) (*http.Response, string) {
	e.t.Helper()

	req, _ := http.NewRequest(http.MethodGet, e.viewer.URL+path, nil)
	req.Host = host
	setViewerHeaders(req.Header, viewer, fp, notAfter)
	req.Header.Set("Origin", "https://"+host)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}

	defer func() { _ = resp.Body.Close() }()

	b, _ := io.ReadAll(resp.Body)

	return resp, string(b)
}

func setViewerHeaders(h http.Header, viewer, fp string, notAfter time.Time) {
	if viewer != "" {
		h.Set(HeaderViewer, viewer)
	}

	if fp != "" {
		h.Set(HeaderFingerprint, fp)
	}

	if !notAfter.IsZero() {
		h.Set(HeaderNotAfter, notAfter.Format(time.RFC3339))
	}
}

var farFuture = time.Now().Add(24 * time.Hour)

func TestViewerProxy(t *testing.T) {
	e := newEnv(t)
	e.connect("agent-devbox", "devbox-body")

	req, _ := http.NewRequest(http.MethodGet, e.viewer.URL+"/hdr", nil)
	req.Host = "t3.devbox.mesh.test"
	setViewerHeaders(req.Header, "z-phone", viewerFP, farFuture)
	req.Header.Set("X-Mtls-Other", "x")
	req.Header.Set("Origin", "https://t3.devbox.mesh.test")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	want := "devbox-body host=t3.devbox.mesh.test origin=https://t3.devbox.mesh.test mtls=0"
	if resp.StatusCode != 200 || string(b) != want {
		t.Fatalf("got %d %q, want %q", resp.StatusCode, b, want)
	}
}

func TestViewerUpgrade(t *testing.T) {
	e := newEnv(t)
	e.connect("agent-devbox", "devbox-body")

	conn, err := net.Dial("tcp", e.viewer.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	hdr := http.Header{}
	setViewerHeaders(hdr, "z-phone", viewerFP, farFuture)

	var sb strings.Builder
	sb.WriteString("GET /ws HTTP/1.1\r\nHost: t3.devbox.mesh.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n")
	_ = hdr.Write(&sb)
	sb.WriteString("\r\n")

	if _, err := io.WriteString(conn, sb.String()); err != nil {
		t.Fatal(err)
	}

	br := bufio.NewReader(conn)

	resp, err := http.ReadResponse(br, nil)
	if err != nil || resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade: %v %v", resp, err)
	}

	_, _ = io.WriteString(conn, "hello\n")

	line, err := br.ReadString('\n')
	if err != nil || line != "hello\n" {
		t.Fatalf("echo = %q, %v", line, err)
	}
}

func TestViewerRejections(t *testing.T) {
	e := newEnv(t)
	e.connect("agent-devbox", "devbox-body")

	cases := []struct {
		name, host, viewer, fp string
		notAfter               time.Time
		want                   int
	}{
		{"no viewer", "t3.devbox.mesh.test", "", viewerFP, farFuture, 403},
		{"no fingerprint", "t3.devbox.mesh.test", "z-phone", "", farFuture, 403},
		{"no not-after", "t3.devbox.mesh.test", "z-phone", viewerFP, time.Time{}, 403},
		{"bad fingerprint", "t3.devbox.mesh.test", "z-phone", "xyz", farFuture, 403},
		{"agent as viewer", "t3.devbox.mesh.test", "agent-z-arch", viewerFP, farFuture, 403},
		{"unknown host", "t3.nope.mesh.test", "z-phone", viewerFP, farFuture, 404},
		{"not allowed", "t3.devbox.mesh.test", "z-other", viewerFP, farFuture, 403},
		{"expired", "t3.devbox.mesh.test", "z-phone", viewerFP, time.Now().Add(-time.Minute), 403},
		{"offline", "t3.z-arch.mesh.test", "z-phone", viewerFP, farFuture, 502},
	}

	for _, c := range cases {
		resp, body := e.get(c.host, c.viewer, c.fp, c.notAfter, "/hdr")
		if resp.StatusCode != c.want {
			t.Errorf("%s: status %d, want %d", c.name, resp.StatusCode, c.want)
		}

		if c.name == "offline" && !strings.Contains(body, "z-arch") {
			t.Errorf("offline page does not name the machine: %q", body)
		}
	}
}

func TestNonAgentAndCertlessRefused(t *testing.T) {
	e := newEnv(t)

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

	phone, _, _ := e.ca.IssueIdentity(t, "z-phone", false, farFuture)
	e.fake.SetNewest("z-phone", pki.Fingerprint(phone.Leaf))
	dead(e.dial(&phone, proto.TunnelALPN(1)))
	dead(e.dial(nil, proto.TunnelALPN(1)))
	dead(e.dial(nil, proto.ALPNEnroll))

	// An unconfigured agent-looking identity is refused too.
	rogue, _, _ := e.ca.IssueIdentity(t, "agent-rogue", true, farFuture)
	dead(e.dial(&rogue, proto.TunnelALPN(1)))

	// A phone cert through the full client flow gets no session.
	if _, err := e.connectWith("z-phone", phone, "x"); err == nil {
		t.Fatal("phone certificate opened a tunnel")
	}

	// With a token outstanding the enroll ALPN is accepted without a cert.
	if _, _, err := e.srv.tokens.Create("agent-devbox"); err != nil {
		t.Fatal(err)
	}

	conn, err := e.dial(nil, proto.ALPNEnroll)
	if err != nil {
		t.Fatal(err)
	}

	_ = conn.Close()
}

func TestRelayAllowedAndDenied(t *testing.T) {
	e := newEnv(t)
	e.connect("agent-devbox", "devbox-body")
	arch := e.connect("agent-z-arch", "arch-body")

	open := func(a *agent, to string) (net.Conn, proto.StreamReply) {
		st, err := a.ymx.OpenStream()
		if err != nil {
			t.Fatal(err)
		}

		_ = st.SetDeadline(time.Now().Add(5 * time.Second))

		if err := proto.WriteLine(st, proto.StreamHeader{To: to}); err != nil {
			t.Fatal(err)
		}

		var reply proto.StreamReply
		if err := proto.ReadLine(st, &reply); err != nil {
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
	devbox := e.connect("agent-devbox", "devbox-2")
	if _, reply := open(devbox, "t3.z-arch"); reply.OK {
		t.Fatal("relay allowed against rules")
	}

	if _, reply := open(arch, "t3.nowhere"); reply.OK {
		t.Fatal("relay to unknown target allowed")
	}
}

func TestNewestSessionWins(t *testing.T) {
	e := newEnv(t)
	e.connect("agent-devbox", "first")
	e.connect("agent-devbox", "second")

	_, body := e.get("t3.devbox.mesh.test", "z-phone", viewerFP, farFuture, "/hdr")
	if !strings.HasPrefix(body, "second ") {
		t.Fatalf("body = %q, want second session", body)
	}

	var st statusDoc
	getJSON(t, e.ops.URL+"/status", &st)

	if st.Machines["devbox"].Sessions != 2 || !st.Machines["devbox"].Connected || st.Machines["devbox"].Path != "LAN" {
		t.Fatalf("status = %+v", st.Machines["devbox"])
	}
}

func getJSON(t *testing.T, url string, v any) {
	t.Helper()

	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = resp.Body.Close() }()

	if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
		t.Fatal(err)
	}
}

func openStream(t *testing.T, e *env, path string, notAfter time.Time) (io.Reader, func()) {
	t.Helper()

	req, _ := http.NewRequest(http.MethodGet, e.viewer.URL+path, nil)
	req.Host = "t3.devbox.mesh.test"
	setViewerHeaders(req.Header, "z-phone", viewerFP, notAfter)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	br := bufio.NewReader(resp.Body)
	if line, err := br.ReadString('\n'); err != nil || line != "first\n" {
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
	e := newEnv(t)
	e.connect("agent-devbox", "devbox-body")

	r, closeFn := openStream(t, e, "/stream", farFuture)
	defer closeFn()

	e.setConfig(cfgOpts{blocked: []string{viewerFP}})
	expectStreamClosed(t, r)

	if resp, _ := e.get("t3.devbox.mesh.test", "z-phone", viewerFP, farFuture, "/hdr"); resp.StatusCode != 403 {
		t.Fatalf("blocked viewer got %d", resp.StatusCode)
	}
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
	e := newEnv(t)
	a := e.connect("agent-devbox", "devbox-body")

	e.setConfig(cfgOpts{disabled: []string{"agent-devbox"}})

	m := a.next(func(m proto.Message) bool { _, ok := m.(proto.Reject); return ok })
	if m.(proto.Reject).Reason != proto.RejectIdentityDisabled {
		t.Fatalf("reject = %+v", m)
	}

	a.waitClosed()

	if _, err := e.connectWith("agent-devbox", a.cert, "again"); err == nil {
		t.Fatal("disabled agent reconnected")
	}
}

func TestBlockedAgentLeaf(t *testing.T) {
	e := newEnv(t)
	a := e.connect("agent-devbox", "devbox-body")

	e.setConfig(cfgOpts{blocked: []string{a.fp}})
	a.next(func(m proto.Message) bool { _, ok := m.(proto.Reject); return ok })
	a.waitClosed()
}

func TestLeafNotNewestRejected(t *testing.T) {
	e := newEnv(t)

	cert, _ := e.newCert("agent-devbox", farFuture)
	e.fake.SetNewest("agent-devbox", strings.Repeat("b", 64))

	_, err := e.connectWith("agent-devbox", cert, "x")

	var rj *rejectError
	if !errors.As(err, &rj) || rj.Reason != proto.RejectLeafNotNewest {
		t.Fatalf("err = %v, want leaf-not-newest", err)
	}
}

func TestNoIssuanceRecordAdmitted(t *testing.T) {
	e := newEnv(t)

	cert, _, _ := e.ca.IssueIdentity(t, "agent-devbox", true, farFuture)
	if _, err := e.connectWith("agent-devbox", cert, "x"); err != nil {
		t.Fatalf("leaf without record refused: %v", err)
	}
}

func (a *agent) renew(key *ecdsa.PrivateKey, identity string) proto.Message {
	a.t.Helper()

	csr, err := pki.CreateCSR(key, identity)
	if err != nil {
		a.t.Fatal(err)
	}

	if err := a.ctrl.Send(proto.Renew{CSR: string(csr)}); err != nil {
		a.t.Fatal(err)
	}

	return a.next(func(m proto.Message) bool {
		switch m.(type) {
		case proto.Renewed, proto.Reject:
			return true
		}

		return false
	})
}

func TestRenewal(t *testing.T) {
	e := newEnv(t)
	a := e.connect("agent-devbox", "devbox-body")

	// Same key, wrong identity: rejected, session stays up.
	if rj, ok := a.renew(a.cert.PrivateKey.(*ecdsa.PrivateKey), "agent-devbox").(proto.Reject); !ok || rj.Reason != proto.RejectRenewFailed {
		t.Fatalf("same-key renewal = %+v", rj)
	}

	key, err := pki.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	if rj, ok := a.renew(key, "agent-z-arch").(proto.Reject); !ok || rj.Reason != proto.RejectRenewFailed {
		t.Fatalf("foreign-identity renewal = %+v", rj)
	}

	renewed, ok := a.renew(key, "agent-devbox").(proto.Renewed)
	if !ok {
		t.Fatal("renewal failed")
	}

	certs, err := pki.ParseCertsPEM([]byte(renewed.Certificate))
	if err != nil {
		t.Fatal(err)
	}

	newest, _ := e.fake.Newest(context.Background(), "agent-devbox")
	if newest != pki.Fingerprint(certs[0]) {
		t.Fatal("newest leaf not updated")
	}

	// Session still works; the new leaf is admitted, the old one is not.
	if _, body := e.get("t3.devbox.mesh.test", "z-phone", viewerFP, farFuture, "/hdr"); !strings.HasPrefix(body, "devbox-body") {
		t.Fatalf("session broken after renewal: %q", body)
	}

	newCert := tls.Certificate{Certificate: [][]byte{certs[0].Raw}, PrivateKey: key, Leaf: certs[0]}
	if _, err := e.connectWith("agent-devbox", newCert, "new"); err != nil {
		t.Fatalf("new leaf refused: %v", err)
	}

	_, err = e.connectWith("agent-devbox", a.cert, "old")

	var rj *rejectError
	if !errors.As(err, &rj) || rj.Reason != proto.RejectLeafNotNewest {
		t.Fatalf("old leaf err = %v", err)
	}
}

func TestUpdatesPeersAndRelease(t *testing.T) {
	e := newEnv(t)
	arch := e.connect("agent-z-arch", "arch-body")

	if len(arch.ack.Peers.Peers) != 1 || arch.ack.Peers.Peers[0].Machine != "devbox" || arch.ack.Peers.Peers[0].Home {
		t.Fatalf("initial peers = %+v", arch.ack.Peers)
	}

	if !arch.ack.Home || len(arch.ack.HomeCIDRs) != 1 || arch.ack.Release.Version != "v0.3.0" || arch.ack.Machine != "z-arch" {
		t.Fatalf("ack = %+v", arch.ack)
	}

	e.connect("agent-devbox", "devbox-body")

	m := arch.next(func(m proto.Message) bool { u, ok := m.(proto.Update); return ok && u.Peers != nil })

	p := m.(proto.Update).Peers.Peers[0]
	if !p.Home || p.DirectPort != 27400 || len(p.LANAddrs) != 1 || p.LANAddrs[0] != "192.168.1.5" {
		t.Fatalf("peer = %+v", p)
	}

	e.setConfig(cfgOpts{release: "v0.4.0"})

	rel := arch.next(func(m proto.Message) bool { _, ok := m.(proto.Release); return ok }).(proto.Release)
	if rel.Version != "v0.4.0" {
		t.Fatalf("release = %+v", rel)
	}

	e.setConfig(cfgOpts{release: "v0.4.0", disabled: []string{"z-old"}})
	arch.next(func(m proto.Message) bool { u, ok := m.(proto.Update); return ok && u.Revocations != nil })
}

func status(t *testing.T, e *env, name string) int {
	t.Helper()

	resp, err := http.Get(e.ops.URL + "/alerts/" + name)
	if err != nil {
		t.Fatal(err)
	}

	_ = resp.Body.Close()

	return resp.StatusCode
}

func TestAlerts(t *testing.T) {
	e := newEnv(t)

	for path, want := range map[string]int{"/healthz": 200, "/readyz": 200, "/status": 200} {
		resp, err := http.Get(e.ops.URL + path)
		if err != nil {
			t.Fatal(err)
		}

		_ = resp.Body.Close()

		if resp.StatusCode != want {
			t.Errorf("%s = %d", path, resp.StatusCode)
		}
	}

	if got := status(t, e, "nonsense"); got != 404 {
		t.Errorf("unknown alert = %d", got)
	}

	if got := status(t, e, "agent-ghost-disconnected"); got != 404 {
		t.Errorf("unknown machine alert = %d", got)
	}

	// Short-lived leaf: cert-expiry fires for it only.
	cert, _ := e.newCert("agent-devbox", time.Now().Add(10*24*time.Hour))

	a, err := e.connectWith("agent-devbox", cert, "devbox-body")
	if err != nil {
		t.Fatal(err)
	}

	e.offset.Store(int64(11 * time.Minute))

	checks := map[string]int{
		"agent-devbox-disconnected":  200,
		"agent-z-arch-disconnected":  503,
		"agent-devbox-cert-expiry":   503,
		"agent-z-arch-cert-expiry":   200,
		"agent-devbox-update-failed": 200,
		"stale-config":               200,
	}
	for name, want := range checks {
		if got := status(t, e, name); got != want {
			t.Errorf("%s = %d, want %d", name, got, want)
		}
	}

	if err := a.ctrl.Send(proto.Status{
		Version:       "v0.3.0",
		FailedUpdates: []proto.FailedUpdate{{Version: "v0.3.0", Reason: "crash", Attempts: 1}},
		RulesRevision: "r1",
	}); err != nil {
		t.Fatal(err)
	}

	eventually(t, func() bool { return status(t, e, "agent-devbox-update-failed") == 503 })

	var st statusDoc
	getJSON(t, e.ops.URL+"/status", &st)

	if st.Machines["devbox"].Acked.Rules != "r1" || len(st.Machines["devbox"].FailedUpdates) != 1 {
		t.Fatalf("status = %+v", st.Machines["devbox"])
	}

	// Stale config: an invalid mounted config that cannot be loaded.
	writeFile(t, filepath.Join(e.paths.ConfigDir, hubconfig.ConfigFile), "not: [valid")
	e.watcher.Reload(e.srv.OnConfigChange)
	e.offset.Store(int64(20 * time.Minute))

	if got := status(t, e, "stale-config"); got != 503 {
		t.Errorf("stale-config = %d", got)
	}

	if resp, err := http.Get(e.ops.URL + "/readyz"); err != nil || resp.StatusCode != 200 {
		t.Errorf("readyz must not fail on stale config: %v", err)
	}
}

func TestVersionLagAlert(t *testing.T) {
	e := newEnv(t)
	e.connect("agent-devbox", "devbox-body")
	e.setConfig(cfgOpts{release: "v0.5.0"})

	if got := status(t, e, "agent-devbox-update-failed"); got != 200 {
		t.Fatalf("fresh mismatch fires: %d", got)
	}

	e.offset.Store(int64(61 * time.Minute))

	if got := status(t, e, "agent-devbox-update-failed"); got != 503 {
		t.Fatalf("lagging agent = %d", got)
	}
}
