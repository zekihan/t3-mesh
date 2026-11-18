package direct

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zekihan/t3-mesh/internal/pki"
	"github.com/zekihan/t3-mesh/internal/pki/pkitest"
	"github.com/zekihan/t3-mesh/internal/policy"
	"github.com/zekihan/t3-mesh/internal/proto"
)

const (
	devHost   = "t3.z-arch.mesh.test"
	devDomain = "mesh.test"
	phoneID   = "device-z-phone-mesh"
	tabletID  = "device-z-tablet-mesh"
)

// seenRequest is what the fake T3 received.
type seenRequest struct {
	Header http.Header `json:"headers"`
	Host   string      `json:"host"`
	Path   string      `json:"path"`
}

type devEnv struct {
	gateway atomic.Value
	ca      *pkitest.CA
	pool    *x509.CertPool
	mgr     *Manager
	backend *httptest.Server
	t       *testing.T
	view    View
	offset  atomic.Int64
	hits    atomic.Int64
	changes atomic.Int64
	port    int
	mu      sync.Mutex
}

func (env *devEnv) get() View {
	env.mu.Lock()
	defer env.mu.Unlock()

	return env.view
}

func (env *devEnv) set(f func(v *View)) {
	env.mu.Lock()
	f(&env.view)
	env.mu.Unlock()
}

func (env *devEnv) now() time.Time { return time.Now().Add(time.Duration(env.offset.Load())) }

func (env *devEnv) advance(d time.Duration) { env.offset.Add(int64(d)) }

// fakeT3 is the stand-in for T3: it describes the request it got.
func (env *devEnv) fakeT3() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		env.hits.Add(1)

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-From-T3", "yes")

		_ = json.NewEncoder(w).Encode(seenRequest{Header: r.Header, Host: r.Host, Path: r.URL.Path})
	})
	mux.HandleFunc("/ws", func(w http.ResponseWriter, _ *http.Request) {
		env.hits.Add(1)

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
	mux.HandleFunc("/hold", func(w http.ResponseWriter, r *http.Request) {
		env.hits.Add(1)

		_, _ = io.WriteString(w, "first\n")
		_ = http.NewResponseController(w).Flush()

		select {
		case <-r.Context().Done():
		case <-time.After(10 * time.Second):
		}
	})

	srv := httptest.NewServer(mux)
	env.t.Cleanup(srv.Close)

	return srv
}

func newDevEnv(t *testing.T) *devEnv {
	t.Helper()

	env := &devEnv{t: t, ca: pkitest.NewCA(t, "clients"), port: freePort(t)}
	env.pool = x509.NewCertPool()
	env.pool.AddCert(env.ca.Cert)
	env.backend = env.fakeT3()
	env.gateway.Store("aa:bb:cc:dd:ee:ff")

	identity, _, _ := env.ca.IssueIdentity(
		t, policy.AgentIdentity("z-arch"), true, time.Now().Add(24*time.Hour),
	)

	env.view = View{
		Self: "z-arch", Identity: identity, Roots: env.pool, HubConnected: true, SelfHome: true,
		ViewerDomain: devDomain,
		HomePrefixes: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")},
		Rules:        proto.Rules{Allow: map[string][]string{"t3.z-arch": {phoneID}}},
	}

	env.mgr = New(Options{
		Port:       freePort(t),
		DevicePort: env.port,
		CacheTTL:   time.Hour,
		Serve:      map[string]string{"t3": env.backend.Listener.Addr().String()},
		View:       env.get,
		Now:        env.now,
		Log:        slog.New(slog.DiscardHandler),
		GatewayMAC: func() (string, error) {
			mac, _ := env.gateway.Load().(string)

			return mac, nil
		},
		LocalAddrs:     func() ([]netip.Addr, error) { return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil },
		OnDeviceChange: func() { env.changes.Add(1) },
	})
	t.Cleanup(func() { _ = env.mgr.Close() })

	return env
}

// enrolled issues a device leaf and records it as the newest this agent knows.
func (env *devEnv) enrolled(identity string) tls.Certificate {
	env.t.Helper()

	cert, _, _ := env.ca.IssueIdentity(env.t, identity, false, time.Now().Add(24*time.Hour))
	env.know(identity, &cert)

	return cert
}

func (env *devEnv) know(identity string, cert *tls.Certificate) {
	env.set(func(view *View) {
		leaves := make([]proto.DeviceLeaf, 0, len(view.DeviceLeaves.Leaves)+1)

		for _, leaf := range view.DeviceLeaves.Leaves {
			if leaf.Identity != identity {
				leaves = append(leaves, leaf)
			}
		}

		view.DeviceLeaves = proto.DeviceLeaves{
			Revision: strconv.Itoa(len(leaves) + 1),
			Leaves: append(leaves, proto.DeviceLeaf{
				Identity: identity, Fingerprint: pki.Fingerprint(cert.Leaf),
			}),
		}
	})
}

func (env *devEnv) allow(identities ...string) {
	env.set(func(v *View) {
		v.Rules = proto.Rules{Allow: map[string][]string{"t3.z-arch": identities}}
	})
}

// open starts the listener, as the agent does when the hub marks the machine home.
func (env *devEnv) open() string {
	env.t.Helper()

	env.mgr.Reconcile(env.t.Context())

	port, addrs := env.mgr.DeviceListener()
	if port != env.port || len(addrs) != 1 {
		env.t.Fatalf("device listener = %d %v", port, addrs)
	}

	return net.JoinHostPort(addrs[0], strconv.Itoa(port))
}

// checkServer is what the app does with the agent's certificate: server auth
// usage, exactly one URI naming the expected agent, chained to the clients CA.
func (env *devEnv) checkServer(state *tls.ConnectionState) error {
	leaf := state.PeerCertificates[0]

	name, err := pki.CertIdentity(leaf)
	if err != nil || name != "agent-z-arch" {
		return fmt.Errorf("server identity %q: %w", name, err)
	}

	_, err = pki.VerifyPeer(
		rawOf(state.PeerCertificates),
		env.pool,
		x509.ExtKeyUsageServerAuth,
		time.Now(),
	)
	if err != nil {
		return fmt.Errorf("server certificate: %w", err)
	}

	return nil
}

func rawOf(certs []*x509.Certificate) [][]byte {
	out := make([][]byte, len(certs))
	for i, c := range certs {
		out[i] = c.Raw
	}

	return out
}

func (env *devEnv) clientConfig(cert *tls.Certificate) *tls.Config {
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{"http/1.1"},
		// The agent's certificate carries an identity URI and no host name; checkServer
		// holds it to what the app holds it to.
		InsecureSkipVerify: true, //nolint:gosec // checked by VerifyConnection
		VerifyConnection:   func(state tls.ConnectionState) error { return env.checkServer(&state) },
	}

	if cert != nil {
		cfg.Certificates = []tls.Certificate{*cert}
	}

	return cfg
}

func (env *devEnv) dial(addr string, cfg *tls.Config) (net.Conn, error) {
	env.t.Helper()

	dialer := tls.Dialer{Config: cfg, NetDialer: &net.Dialer{Timeout: 3 * time.Second}}

	conn, err := dialer.DialContext(env.t.Context(), "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}

	env.t.Cleanup(func() { _ = conn.Close() })

	return conn, nil
}

func (env *devEnv) connect(addr string, cert *tls.Certificate) net.Conn {
	env.t.Helper()

	conn, err := env.dial(addr, env.clientConfig(cert))
	if err != nil {
		env.t.Fatal(err)
	}

	return conn
}

type reply struct {
	resp *http.Response
	body []byte
}

// httpRoundTrip sends one request on conn and reads the whole reply.
func httpRoundTrip(
	t *testing.T,
	conn net.Conn,
	br *bufio.Reader,
	method, host, path string,
	hdr http.Header,
) reply {
	t.Helper()

	req, err := http.NewRequestWithContext(t.Context(), method, "http://"+host+path, http.NoBody)
	if err != nil {
		t.Fatal(err)
	}

	req.Host = host

	maps.Copy(req.Header, hdr)

	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	err = req.Write(conn)
	if err != nil {
		t.Fatalf("write request: %v", err)
	}

	resp, err := http.ReadResponse(br, req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}

	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	return reply{resp: resp, body: body}
}

// request is httpRoundTrip on a fresh connection as the given device.
func (env *devEnv) request(
	addr string,
	cert *tls.Certificate,
	method, host, path string,
	hdr http.Header,
) reply {
	env.t.Helper()

	conn := env.connect(addr, cert)

	return httpRoundTrip(env.t, conn, bufio.NewReader(conn), method, host, path, hdr)
}

// refused asserts that a caller never reaches T3: the TLS handshake fails, or the
// connection is cut before any HTTP answer. In TLS 1.3 the client finishes its
// handshake before the server judges its certificate, so the refusal shows on the
// first read.
func (env *devEnv) refused(addr string, cfg *tls.Config, what string) {
	env.t.Helper()

	hits := env.hits.Load()

	conn, err := env.dial(addr, cfg)
	if err == nil {
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		_, _ = io.WriteString(conn, "GET / HTTP/1.1\r\nHost: "+devHost+"\r\n\r\n")

		buf := make([]byte, 1)

		n, rerr := conn.Read(buf)
		if rerr == nil || n > 0 {
			env.t.Fatalf("%s: got an answer (%d bytes), want a refusal", what, n)
		}

		var ne net.Error
		if errors.As(rerr, &ne) && ne.Timeout() {
			env.t.Fatalf("%s: connection left open, want refusal", what)
		}
	}

	if env.hits.Load() != hits {
		env.t.Fatalf("%s: the request reached T3", what)
	}
}

func decodeSeen(t *testing.T, rep reply) seenRequest {
	t.Helper()

	var seen seenRequest

	err := json.Unmarshal(rep.body, &seen)
	if err != nil {
		t.Fatalf("T3 reply %q: %v", rep.body, err)
	}

	return seen
}

func TestDeviceProxiesToT3(t *testing.T) {
	t.Parallel()

	env := newDevEnv(t)
	cert := env.enrolled(phoneID)
	addr := env.open()

	rep := env.request(addr, &cert, http.MethodGet, devHost, "/api/x?y=1", http.Header{
		"Origin": {"https://" + devHost}, "Cookie": {"s=1"},
	})
	if rep.resp.StatusCode != http.StatusOK || rep.resp.Header.Get("X-From-T3") != "yes" {
		t.Fatalf("reply %d %v", rep.resp.StatusCode, rep.resp.Header)
	}

	seen := decodeSeen(t, rep)
	if seen.Path != "/api/x" || seen.Host != devHost {
		t.Fatalf("T3 saw %+v, want Host %s forwarded unchanged", seen, devHost)
	}

	if seen.Header.Get("Origin") != "https://"+devHost || seen.Header.Get("Cookie") != "s=1" {
		t.Fatalf("T3 lost request headers: %v", seen.Header)
	}

	if seen.Header.Get("X-Forwarded-Proto") != "https" {
		t.Fatalf("X-Forwarded-Proto = %q, want https", seen.Header.Get("X-Forwarded-Proto"))
	}

	if v := seen.Header.Get("X-Forwarded-For"); v != "" {
		t.Fatalf("X-Forwarded-For = %q, want none", v)
	}

	// The agent's own certificate is what the app sees: its agent identity.
	conn := env.connect(addr, &cert)

	tc, ok := conn.(*tls.Conn)
	if !ok {
		t.Fatalf("connection is %T", conn)
	}

	state := tc.ConnectionState()
	if state.Version != tls.VersionTLS13 || state.NegotiatedProtocol != "http/1.1" {
		t.Fatalf(
			"negotiated %x %q, want TLS 1.3 and http/1.1",
			state.Version,
			state.NegotiatedProtocol,
		)
	}
}

func TestDeviceHostRule(t *testing.T) {
	t.Parallel()

	env := newDevEnv(t)
	cert := env.enrolled(phoneID)
	addr := env.open()

	for _, host := range []string{devHost, devHost + ":443", "T3.Z-Arch.Mesh.Test", "t3.z-arch.mesh.test:443"} {
		rep := env.request(addr, &cert, http.MethodGet, host, "/", nil)
		if rep.resp.StatusCode != http.StatusOK {
			t.Errorf("Host %q: %d, want 200", host, rep.resp.StatusCode)

			continue
		}

		if got := decodeSeen(t, rep).Host; got != host {
			t.Errorf("T3 saw Host %q, want %q unchanged", got, host)
		}
	}

	hits := env.hits.Load()

	for _, host := range []string{
		"t3.devbox.mesh.test", "t3.z-arch.mesh.noqer.com", "z-arch.mesh.test", "evil.example",
		devHost + ":8443", devHost + ".", "127.0.0.1", "hub.mesh.test", "t3.z-arch.mesh.test.evil.example",
	} {
		rep := env.request(addr, &cert, http.MethodGet, host, "/", nil)
		if rep.resp.StatusCode != http.StatusMisdirectedRequest {
			t.Errorf("Host %q: %d, want 421", host, rep.resp.StatusCode)
		}
	}

	if env.hits.Load() != hits {
		t.Fatal("a wrongly addressed request reached T3")
	}

	// The probe is held to the same rule.
	rep := env.request(addr, &cert, http.MethodGet, "evil.example", ProbePath, nil)
	if rep.resp.StatusCode != http.StatusMisdirectedRequest {
		t.Fatalf("probe with a wrong Host: %d, want 421", rep.resp.StatusCode)
	}
}

func TestDeviceWithoutViewerDomainServesNothing(t *testing.T) {
	t.Parallel()

	env := newDevEnv(t)
	cert := env.enrolled(phoneID)
	addr := env.open()

	env.set(func(v *View) { v.ViewerDomain = "" })

	rep := env.request(addr, &cert, http.MethodGet, devHost, "/", nil)
	if rep.resp.StatusCode != http.StatusMisdirectedRequest {
		t.Fatalf("without a viewer domain: %d, want 421", rep.resp.StatusCode)
	}
}

func TestDeviceStripsForwardingHeaders(t *testing.T) {
	t.Parallel()

	env := newDevEnv(t)
	cert := env.enrolled(phoneID)
	addr := env.open()

	rep := env.request(addr, &cert, http.MethodGet, devHost, "/", http.Header{
		"X-Mtls-Mesh-Viewer":      {"urn:noqer:mtls:clients:z-phone"},
		"X-Mtls-Mesh-Fingerprint": {strings.Repeat("a", 64)},
		"Forwarded":               {"for=203.0.113.9;proto=http"},
		"X-Forwarded-For":         {"203.0.113.9"},
		"X-Forwarded-Host":        {"evil.example"},
		"X-Forwarded-Proto":       {"http"},
		"X-Forwarded-Port":        {"8080"},
		"X-Forwarded-Server":      {"evil"},
		"X-Real-Ip":               {"203.0.113.9"},
		"X-Kept":                  {"yes"},
	})

	seen := decodeSeen(t, rep)

	for k := range seen.Header {
		lower := strings.ToLower(k)
		if strings.HasPrefix(lower, "x-mtls-") || lower == "forwarded" || lower == "x-real-ip" ||
			(strings.HasPrefix(lower, "x-forwarded-") && lower != "x-forwarded-proto") {
			t.Errorf("%s reached T3: %v", k, seen.Header[k])
		}
	}

	if seen.Header.Get("X-Forwarded-Proto") != "https" {
		t.Errorf("X-Forwarded-Proto = %q, want https", seen.Header.Get("X-Forwarded-Proto"))
	}

	if seen.Header.Get("X-Kept") != "yes" {
		t.Error("an unrelated header was dropped")
	}
}

func TestDeviceProbeIsAnsweredByTheAgent(t *testing.T) {
	t.Parallel()

	env := newDevEnv(t)
	cert := env.enrolled(phoneID)
	addr := env.open()

	conn := env.connect(addr, &cert)
	br := bufio.NewReader(conn)

	rep := httpRoundTrip(t, conn, br, http.MethodGet, devHost, ProbePath, nil)
	if rep.resp.StatusCode != http.StatusOK || rep.resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("probe: %d %v", rep.resp.StatusCode, rep.resp.Header)
	}

	if rep.resp.Header.Get("X-From-T3") != "" {
		t.Fatal("the probe was answered by T3")
	}

	if string(rep.body) != `{"machine":"z-arch","identity":"device-z-phone-mesh"}` {
		t.Fatalf("probe body = %s", rep.body)
	}

	// With a query it is still the probe, and it never reaches T3 on any method.
	rep = httpRoundTrip(t, conn, br, http.MethodGet, devHost, ProbePath+"?x=1", nil)
	if rep.resp.StatusCode != http.StatusOK || !strings.Contains(string(rep.body), "z-arch") {
		t.Fatalf("probe with a query: %d %s", rep.resp.StatusCode, rep.body)
	}

	rep = httpRoundTrip(t, conn, br, http.MethodHead, devHost, ProbePath, nil)
	if rep.resp.StatusCode != http.StatusOK || len(rep.body) != 0 {
		t.Fatalf("HEAD probe: %d %q", rep.resp.StatusCode, rep.body)
	}

	rep = httpRoundTrip(t, conn, br, http.MethodPost, devHost, ProbePath, nil)
	if rep.resp.StatusCode != http.StatusMethodNotAllowed ||
		rep.resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("POST probe: %d %v", rep.resp.StatusCode, rep.resp.Header)
	}

	if env.hits.Load() != 0 {
		t.Fatalf("T3 got %d requests from probes, want none", env.hits.Load())
	}

	// A path that only resembles it goes to T3 like any other.
	rep = httpRoundTrip(t, conn, br, http.MethodGet, devHost, ProbePath+"/x", nil)
	if rep.resp.Header.Get("X-From-T3") != "yes" {
		t.Fatalf("%s/x was not proxied", ProbePath)
	}
}

func TestDeviceWebSocketIsProxied(t *testing.T) {
	t.Parallel()

	env := newDevEnv(t)
	cert := env.enrolled(phoneID)
	addr := env.open()

	conn := env.connect(addr, &cert)
	br := upgrade(t, conn, devHost)

	_, err := io.WriteString(conn, "hello\n")
	if err != nil {
		t.Fatal(err)
	}

	line, err := br.ReadString('\n')
	if err != nil || line != "hello\n" {
		t.Fatalf("echo over the upgraded connection: %q %v", line, err)
	}

	waitFor(t, "device session", func() bool { return env.mgr.DeviceSessions() == 1 })
}

// upgrade opens a WebSocket on /ws as the app would and returns the reader for
// what follows the 101.
func upgrade(t *testing.T, conn net.Conn, host string) *bufio.Reader {
	t.Helper()

	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	_, err := io.WriteString(conn, "GET /ws HTTP/1.1\r\nHost: "+host+
		"\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\n"+
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n")
	if err != nil {
		t.Fatal(err)
	}

	br := bufio.NewReader(conn)

	resp, err := http.ReadResponse(br, nil)
	if err != nil || resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade: %v %v", resp, err)
	}

	_ = resp.Body.Close()

	return br
}

func TestDeviceRefusals(t *testing.T) {
	t.Parallel()

	env := newDevEnv(t)
	good := env.enrolled(phoneID)
	addr := env.open()

	// An enrolled device that the machine's rule does not list.
	tablet := env.enrolled(tabletID)

	env.allow(phoneID)

	// The KeyChain identity of the same phone, and an agent.
	keychain, _, _ := env.ca.IssueIdentity(t, "z-phone", false, time.Now().Add(time.Hour))
	agentCert, _, _ := env.ca.IssueIdentity(t, "agent-z-mac", true, time.Now().Add(time.Hour))
	env.allow(phoneID, "z-phone", "agent-z-mac")

	// A device whose leaf is no longer the newest the agent knows.
	older, _, _ := env.ca.IssueIdentity(t, phoneID, false, time.Now().Add(time.Hour))

	// A device identity with the wrong usages, extra names, two URIs, or another CA.
	withServer, _, _ := env.ca.IssueIdentity(t, phoneID, true, time.Now().Add(time.Hour))
	withDNS := csrIssued(t, env.ca, []string{phoneID}, []string{"phone.example"})
	twoURIs := csrIssued(t, env.ca, []string{phoneID, tabletID}, nil)
	stranger, _, _ := pkitest.NewCA(t, "other").
		IssueIdentity(t, phoneID, false, time.Now().Add(time.Hour))

	cases := []struct {
		cert *tls.Certificate
		name string
		// newest registers the leaf as the newest the agent knows for this device,
		// so that what refuses it is its own shape and not an older leaf.
		newest string
	}{
		{name: "KeyChain identity listed in the rule", cert: &keychain},
		{name: "agent identity listed in the rule", cert: &agentCert},
		{name: "enrolled device not in the rule", cert: &tablet},
		{name: "superseded leaf", cert: &older},
		{name: "device leaf with server auth", cert: &withServer, newest: phoneID},
		{name: "device leaf with a DNS name", cert: &withDNS, newest: phoneID},
		{name: "two URIs", cert: &twoURIs},
		{name: "leaf from another CA", cert: &stranger, newest: phoneID},
		{name: "no certificate", cert: nil},
	}

	for _, tc := range cases {
		if tc.newest != "" {
			env.know(tc.newest, tc.cert)
		}

		env.refused(addr, env.clientConfig(tc.cert), tc.name)

		env.know(phoneID, &good)
	}

	// The refusals changed nothing for the admitted device.
	rep := env.request(addr, &good, http.MethodGet, devHost, "/", nil)
	if rep.resp.StatusCode != http.StatusOK {
		t.Fatalf("the enrolled device was refused too: %d", rep.resp.StatusCode)
	}
}

// csrIssued issues a leaf for a CSR with the given identity URIs and DNS names,
// with client auth only, as a mis-issuing CA might.
func csrIssued(t *testing.T, ca *pkitest.CA, identities, dns []string) tls.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	uris := make([]*url.URL, 0, len(identities))

	for _, id := range identities {
		u, perr := url.Parse(policy.IdentityURI(id))
		if perr != nil {
			t.Fatal(perr)
		}

		uris = append(uris, u)
	}

	der, err := x509.CreateCertificateRequest(
		rand.Reader,
		&x509.CertificateRequest{URIs: uris, DNSNames: dns},
		key,
	)
	if err != nil {
		t.Fatal(err)
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})

	certPEM, _, err := ca.SignCSRUsages(
		csrPEM,
		time.Hour,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	)
	if err != nil {
		t.Fatal(err)
	}

	block, _ := pem.Decode(certPEM)

	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	return tls.Certificate{Certificate: [][]byte{block.Bytes}, PrivateKey: key, Leaf: leaf}
}

func TestDeviceRefusedByRevocation(t *testing.T) {
	t.Parallel()

	env := newDevEnv(t)
	cert := env.enrolled(phoneID)
	addr := env.open()

	env.set(
		func(v *View) { v.Revocations.BlockedFingerprints = []string{pki.Fingerprint(cert.Leaf)} },
	)
	env.refused(addr, env.clientConfig(&cert), "blocked leaf")

	env.set(func(v *View) {
		v.Revocations = proto.Revocations{DisabledIdentities: []string{phoneID}}
	})
	env.refused(addr, env.clientConfig(&cert), "disabled identity")

	env.set(func(v *View) { v.Revocations = proto.Revocations{} })

	rep := env.request(addr, &cert, http.MethodGet, devHost, "/", nil)
	if rep.resp.StatusCode != http.StatusOK {
		t.Fatalf("after the revocation was lifted: %d", rep.resp.StatusCode)
	}
}

func TestDeviceExpiredLeafIsRefused(t *testing.T) {
	t.Parallel()

	env := newDevEnv(t)
	cert := env.enrolled(phoneID)
	addr := env.open()

	env.advance(25 * time.Hour)
	env.refused(addr, env.clientConfig(&cert), "expired leaf")
}

func TestDeviceALPNAndTLSVersion(t *testing.T) {
	t.Parallel()

	env := newDevEnv(t)
	cert := env.enrolled(phoneID)
	addr := env.open()

	h2 := env.clientConfig(&cert)
	h2.NextProtos = []string{"h2"}
	env.refused(addr, h2, "h2 only")

	none := env.clientConfig(&cert)
	none.NextProtos = nil
	env.refused(addr, none, "no ALPN")

	tls12 := env.clientConfig(&cert)
	tls12.MinVersion, tls12.MaxVersion = tls.VersionTLS12, tls.VersionTLS12
	env.refused(addr, tls12, "TLS 1.2")

	// h2 offered next to http/1.1 still negotiates http/1.1.
	both := env.clientConfig(&cert)
	both.NextProtos = []string{"h2", "http/1.1"}

	conn := env.connect(addr, &cert)
	if rep := httpRoundTrip(
		t,
		conn,
		bufio.NewReader(conn),
		http.MethodGet,
		devHost,
		"/",
		nil,
	); rep.resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", rep.resp.StatusCode)
	}

	conn2, err := env.dial(addr, both)
	if err != nil {
		t.Fatal(err)
	}

	tc, ok := conn2.(*tls.Conn)
	if !ok {
		t.Fatalf("connection is %T", conn2)
	}

	if got := tc.ConnectionState().NegotiatedProtocol; got != "http/1.1" {
		t.Fatalf("negotiated %q, want http/1.1", got)
	}
}

func TestDeviceBackendDownIsBadGateway(t *testing.T) {
	t.Parallel()

	env := newDevEnv(t)
	cert := env.enrolled(phoneID)
	addr := env.open()

	env.backend.Close()

	rep := env.request(addr, &cert, http.MethodGet, devHost, "/", nil)
	if rep.resp.StatusCode != http.StatusBadGateway ||
		strings.TrimSpace(string(rep.body)) != "bad gateway" {
		t.Fatalf("with T3 down: %d %q, want the hub's 502", rep.resp.StatusCode, rep.body)
	}
}

// wsOpen is a device connection with an upgraded WebSocket and a keep-alive
// connection that is idle between requests.
type wsOpen struct {
	ws, idle net.Conn
	wsReader *bufio.Reader
}

func (env *devEnv) openSessions(addr string, cert *tls.Certificate) *wsOpen {
	env.t.Helper()

	open := &wsOpen{ws: env.connect(addr, cert), idle: env.connect(addr, cert)}
	open.wsReader = upgrade(env.t, open.ws, devHost)

	idleReader := bufio.NewReader(open.idle)
	if rep := httpRoundTrip(
		env.t,
		open.idle,
		idleReader,
		http.MethodGet,
		devHost,
		"/",
		nil,
	); rep.resp.StatusCode != http.StatusOK {
		env.t.Fatalf("keep-alive request: %d", rep.resp.StatusCode)
	}

	waitFor(env.t, "two device sessions", func() bool { return env.mgr.DeviceSessions() == 2 })

	return open
}

func (open *wsOpen) assertAlive(t *testing.T) {
	t.Helper()

	_ = open.ws.SetDeadline(time.Now().Add(3 * time.Second))

	_, err := io.WriteString(open.ws, "ping\n")
	if err != nil {
		t.Fatal(err)
	}

	line, err := open.wsReader.ReadString('\n')
	if err != nil || line != "ping\n" {
		t.Fatalf("WebSocket is not alive: %q %v", line, err)
	}
}

// assertClosed expects both connections to be cut and the sessions gone.
func (open *wsOpen) assertClosed(t *testing.T, env *devEnv, what string) {
	t.Helper()

	for name, conn := range map[string]net.Conn{"WebSocket": open.ws, "keep-alive connection": open.idle} {
		_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))

		n, err := conn.Read(make([]byte, 1))
		if n > 0 {
			continue
		}

		var ne net.Error
		if err == nil || (errors.As(err, &ne) && ne.Timeout()) {
			t.Fatalf("%s: the %s is still open", what, name)
		}
	}

	waitFor(t, what+": sessions gone", func() bool { return env.mgr.DeviceSessions() == 0 })
}

func TestDeviceLiveSessionsCloseOnLoss(t *testing.T) {
	t.Parallel()

	tests := []struct {
		change func(env *devEnv, cert *tls.Certificate)
		name   string
		// sweep leaves the closing to the periodic sweep: the cause is the clock,
		// which no update announces.
		sweep bool
	}{
		{
			name: "blocked leaf",
			change: func(env *devEnv, cert *tls.Certificate) {
				env.set(func(v *View) {
					v.Revocations.BlockedFingerprints = []string{pki.Fingerprint(cert.Leaf)}
				})
			},
		},
		{
			name: "disabled identity",
			change: func(env *devEnv, _ *tls.Certificate) {
				env.set(func(v *View) { v.Revocations.DisabledIdentities = []string{phoneID} })
			},
		},
		{
			name:   "removed from the rule",
			change: func(env *devEnv, _ *tls.Certificate) { env.allow("z-viewer") },
		},
		{
			name: "superseded leaf",
			change: func(env *devEnv, _ *tls.Certificate) {
				newer, _, _ := env.ca.IssueIdentity(
					env.t,
					phoneID,
					false,
					time.Now().Add(time.Hour),
				)
				env.know(phoneID, &newer)
			},
		},
		{
			name: "device dropped from the leaves",
			change: func(env *devEnv, _ *tls.Certificate) {
				env.set(func(v *View) { v.DeviceLeaves = proto.DeviceLeaves{Revision: "9"} })
			},
		},
		{
			name:   "leaf expiry",
			sweep:  true,
			change: func(env *devEnv, _ *tls.Certificate) { env.advance(25 * time.Hour) },
		},
		{
			name:  "cache window over",
			sweep: true,
			change: func(env *devEnv, _ *tls.Certificate) {
				env.set(func(v *View) {
					v.HubConnected = false
					v.LastHubContact = env.now()
					v.HomeGatewayMAC = "aa:bb:cc:dd:ee:ff"
				})
				env.advance(90 * time.Minute)
			},
		},
		{
			name: "hub says the machine left home",
			change: func(env *devEnv, _ *tls.Certificate) {
				env.set(func(v *View) { v.SelfHome = false })
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			env := newDevEnv(t)
			cert := env.enrolled(phoneID)
			addr := env.open()
			open := env.openSessions(addr, &cert)

			open.assertAlive(t)

			tt.change(env, &cert)

			// The agent re-checks on every update; the periodic sweep also catches
			// the clock-driven ones.
			start := time.Now()

			if !tt.sweep {
				env.mgr.Recheck()
			}

			open.assertClosed(t, env, tt.name)

			if took := time.Since(start); took > 4*time.Second {
				t.Fatalf("closing took %s", took)
			}
		})
	}
}

// A session closes at once on the update, without waiting for the sweep.
func TestDeviceRecheckClosesAtOnce(t *testing.T) {
	t.Parallel()

	env := newDevEnv(t)
	cert := env.enrolled(phoneID)
	addr := env.open()
	open := env.openSessions(addr, &cert)

	env.set(
		func(v *View) { v.Revocations.BlockedFingerprints = []string{pki.Fingerprint(cert.Leaf)} },
	)
	env.mgr.Recheck()

	if got := env.mgr.DeviceSessions(); got != 0 {
		t.Fatalf("%d sessions still registered right after Recheck", got)
	}

	open.assertClosed(t, env, "recheck")
}

// A request that arrives on a connection whose device was refused since the last
// sweep is not served either.
func TestDeviceRequestAfterLossIsNotServed(t *testing.T) {
	t.Parallel()

	env := newDevEnv(t)
	cert := env.enrolled(phoneID)
	addr := env.open()

	conn := env.connect(addr, &cert)
	br := bufio.NewReader(conn)

	if rep := httpRoundTrip(
		t,
		conn,
		br,
		http.MethodGet,
		devHost,
		"/",
		nil,
	); rep.resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", rep.resp.StatusCode)
	}

	hits := env.hits.Load()

	env.set(func(v *View) { v.Revocations.DisabledIdentities = []string{phoneID} })

	_, _ = io.WriteString(conn, "GET / HTTP/1.1\r\nHost: "+devHost+"\r\n\r\n")
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))

	resp, err := http.ReadResponse(br, nil)
	if err == nil {
		_ = resp.Body.Close()

		t.Fatal("a request on a revoked connection was answered")
	}

	if env.hits.Load() != hits {
		t.Fatal("the request reached T3")
	}
}

// Closing a session also cuts what T3 is still sending for it.
func TestDeviceRevocationCutsTheBackendRequest(t *testing.T) {
	t.Parallel()

	env := newDevEnv(t)
	cert := env.enrolled(phoneID)
	addr := env.open()

	conn := env.connect(addr, &cert)

	_, _ = io.WriteString(conn, "GET /hold HTTP/1.1\r\nHost: "+devHost+"\r\n\r\n")

	br := bufio.NewReader(conn)

	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))

	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = resp.Body.Close() }()

	env.set(
		func(v *View) { v.Revocations.BlockedFingerprints = []string{pki.Fingerprint(cert.Leaf)} },
	)
	env.mgr.Recheck()

	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))

	_, err = io.Copy(io.Discard, resp.Body)

	var ne net.Error
	if err == nil || (errors.As(err, &ne) && ne.Timeout()) {
		// A clean end would mean T3 finished, a timeout that nothing was cut; the
		// fake holds the response for 10 s.
		t.Fatalf("the held response was not cut after revocation: %v", err)
	}
}

func TestDeviceOutageKeepsAccessWithinCacheTTL(t *testing.T) {
	t.Parallel()

	env := newDevEnv(t)
	cert := env.enrolled(phoneID)
	env.set(func(v *View) {
		v.HubConnected = false
		v.LastHubContact = env.now()
		v.HomeGatewayMAC = "AA:BB:CC:DD:EE:FF"
	})

	addr := env.open()
	open := env.openSessions(addr, &cert)

	// Days into the outage, still inside the window.
	env.advance(30 * time.Minute)
	env.mgr.Reconcile(t.Context())
	open.assertAlive(t)

	rep := env.request(addr, &cert, http.MethodGet, devHost, "/", nil)
	if rep.resp.StatusCode != http.StatusOK {
		t.Fatalf("new request within the window: %d", rep.resp.StatusCode)
	}

	// Past the window every session closes and the listener goes.
	env.advance(45 * time.Minute)
	env.mgr.Reconcile(t.Context())
	open.assertClosed(t, env, "cache window over")

	if port, _ := env.mgr.DeviceListener(); port != 0 {
		t.Fatal("the device listener is still bound after the cache window")
	}

	env.refused(addr, env.clientConfig(&cert), "after the cache window")
}

func TestDeviceHomeGate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		setup func(env *devEnv)
		name  string
	}{
		{
			name:  "hub connected, machine not home",
			setup: func(env *devEnv) { env.set(func(v *View) { v.SelfHome = false }) },
		},
		{
			// A foreign network that also uses a home prefix: the addresses match, the
			// gateway does not.
			name: "hub unreachable on a foreign network matching the home prefixes",
			setup: func(env *devEnv) {
				env.set(func(v *View) {
					v.HubConnected = false
					v.LastHubContact = env.now()
					v.HomeGatewayMAC = "aa:bb:cc:dd:ee:ff"
				})
				env.gateway.Store("11:22:33:44:55:66")
			},
		},
		{
			name: "hub unreachable and no cached home gateway",
			setup: func(env *devEnv) {
				env.set(func(v *View) {
					v.HubConnected = false
					v.LastHubContact = env.now()
				})
			},
		},
		{
			name: "hub unreachable and the cache window over",
			setup: func(env *devEnv) {
				env.set(func(v *View) {
					v.HubConnected = false
					v.LastHubContact = env.now().Add(-2 * time.Hour)
					v.HomeGatewayMAC = "aa:bb:cc:dd:ee:ff"
				})
			},
		},
		{
			// The agent hands the direct package no prefixes until a trust bundle is cached.
			name:  "no home prefixes",
			setup: func(env *devEnv) { env.set(func(v *View) { v.HomePrefixes = nil }) },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			env := newDevEnv(t)
			cert := env.enrolled(phoneID)

			env.open()
			env.mgr.Reconcile(t.Context())

			tt.setup(env)
			env.mgr.Reconcile(t.Context())

			if port, addrs := env.mgr.DeviceListener(); port != 0 || len(addrs) != 0 {
				t.Fatalf("listener bound while the gate is closed: %d %v", port, addrs)
			}

			// Nothing listens on the device port any more.
			_, err := env.dial(
				net.JoinHostPort("127.0.0.1", strconv.Itoa(env.port)),
				env.clientConfig(&cert),
			)
			if err == nil {
				t.Fatal("the device port still accepts connections")
			}
		})
	}
}

func TestDeviceListenerFollowsTheGateAndNotifies(t *testing.T) {
	t.Parallel()

	env := newDevEnv(t)
	env.enrolled(phoneID)

	if port, _ := env.mgr.DeviceListener(); port != 0 {
		t.Fatal("listening before Reconcile")
	}

	addr := env.open()

	if env.changes.Load() != 1 {
		t.Fatalf("OnDeviceChange called %d times after binding, want 1", env.changes.Load())
	}

	// Nothing changed: no notification.
	env.mgr.Reconcile(t.Context())

	if env.changes.Load() != 1 {
		t.Fatalf("OnDeviceChange called again with nothing new: %d", env.changes.Load())
	}

	if !strings.HasPrefix(addr, "127.0.0.1:") {
		t.Fatalf("bound on %s", addr)
	}

	env.set(func(v *View) { v.SelfHome = false })
	env.mgr.Reconcile(t.Context())

	if env.changes.Load() != 2 {
		t.Fatalf(
			"OnDeviceChange called %d times after the listener closed, want 2",
			env.changes.Load(),
		)
	}
}

func TestDeviceListenerOff(t *testing.T) {
	t.Parallel()

	for name, opts := range map[string]func(*Options){
		"no port":   func(o *Options) { o.DevicePort = 0 },
		"no t3":     func(o *Options) { o.Serve = map[string]string{"other": "127.0.0.1:1"} },
		"no serves": func(o *Options) { o.Serve = nil },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			env := newDevEnv(t)
			_ = env.mgr.Close()

			o := env.mgr.opts
			opts(&o)
			o.OnDeviceChange = nil

			mgr := New(o)

			t.Cleanup(func() { _ = mgr.Close() })

			mgr.Reconcile(t.Context())

			if port, _ := mgr.DeviceListener(); port != 0 {
				t.Fatal("device listener bound")
			}

			// The agent-to-agent listener is unaffected by the device one being off.
			if len(mgr.Listening()) != 1 {
				t.Fatalf("direct listener = %v", mgr.Listening())
			}
		})
	}
}

// The device listener does not accept an agent speaking t3-mesh-direct/1, and the
// direct listener does not take a device.
func TestDeviceAndDirectListenersStaySeparate(t *testing.T) {
	t.Parallel()

	env := newDevEnv(t)
	cert := env.enrolled(phoneID)
	env.open()

	directAddr := env.mgr.Listening()
	if len(directAddr) != 1 {
		t.Fatalf("direct listeners = %v", directAddr)
	}

	cfg := env.clientConfig(&cert)
	cfg.NextProtos = []string{proto.ALPNDirect}

	conn, err := env.dial(directAddr[0].String(), cfg)
	if err != nil {
		t.Fatal(err)
	}

	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = io.WriteString(conn, `{"svc":"t3"}`+"\n")

	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil || !strings.Contains(line, `"ok":false`) {
		t.Fatalf(
			"the agent-to-agent listener answered a device with %q (%v), want a refusal",
			line,
			err,
		)
	}

	if env.hits.Load() != 0 {
		t.Fatal("a device reached T3 through the agent-to-agent listener")
	}
}

func TestDeviceCloseStopsEverything(t *testing.T) {
	t.Parallel()

	env := newDevEnv(t)
	cert := env.enrolled(phoneID)
	addr := env.open()
	open := env.openSessions(addr, &cert)

	done := make(chan struct{})

	go func() {
		_ = env.mgr.Close()

		close(done)
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Close did not return with device sessions open")
	}

	open.assertClosed(t, env, "manager closed")
}
