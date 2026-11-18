package enroll

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zekihan/t3-mesh/internal/hub/issuer/issuertest"
	"github.com/zekihan/t3-mesh/internal/pki"
	"github.com/zekihan/t3-mesh/internal/pki/pkitest"
	"github.com/zekihan/t3-mesh/internal/policy"
	"github.com/zekihan/t3-mesh/internal/proto"
)

type clock struct {
	t  time.Time
	mu sync.Mutex
}

var (
	errDisabled      = errors.New("disabled")
	errNotConfigured = errors.New("not configured")
)

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.t
}

func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.t = c.t.Add(d)
}

type env struct {
	clk    *clock
	tokens *Tokens
	h      *Handler
	fake   *issuertest.Fake
	ca     *pkitest.CA
	issued []string
}

func newEnv(t *testing.T) *env {
	t.Helper()

	ca := pkitest.NewCA(t, "test")
	clk := &clock{t: time.Unix(1_700_000_000, 0)}
	harness := &env{clk: clk, tokens: NewTokens(clk.Now), ca: ca}
	harness.fake = &issuertest.Fake{Sign: func(csr []byte) ([]byte, []byte, error) {
		return ca.SignCSR(csr, time.Hour)
	}}
	lim := NewLimiter(clk.Now)
	harness.h = &Handler{
		Tokens:   harness.tokens,
		Issuer:   harness.fake,
		Allowed:  func(string) error { return nil },
		OnIssued: func(id, fp string) { harness.issued = append(harness.issued, id+" "+fp) },
		Trust: func() proto.TrustBundle {
			return proto.TrustBundle{Revision: "rev-9", PEM: string(ca.CertPEM)}
		},
		Limiter: lim,
		Now:     clk.Now,
	}

	return harness
}

func csrFor(t *testing.T, identity string) []byte {
	t.Helper()

	key, err := pki.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	csr, err := pki.CreateCSR(key, identity)
	if err != nil {
		t.Fatal(err)
	}

	return csr
}

// run serves one exchange over a pipe, sending req (if non-nil) and returning the reply.
//
//nolint:ireturn // returns the decoded wire message, whose concrete type the caller inspects
func (harness *env) run(t *testing.T, req proto.Message) proto.Message {
	t.Helper()

	client, server := net.Pipe()
	done := make(chan struct{})

	go func() {
		defer close(done)

		harness.h.Serve(t.Context(), server, netip.MustParseAddr("192.0.2.1"))
	}()

	_ = client.SetDeadline(time.Now().Add(5 * time.Second))

	if req != nil {
		go func() { _ = proto.WriteMessage(client, req) }()
	}

	msg, err := proto.ReadMessage(client, proto.MaxMessageSize)
	if err != nil {
		msg = nil
	}

	_ = client.Close()

	<-done

	return msg
}

func wantReject(t *testing.T, msg proto.Message) {
	t.Helper()

	rj, ok := msg.(proto.Reject)
	if !ok {
		t.Fatalf("got %#v, want Reject", msg)
	}

	if rj.Reason != proto.RejectEnrollFailed {
		t.Fatalf("reason %q", rj.Reason)
	}
}

func TestSuccess(t *testing.T) {
	harness := newEnv(t)
	token, _, _ := harness.tokens.Create("agent-a")
	msg := harness.run(t, proto.Enroll{Token: token, CSR: string(csrFor(t, "agent-a"))})

	en, ok := msg.(proto.Enrolled)
	if !ok {
		t.Fatalf("got %#v", msg)
	}

	certs, err := pki.ParseCertsPEM([]byte(en.Certificate))
	if err != nil || len(certs) != 1 {
		t.Fatalf("certs: %v", err)
	}

	if len(harness.issued) != 1 || harness.issued[0] != "agent-a "+pki.Fingerprint(certs[0]) {
		t.Fatalf("issued %v", harness.issued)
	}

	if harness.tokens.Outstanding() {
		t.Fatal("token still outstanding")
	}
}

func TestWrongToken(t *testing.T) {
	harness := newEnv(t)

	_, _, err := harness.tokens.Create("agent-a")
	if err != nil {
		t.Fatal(err)
	}

	wantReject(t, harness.run(t, proto.Enroll{Token: "nope", CSR: string(csrFor(t, "agent-a"))}))
}

func TestExpiredToken(t *testing.T) {
	e := newEnv(t)
	token, _, _ := e.tokens.Create("agent-a")
	e.clk.Advance(TokenTTL + time.Second)
	wantReject(t, e.run(t, proto.Enroll{Token: token, CSR: string(csrFor(t, "agent-a"))}))
}

func TestReusedToken(t *testing.T) {
	harness := newEnv(t)
	token, _, _ := harness.tokens.Create("agent-a")
	req := proto.Enroll{Token: token, CSR: string(csrFor(t, "agent-a"))}

	if _, ok := harness.run(t, req).(proto.Enrolled); !ok {
		t.Fatal("first use failed")
	}

	wantReject(t, harness.run(t, req))
}

func TestIdentityMismatchBurnsToken(t *testing.T) {
	e := newEnv(t)
	token, _, _ := e.tokens.Create("agent-a")
	wantReject(t, e.run(t, proto.Enroll{Token: token, CSR: string(csrFor(t, "agent-b"))}))

	if e.tokens.Outstanding() {
		t.Fatal("token not burned")
	}
}

func TestGarbageCSRKeepsToken(t *testing.T) {
	e := newEnv(t)
	token, _, _ := e.tokens.Create("agent-a")
	wantReject(t, e.run(t, proto.Enroll{Token: token, CSR: "garbage"}))

	if !e.tokens.Outstanding() {
		t.Fatal("token burned by garbage request")
	}
}

func TestDisabledIdentity(t *testing.T) {
	e := newEnv(t)
	e.h.Allowed = func(string) error { return errDisabled }
	token, _, _ := e.tokens.Create("agent-a")
	wantReject(t, e.run(t, proto.Enroll{Token: token, CSR: string(csrFor(t, "agent-a"))}))

	if len(e.issued) != 0 {
		t.Fatal("issued for disabled identity")
	}
}

func TestOversized(t *testing.T) {
	e := newEnv(t)
	token, _, _ := e.tokens.Create("agent-a")
	wantReject(
		t,
		e.run(t, proto.Enroll{Token: token, CSR: strings.Repeat("x", proto.MaxEnrollSize)}),
	)
}

func TestWrongMessageType(t *testing.T) {
	e := newEnv(t)
	wantReject(t, e.run(t, proto.Ping{}))
}

func TestIssuerWrongCert(t *testing.T) {
	cases := map[string]func(ca *pkitest.CA, csr []byte) ([]byte, []byte, error){
		"other key": func(ca *pkitest.CA, _ []byte) ([]byte, []byte, error) {
			return ca.SignCSR(csrFor(t, "agent-a"), time.Hour)
		},
		"other identity": func(ca *pkitest.CA, csr []byte) ([]byte, []byte, error) {
			return ca.SignCSR(csrFor(t, "agent-b"), time.Hour)
		},
	}

	for name, sign := range cases {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			ca := pkitest.NewCA(t, "x")
			e.fake.Sign = func(csr []byte) ([]byte, []byte, error) { return sign(ca, csr) }
			token, _, _ := e.tokens.Create("agent-a")
			wantReject(t, e.run(t, proto.Enroll{Token: token, CSR: string(csrFor(t, "agent-a"))}))

			if len(e.issued) != 0 {
				t.Fatal("OnIssued called")
			}
		})
	}
}

func TestRateLimit(t *testing.T) {
	harness := newEnv(t)

	for range 5 {
		wantReject(t, harness.run(t, proto.Enroll{Token: "x", CSR: "y"}))
	}

	// Sixth attempt is limited before anything is read: the reject arrives without a request.
	wantReject(t, harness.run(t, nil))

	harness.clk.Advance(11 * time.Minute)
	wantReject(t, harness.run(t, proto.Enroll{Token: "x", CSR: "y"}))

	if !harness.h.Limiter.Allow(netip.MustParseAddr("192.0.2.1")) {
		t.Fatal("limiter did not recover")
	}
}

func TestLimiterBounded(t *testing.T) {
	clk := &clock{t: time.Unix(0, 0)}
	limiter := NewLimiter(clk.Now)
	limiter.MaxEntries = 2

	if !limiter.Allow(netip.MustParseAddr("192.0.2.1")) ||
		!limiter.Allow(netip.MustParseAddr("192.0.2.2")) {
		t.Fatal("first two refused")
	}

	if limiter.Allow(netip.MustParseAddr("192.0.2.3")) {
		t.Fatal("third allowed with full table")
	}

	clk.Advance(time.Hour)

	if !limiter.Allow(netip.MustParseAddr("192.0.2.3")) {
		t.Fatal("not allowed after cleanup")
	}
}

func TestTokensReplace(t *testing.T) {
	tk := NewTokens(time.Now)
	first, _, _ := tk.Create("agent-a")
	second, _, _ := tk.Create("agent-a")

	_, err := tk.Redeem(first)
	if err == nil {
		t.Fatal("replaced token redeemable")
	}

	id, err := tk.Redeem(second)
	if err != nil || id != "agent-a" {
		t.Fatalf("redeem: %q %v", id, err)
	}
}

func TestAdminRoundTrip(t *testing.T) {
	tk := NewTokens(time.Now)
	path := filepath.Join(t.TempDir(), "admin.sock")
	// Stale file must be replaced.
	err := os.WriteFile(path, nil, 0o600)
	if err != nil {
		t.Fatal(err)
	}

	admin := &Admin{Path: path, Tokens: tk, Allowed: func(_, id string) error {
		if id == "bad" {
			return errNotConfigured
		}

		return nil
	}}
	ctx, cancel := context.WithCancel(t.Context())
	errc := make(chan error, 1)

	go func() { errc <- admin.Serve(ctx) }()

	var (
		token   string
		expires time.Time
	)

	deadline := time.Now().Add(5 * time.Second)

	for {
		token, expires, err = RequestToken(ctx, path, KindAgent, "agent-a")
		if err == nil || time.Now().After(deadline) {
			break
		}
	}

	if err != nil {
		t.Fatal(err)
	}

	if !expires.After(time.Now()) {
		t.Fatalf("expires %v", expires)
	}

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode())
	}

	id, err := tk.Redeem(token)
	if err != nil || id != "agent-a" {
		t.Fatalf("redeem: %q %v", id, err)
	}

	_, _, err = RequestToken(ctx, path, KindAgent, "bad")
	if err == nil {
		t.Fatal("disallowed identity got a token")
	}

	cancel()

	err = <-errc
	if err != nil {
		t.Fatal(err)
	}
}

// serveAdmin runs an Admin on a temp socket and returns the socket path.
func serveAdmin(t *testing.T, admin *Admin) string {
	t.Helper()

	admin.Path = filepath.Join(t.TempDir(), "admin.sock")

	ctx, cancel := context.WithCancel(t.Context())
	errc := make(chan error, 1)

	go func() { errc <- admin.Serve(ctx) }()

	t.Cleanup(func() {
		cancel()

		err := <-errc
		if err != nil {
			t.Error(err)
		}
	})

	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()

	timeout := time.After(5 * time.Second)

	for {
		_, err := os.Stat(admin.Path)
		if err == nil {
			return admin.Path
		}

		select {
		case <-timeout:
			t.Fatal("admin socket did not appear")
		case <-ticker.C:
		}
	}
}

func adminRaw(t *testing.T, path, line string) string {
	t.Helper()

	var dialer net.Dialer

	conn, err := dialer.DialContext(t.Context(), "unix", path)
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	_, err = conn.Write([]byte(line + "\n"))
	if err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 1024)

	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}

	return string(buf[:n])
}

func TestAdminKinds(t *testing.T) {
	type call struct{ kind, identity string }

	var (
		mu    sync.Mutex
		calls []call
	)

	tk := NewTokens(time.Now)
	path := serveAdmin(t, &Admin{Tokens: tk, Allowed: func(kind, identity string) error {
		mu.Lock()

		calls = append(calls, call{kind, identity})

		mu.Unlock()

		if identity == "refused" {
			return errNotConfigured
		}

		return nil
	}})

	ctx := t.Context()

	token, _, err := RequestToken(ctx, path, KindDevice, "device-z-phone-mesh")
	if err != nil {
		t.Fatal(err)
	}

	id, err := tk.Redeem(token)
	if err != nil || id != "device-z-phone-mesh" {
		t.Fatalf("redeem: %q %v", id, err)
	}

	_, _, err = RequestToken(ctx, path, KindDevice, "refused")
	if err == nil {
		t.Fatal("refused device got a token")
	}

	// A release before device enrollment sends no kind: it is an agent token.
	reply := adminRaw(t, path, `{"op":"enroll-token","identity":"agent-a"}`)
	if !strings.Contains(reply, `"token"`) {
		t.Fatalf("legacy request: %s", reply)
	}

	for _, bad := range []string{
		`{"op":"enroll-token","identity":"agent-a","kind":"phone"}`,
		`{"op":"enroll-token","identity":"agent-a","kind":"DEVICE"}`,
		`{"op":"enroll-token","identity":"","kind":"device"}`,
		`{"op":"other","identity":"agent-a","kind":"agent"}`,
		`not json`,
	} {
		if reply := adminRaw(t, path, bad); !strings.Contains(reply, `"bad request"`) {
			t.Errorf("%s -> %s", bad, reply)
		}
	}

	mu.Lock()
	defer mu.Unlock()

	want := []call{
		{KindDevice, "device-z-phone-mesh"}, {KindDevice, "refused"}, {KindAgent, "agent-a"},
	}
	if len(calls) != len(want) {
		t.Fatalf("Allowed calls = %v, want %v", calls, want)
	}

	for i := range want {
		if calls[i] != want[i] {
			t.Errorf("Allowed call %d = %v, want %v", i, calls[i], want[i])
		}
	}
}

const devPhone = "device-z-phone-mesh"

func rawCSR(t *testing.T, key any, tmpl *x509.CertificateRequest) []byte {
	t.Helper()

	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatal(err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

func identityURL(t *testing.T, identity string) *url.URL {
	t.Helper()

	u, err := url.Parse(policy.IdentityURI(identity))
	if err != nil {
		t.Fatal(err)
	}

	return u
}

func TestDeviceSuccess(t *testing.T) {
	harness := newEnv(t)
	token, _, _ := harness.tokens.Create(devPhone)
	msg := harness.run(t, proto.Enroll{Token: token, CSR: string(csrFor(t, devPhone))})

	en, ok := msg.(proto.Enrolled)
	if !ok {
		t.Fatalf("got %#v", msg)
	}

	certs, err := pki.ParseCertsPEM([]byte(en.Certificate))
	if err != nil || len(certs) != 1 {
		t.Fatalf("certs: %v", err)
	}

	leaf := certs[0]

	err = pki.CheckDeviceLeaf(leaf)
	if err != nil {
		t.Fatalf("leaf: %v", err)
	}

	if id, _ := pki.CertIdentity(leaf); id != devPhone {
		t.Fatalf("identity %q", id)
	}

	if len(harness.issued) != 1 || harness.issued[0] != devPhone+" "+pki.Fingerprint(leaf) {
		t.Fatalf("issued %v", harness.issued)
	}

	// The reply carries the clients CA bundle and its revision, and the chain.
	if en.CABundle != string(harness.ca.CertPEM) || en.CARevision != "rev-9" ||
		en.Chain != string(harness.ca.CertPEM) {
		t.Fatalf("reply = %+v", en)
	}

	pool, err := pki.PoolFromPEM([]byte(en.CABundle))
	if err != nil {
		t.Fatal(err)
	}

	_, err = pki.VerifyPeer([][]byte{leaf.Raw}, pool, x509.ExtKeyUsageClientAuth, time.Now())
	if err != nil {
		t.Fatalf("leaf does not verify against the bundle: %v", err)
	}

	if harness.tokens.Outstanding() {
		t.Fatal("token still outstanding")
	}
}

func TestAgentReplyAlsoCarriesTrust(t *testing.T) {
	harness := newEnv(t)
	token, _, _ := harness.tokens.Create("agent-a")

	en, ok := harness.run(t, proto.Enroll{Token: token, CSR: string(csrFor(t, "agent-a"))}).(proto.Enrolled)
	if !ok || en.CABundle != string(harness.ca.CertPEM) || en.CARevision != "rev-9" {
		t.Fatalf("reply = %+v", en)
	}
}

func TestDeviceCSRRejected(t *testing.T) {
	good := identityURL(t, devPhone)

	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	key, err := pki.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	caExt := pkix.Extension{
		Id: asn1.ObjectIdentifier{2, 5, 29, 19}, Value: []byte{0x30, 0x03, 0x01, 0x01, 0xff},
	}

	cases := map[string][]byte{
		"p384 key": rawCSR(t, p384, &x509.CertificateRequest{URIs: []*url.URL{good}}),
		"rsa key":  rawCSR(t, rsaKey, &x509.CertificateRequest{URIs: []*url.URL{good}}),
		"dns san": rawCSR(t, key, &x509.CertificateRequest{
			URIs: []*url.URL{good}, DNSNames: []string{"a.example"},
		}),
		"second uri": rawCSR(t, key, &x509.CertificateRequest{
			URIs: []*url.URL{good, identityURL(t, "agent-z-mac")},
		}),
		"ca request": rawCSR(t, key, &x509.CertificateRequest{
			URIs: []*url.URL{good}, ExtraExtensions: []pkix.Extension{caExt},
		}),
	}

	for name, csr := range cases {
		t.Run(name, func(t *testing.T) {
			harness := newEnv(t)
			token, _, _ := harness.tokens.Create(devPhone)

			wantReject(t, harness.run(t, proto.Enroll{Token: token, CSR: string(csr)}))

			if len(harness.issued) != 0 {
				t.Fatal("issued for a bad CSR")
			}

			// Like any malformed request, it does not burn the token.
			if !harness.tokens.Outstanding() {
				t.Fatal("token burned by a bad CSR")
			}
		})
	}
}

func TestTokenBoundToOneDevice(t *testing.T) {
	harness := newEnv(t)
	token, _, _ := harness.tokens.Create(devPhone)

	wantReject(
		t,
		harness.run(t, proto.Enroll{Token: token, CSR: string(csrFor(t, "device-z-tablet-mesh"))}),
	)

	if len(harness.issued) != 0 || harness.tokens.Outstanding() {
		t.Fatalf("issued %v, outstanding %v", harness.issued, harness.tokens.Outstanding())
	}
}

func TestTokenKindsDoNotCross(t *testing.T) {
	cases := map[string][2]string{
		"agent token, device CSR": {"agent-a", devPhone},
		"device token, agent CSR": {devPhone, "agent-a"},
	}

	for name, ids := range cases {
		t.Run(name, func(t *testing.T) {
			harness := newEnv(t)
			token, _, _ := harness.tokens.Create(ids[0])

			wantReject(
				t,
				harness.run(t, proto.Enroll{Token: token, CSR: string(csrFor(t, ids[1]))}),
			)

			if len(harness.issued) != 0 {
				t.Fatal("issued across kinds")
			}
		})
	}
}

func TestDeviceDisabledOrUnconfigured(t *testing.T) {
	harness := newEnv(t)
	harness.h.Allowed = func(string) error { return errNotConfigured }
	token, _, _ := harness.tokens.Create(devPhone)

	wantReject(t, harness.run(t, proto.Enroll{Token: token, CSR: string(csrFor(t, devPhone))}))

	if len(harness.issued) != 0 {
		t.Fatal("issued for an identity that may not enroll")
	}
}

// A device certificate that could also authenticate a TLS server is never handed out.
func TestDeviceLeafWithServerAuthRefused(t *testing.T) {
	harness := newEnv(t)
	harness.fake.Sign = func(csr []byte) ([]byte, []byte, error) {
		return harness.ca.SignCSRUsages(
			csr,
			time.Hour,
			[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		)
	}
	token, _, _ := harness.tokens.Create(devPhone)

	wantReject(t, harness.run(t, proto.Enroll{Token: token, CSR: string(csrFor(t, devPhone))}))

	if len(harness.issued) != 0 {
		t.Fatal("OnIssued called for a device leaf with server auth")
	}
}
