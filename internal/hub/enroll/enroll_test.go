package enroll

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zekihan/t3-mesh/internal/hub/issuer/issuertest"
	"github.com/zekihan/t3-mesh/internal/pki"
	"github.com/zekihan/t3-mesh/internal/pki/pkitest"
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
	issued []string
}

func newEnv(t *testing.T) *env {
	t.Helper()

	ca := pkitest.NewCA(t, "test")
	clk := &clock{t: time.Unix(1_700_000_000, 0)}
	harness := &env{clk: clk, tokens: NewTokens(clk.Now)}
	harness.fake = &issuertest.Fake{Sign: func(csr []byte) ([]byte, []byte, error) {
		return ca.SignCSR(csr, time.Hour)
	}}
	lim := NewLimiter(clk.Now)
	harness.h = &Handler{
		Tokens:   harness.tokens,
		Issuer:   harness.fake,
		Allowed:  func(string) error { return nil },
		OnIssued: func(id, fp string) { harness.issued = append(harness.issued, id+" "+fp) },
		Limiter:  lim,
		Now:      clk.Now,
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

	admin := &Admin{Path: path, Tokens: tk, Allowed: func(id string) error {
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
		token, expires, err = RequestToken(ctx, path, "agent-a")
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

	_, _, err = RequestToken(ctx, path, "bad")
	if err == nil {
		t.Fatal("disallowed identity got a token")
	}

	cancel()

	err = <-errc
	if err != nil {
		t.Fatal(err)
	}
}
