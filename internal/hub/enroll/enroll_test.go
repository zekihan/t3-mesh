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
	mu sync.Mutex
	t  time.Time
}

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
	issued []string
	fake   *issuertest.Fake
}

func newEnv(t *testing.T) *env {
	t.Helper()

	ca := pkitest.NewCA(t, "test")
	clk := &clock{t: time.Unix(1_700_000_000, 0)}
	e := &env{clk: clk, tokens: NewTokens(clk.Now)}
	e.fake = &issuertest.Fake{Sign: func(csr []byte) ([]byte, []byte, error) {
		return ca.SignCSR(csr, time.Hour)
	}}
	lim := NewLimiter(clk.Now)
	e.h = &Handler{
		Tokens:   e.tokens,
		Issuer:   e.fake,
		Allowed:  func(string) error { return nil },
		OnIssued: func(id, fp string) { e.issued = append(e.issued, id+" "+fp) },
		Limiter:  lim,
		Now:      clk.Now,
	}

	return e
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
func (e *env) run(t *testing.T, req proto.Message) proto.Message {
	t.Helper()

	client, server := net.Pipe()
	done := make(chan struct{})

	go func() {
		defer close(done)
		e.h.Serve(context.Background(), server, netip.MustParseAddr("192.0.2.1"))
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
	e := newEnv(t)
	token, _, _ := e.tokens.Create("agent-a")
	msg := e.run(t, proto.Enroll{Token: token, CSR: string(csrFor(t, "agent-a"))})

	en, ok := msg.(proto.Enrolled)
	if !ok {
		t.Fatalf("got %#v", msg)
	}

	certs, err := pki.ParseCertsPEM([]byte(en.Certificate))
	if err != nil || len(certs) != 1 {
		t.Fatalf("certs: %v", err)
	}

	if len(e.issued) != 1 || e.issued[0] != "agent-a "+pki.Fingerprint(certs[0]) {
		t.Fatalf("issued %v", e.issued)
	}

	if e.tokens.Outstanding() {
		t.Fatal("token still outstanding")
	}
}

func TestWrongToken(t *testing.T) {
	e := newEnv(t)
	_, _, _ = e.tokens.Create("agent-a")
	wantReject(t, e.run(t, proto.Enroll{Token: "nope", CSR: string(csrFor(t, "agent-a"))}))
}

func TestExpiredToken(t *testing.T) {
	e := newEnv(t)
	token, _, _ := e.tokens.Create("agent-a")
	e.clk.Advance(TokenTTL + time.Second)
	wantReject(t, e.run(t, proto.Enroll{Token: token, CSR: string(csrFor(t, "agent-a"))}))
}

func TestReusedToken(t *testing.T) {
	e := newEnv(t)
	token, _, _ := e.tokens.Create("agent-a")
	req := proto.Enroll{Token: token, CSR: string(csrFor(t, "agent-a"))}

	if _, ok := e.run(t, req).(proto.Enrolled); !ok {
		t.Fatal("first use failed")
	}

	wantReject(t, e.run(t, req))
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
	e.h.Allowed = func(string) error { return errors.New("disabled") }
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
	e := newEnv(t)

	for range 5 {
		wantReject(t, e.run(t, proto.Enroll{Token: "x", CSR: "y"}))
	}

	// Sixth attempt is limited before anything is read: the reject arrives without a request.
	wantReject(t, e.run(t, nil))

	e.clk.Advance(11 * time.Minute)
	wantReject(t, e.run(t, proto.Enroll{Token: "x", CSR: "y"}))

	if !e.h.Limiter.Allow(netip.MustParseAddr("192.0.2.1")) {
		t.Fatal("limiter did not recover")
	}
}

func TestLimiterBounded(t *testing.T) {
	clk := &clock{t: time.Unix(0, 0)}
	l := NewLimiter(clk.Now)
	l.MaxEntries = 2

	if !l.Allow(netip.MustParseAddr("192.0.2.1")) || !l.Allow(netip.MustParseAddr("192.0.2.2")) {
		t.Fatal("first two refused")
	}

	if l.Allow(netip.MustParseAddr("192.0.2.3")) {
		t.Fatal("third allowed with full table")
	}

	clk.Advance(time.Hour)

	if !l.Allow(netip.MustParseAddr("192.0.2.3")) {
		t.Fatal("not allowed after cleanup")
	}
}

func TestTokensReplace(t *testing.T) {
	tk := NewTokens(time.Now)
	first, _, _ := tk.Create("agent-a")
	second, _, _ := tk.Create("agent-a")

	if _, err := tk.Redeem(first); err == nil {
		t.Fatal("replaced token redeemable")
	}

	if id, err := tk.Redeem(second); err != nil || id != "agent-a" {
		t.Fatalf("redeem: %q %v", id, err)
	}
}

func TestAdminRoundTrip(t *testing.T) {
	tk := NewTokens(time.Now)
	path := filepath.Join(t.TempDir(), "admin.sock")
	// Stale file must be replaced.
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	a := &Admin{Path: path, Tokens: tk, Allowed: func(id string) error {
		if id == "bad" {
			return errors.New("not configured")
		}

		return nil
	}}
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)

	go func() { errc <- a.Serve(ctx) }()

	var (
		token   string
		expires time.Time
		err     error
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

	if id, err := tk.Redeem(token); err != nil || id != "agent-a" {
		t.Fatalf("redeem: %q %v", id, err)
	}

	if _, _, err = RequestToken(ctx, path, "bad"); err == nil {
		t.Fatal("disallowed identity got a token")
	}

	cancel()

	if err := <-errc; err != nil {
		t.Fatal(err)
	}
}
