package issuer

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

func testCert(t *testing.T, cn string) ([]byte, string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}

	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	sum := sha256.Sum256(der)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	return certPEM, hex.EncodeToString(sum[:])
}

func newIssuer(t *testing.T, srv *httptest.Server, tokenPath string, logger *slog.Logger) *K8s {
	t.Helper()

	iss, err := New(Config{
		Namespace:    "mtls-pki",
		Issuer:       IssuerRef{Name: "clients", Kind: "Issuer", Group: "cert-manager.io"},
		APIServer:    srv.URL,
		TokenPath:    tokenPath,
		HTTPClient:   srv.Client(),
		PollInterval: 5 * time.Millisecond,
		Logger:       logger,
	})
	if err != nil {
		t.Fatal(err)
	}

	return iss
}

func tokenFile(t *testing.T, content string) string {
	t.Helper()

	tokenPath := filepath.Join(t.TempDir(), "token")

	err := os.WriteFile(tokenPath, []byte(content), 0o600)
	if err != nil {
		t.Fatal(err)
	}

	return tokenPath
}

const crPath = "/apis/cert-manager.io/v1/namespaces/mtls-pki/certificaterequests"

func TestIssuePollsToReady(t *testing.T) {
	certPEM, fp := testCert(t, "leaf")
	caPEM, _ := testCert(t, "ca")
	csr := []byte("-----BEGIN CERTIFICATE REQUEST-----\nabc\n-----END CERTIFICATE REQUEST-----\n")

	var (
		mu     sync.Mutex
		gets   int
		posted map[string]any
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()

		if r.Header.Get("Authorization") != "Bearer tok" {
			t.Errorf("auth header %q", r.Header.Get("Authorization"))
		}

		switch {
		case r.Method == http.MethodPost && r.URL.Path == crPath:
			err := json.NewDecoder(r.Body).Decode(&posted)
			if err != nil {
				t.Error(err)
			}

			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"metadata":{"name":"t3-mesh-agent-z-mac-abcde"}}`))
		case r.Method == http.MethodGet && r.URL.Path == crPath+"/t3-mesh-agent-z-mac-abcde":
			gets++

			resp := map[string]any{"metadata": map[string]any{"name": "t3-mesh-agent-z-mac-abcde"}}
			if gets >= 3 {
				resp["status"] = map[string]any{
					"certificate": certPEM, "ca": caPEM,
					"conditions": []map[string]string{{"type": "Ready", "status": "True"}},
				}
			} else {
				resp["status"] = map[string]any{
					"conditions": []map[string]string{
						{"type": "Ready", "status": "False", "reason": "Pending"},
					},
				}
			}

			_ = json.NewEncoder(w).Encode(resp)
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	var logbuf bytes.Buffer

	logger := slog.New(slog.NewTextHandler(&logbuf, nil))
	k := newIssuer(t, srv, tokenFile(t, "tok\n"), logger)

	cert, chain, err := k.Issue(t.Context(), "agent-z-mac", csr)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(cert, certPEM) || !bytes.Equal(chain, caPEM) {
		t.Error("cert/chain mismatch")
	}

	if gets != 3 {
		t.Errorf("gets = %d", gets)
	}

	for _, want := range []string{
		"Certificate issued",
		"identity=agent-z-mac",
		"fingerprint=" + fp,
		"request=t3-mesh-agent-z-mac-abcde",
	} {
		if !strings.Contains(logbuf.String(), want) {
			t.Errorf("log missing %q: %s", want, logbuf.String())
		}
	}

	assertPostedRequest(t, posted)
}

func asMap(t *testing.T, v any) map[string]any {
	t.Helper()

	m, ok := v.(map[string]any)
	if !ok {
		t.Fatalf("%v is not an object", v)
	}

	return m
}

func assertPostedRequest(t *testing.T, posted map[string]any) {
	t.Helper()

	if posted["apiVersion"] != "cert-manager.io/v1" || posted["kind"] != "CertificateRequest" {
		t.Errorf("type: %v", posted)
	}

	meta := asMap(t, posted["metadata"])
	if meta["generateName"] != "t3-mesh-agent-z-mac-" {
		t.Errorf("generateName %v", meta["generateName"])
	}

	labels := asMap(t, meta["labels"])
	if labels["t3-mesh.noqer.com/identity"] != "agent-z-mac" ||
		labels["app.kubernetes.io/managed-by"] != "t3-mesh-hub" {
		t.Errorf("labels %v", labels)
	}

	assertPostedSpec(t, asMap(t, posted["spec"]))
}

func assertPostedSpec(t *testing.T, spec map[string]any) {
	t.Helper()

	const wantRequest = "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0KYWJjCi0t" +
		"LS0tRU5EIENFUlRJRklDQVRFIFJFUVVFU1QtLS0tLQo="
	if spec["request"] != wantRequest {
		t.Errorf("request %v", spec["request"])
	}

	if spec["duration"] != "8760h0m0s" {
		t.Errorf("duration %v", spec["duration"])
	}

	ref := asMap(t, spec["issuerRef"])
	if ref["name"] != "clients" || ref["kind"] != "Issuer" || ref["group"] != "cert-manager.io" {
		t.Errorf("issuerRef %v", ref)
	}

	usages, ok := spec["usages"].([]any)
	if !ok {
		t.Fatalf("usages %v is not a list", spec["usages"])
	}

	if len(usages) != 3 || usages[0] != "client auth" || usages[1] != "server auth" ||
		usages[2] != "digital signature" {
		t.Errorf("usages %v", usages)
	}
}

func TestIssueDenied(t *testing.T) {
	for name, cond := range map[string]map[string]string{
		"denied": {
			"type": "Denied", "status": "True", "reason": "policy", "message": "no policy allows it",
		},
		"ready-failed": {
			"type": "Ready", "status": "False", "reason": "Failed", "message": "no policy allows it",
		},
		"ready-denied": {
			"type": "Ready", "status": "False", "reason": "Denied", "message": "no policy allows it",
		},
	} {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(
				http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Method == http.MethodPost {
						w.WriteHeader(http.StatusCreated)
						_, _ = w.Write([]byte(`{"metadata":{"name":"x"}}`))

						return
					}

					_ = json.NewEncoder(w).Encode(map[string]any{
						"metadata": map[string]any{"name": "x"},
						"status":   map[string]any{"conditions": []any{cond}},
					})
				}),
			)
			defer srv.Close()

			k := newIssuer(t, srv, tokenFile(t, "tok"), nil)

			_, _, err := k.Issue(t.Context(), "agent-a", []byte("csr"))
			if err == nil || !strings.Contains(err.Error(), "no policy allows it") {
				t.Fatalf("err = %v", err)
			}
		})
	}
}

func TestIssueCreateError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer srv.Close()

	k := newIssuer(t, srv, tokenFile(t, "tok"), nil)

	_, _, err := k.Issue(t.Context(), "agent-a", []byte("csr"))
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("err = %v", err)
	}
}

func TestIssueContextTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusCreated)
		}

		_, _ = w.Write([]byte(`{"metadata":{"name":"x"}}`))
	}))
	defer srv.Close()

	k := newIssuer(t, srv, tokenFile(t, "tok"), nil)

	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()

	_, _, err := k.Issue(ctx, "agent-a", []byte("csr"))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v", err)
	}
}

func TestIssueInvalidIdentity(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()

	k := newIssuer(t, srv, tokenFile(t, "tok"), nil)
	for _, id := range []string{"", "Agent", "a/b", "-a", strings.Repeat("a", 41)} {
		_, _, err := k.Issue(t.Context(), id, []byte("csr"))
		if err == nil {
			t.Errorf("identity %q accepted", id)
		}
	}
}

func TestNewestOrdering(t *testing.T) {
	oldPEM, _ := testCert(t, "old")
	newPEM, newFP := testCert(t, "new")
	pendingPEM, _ := testCert(t, "pending")

	var query string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query = r.URL.Query().Get("labelSelector")
		item := func(name, ts string, cert []byte) map[string]any {
			body := map[string]any{
				"metadata": map[string]any{
					"name":              name,
					"creationTimestamp": ts,
					"labels":            map[string]string{LabelIdentity: "agent-a"},
				},
			}
			if cert != nil {
				body["status"] = map[string]any{"certificate": cert}
			}

			return body
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"items": []any{
			item("b", "2026-03-01T00:00:00Z", newPEM),
			item("a", "2026-01-01T00:00:00Z", oldPEM),
			item("c", "2026-04-01T00:00:00Z", nil),
			item("d", "2026-02-01T00:00:00Z", pendingPEM),
		}})
	}))
	defer srv.Close()

	k := newIssuer(t, srv, tokenFile(t, "tok"), nil)

	fp, err := k.Newest(t.Context(), "agent-a")
	if err != nil {
		t.Fatal(err)
	}

	if fp != newFP {
		t.Errorf("fp = %s, want %s", fp, newFP)
	}

	if query != "app.kubernetes.io/managed-by=t3-mesh-hub,t3-mesh.noqer.com/identity=agent-a" {
		t.Errorf("selector %q", query)
	}
}

func TestNewestNone(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"items":[]}`))
	}))
	defer srv.Close()

	k := newIssuer(t, srv, tokenFile(t, "tok"), nil)

	fp, err := k.Newest(t.Context(), "agent-a")
	if err != nil || fp != "" {
		t.Fatalf("fp=%q err=%v", fp, err)
	}
}

func TestTokenReread(t *testing.T) {
	var (
		mu   sync.Mutex
		seen []string
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()

		seen = append(seen, r.Header.Get("Authorization"))
		mu.Unlock()

		_, _ = w.Write([]byte(`{"items":[]}`))
	}))
	defer srv.Close()

	tp := tokenFile(t, "one")

	iss := newIssuer(t, srv, tp, nil)

	_, err := iss.Newest(t.Context(), "agent-a")
	if err != nil {
		t.Fatal(err)
	}

	err = os.WriteFile(tp, []byte("two\n"), 0o600)
	if err != nil {
		t.Fatal(err)
	}

	_, err = iss.Newest(t.Context(), "agent-a")
	if err != nil {
		t.Fatal(err)
	}

	if len(seen) != 2 || seen[0] != "Bearer one" || seen[1] != "Bearer two" {
		t.Errorf("seen %v", seen)
	}
}

func TestNewValidation(t *testing.T) {
	_, err := New(Config{})
	if err == nil {
		t.Error("empty config accepted")
	}

	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	t.Setenv("KUBERNETES_SERVICE_PORT", "")

	_, err = New(
		Config{
			Namespace:  "n",
			Issuer:     IssuerRef{"a", "Issuer", "cert-manager.io"},
			HTTPClient: http.DefaultClient,
		},
	)
	if err == nil {
		t.Error("missing API server accepted")
	}

	t.Setenv("KUBERNETES_SERVICE_HOST", "::1")
	t.Setenv("KUBERNETES_SERVICE_PORT", "443")

	iss, err := New(
		Config{
			Namespace:  "n",
			Issuer:     IssuerRef{"a", "Issuer", "cert-manager.io"},
			HTTPClient: http.DefaultClient,
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	if iss.base != "https://[::1]:443" {
		t.Errorf("base %q", iss.base)
	}
}

type prunedCR struct {
	name, ts string
	flight   bool
	cert     bool
}

func pruneServer(
	t *testing.T,
	crs []prunedCR,
	notFound string,
) (*httptest.Server, func() []string) {
	t.Helper()

	var (
		mu      sync.Mutex
		deleted []string
	)

	const crPath = "/apis/cert-manager.io/v1/namespaces/mtls-pki/certificaterequests"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()

		switch {
		case r.Method == http.MethodGet && r.URL.Path == crPath:
			sel := r.URL.Query().Get("labelSelector")
			if sel != "app.kubernetes.io/managed-by=t3-mesh-hub,t3-mesh.noqer.com/identity=agent-a" {
				t.Errorf("selector %q", sel)
			}

			items := make([]map[string]any, 0, len(crs))

			for _, cr := range crs {
				st := map[string]any{}
				if cr.cert {
					st["certificate"] = "Y2VydA=="
				}

				if !cr.flight {
					st["conditions"] = []map[string]string{{"type": "Ready", "status": "True"}}
				}

				items = append(items, map[string]any{
					"metadata": map[string]any{
						"name": cr.name, "creationTimestamp": cr.ts,
						"labels": map[string]string{"t3-mesh.noqer.com/identity": "agent-a"},
					},
					"status": st,
				})
			}

			_ = json.NewEncoder(w).Encode(map[string]any{"items": items})
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, crPath+"/"):
			name := strings.TrimPrefix(r.URL.Path, crPath+"/")
			deleted = append(deleted, name)

			if name == notFound {
				http.Error(w, "gone", http.StatusNotFound)

				return
			}

			_, _ = w.Write([]byte(`{}`))
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL)
		}
	}))

	return srv, func() []string {
		mu.Lock()
		defer mu.Unlock()

		out := slices.Clone(deleted)
		slices.Sort(out)

		return out
	}
}

func TestPruneSelection(t *testing.T) {
	crs := []prunedCR{
		{name: "a", ts: "2026-01-05T00:00:00Z", cert: true},
		{name: "b", ts: "2026-01-04T00:00:00Z", cert: true},
		{name: "c", ts: "2026-01-03T00:00:00Z", cert: true},
		{name: "d", ts: "2026-01-02T00:00:00Z", flight: true},
		{name: "e", ts: "2026-01-01T00:00:00Z", cert: true},
		{name: "f", ts: "2026-01-01T00:00:00Z", cert: true},
	}

	srv, deleted := pruneServer(t, crs, "")
	defer srv.Close()

	var logbuf bytes.Buffer

	k := newIssuer(t, srv, tokenFile(t, "tok"), slog.New(slog.NewTextHandler(&logbuf, nil)))

	err := k.Prune(t.Context(), "agent-a", 2)
	if err != nil {
		t.Fatal(err)
	}

	// Kept: a, b (newest two), d (in flight). Deleted: c, e, f.
	if got := deleted(); !slices.Equal(got, []string{"c", "e", "f"}) {
		t.Fatalf("deleted = %v", got)
	}

	for _, want := range []string{"request=c", "identity=agent-a"} {
		if !strings.Contains(logbuf.String(), want) {
			t.Errorf("log missing %q: %s", want, logbuf.String())
		}
	}
}

func TestPruneKeepsNewestIssued(t *testing.T) {
	// The two newest are in flight; the newest issued one must survive keep=1.
	crs := []prunedCR{
		{name: "a", ts: "2026-01-05T00:00:00Z", flight: true},
		{name: "b", ts: "2026-01-04T00:00:00Z", cert: true},
		{name: "c", ts: "2026-01-03T00:00:00Z", cert: true},
	}

	srv, deleted := pruneServer(t, crs, "")
	defer srv.Close()

	err := newIssuer(t, srv, tokenFile(t, "tok"), nil).Prune(t.Context(), "agent-a", 1)
	if err != nil {
		t.Fatal(err)
	}

	if got := deleted(); !slices.Equal(got, []string{"c"}) {
		t.Fatalf("deleted = %v", got)
	}
}

func TestPruneNotFoundIsSuccess(t *testing.T) {
	crs := []prunedCR{
		{name: "a", ts: "2026-01-05T00:00:00Z", cert: true},
		{name: "b", ts: "2026-01-04T00:00:00Z", cert: true},
		{name: "c", ts: "2026-01-03T00:00:00Z", cert: true},
		{name: "d", ts: "2026-01-02T00:00:00Z", cert: true},
	}

	srv, deleted := pruneServer(t, crs, "c")
	defer srv.Close()

	err := newIssuer(t, srv, tokenFile(t, "tok"), nil).Prune(t.Context(), "agent-a", 2)
	if err != nil {
		t.Fatalf("err = %v", err)
	}

	if got := deleted(); !slices.Equal(got, []string{"c", "d"}) {
		t.Fatalf("deleted = %v", got)
	}
}
