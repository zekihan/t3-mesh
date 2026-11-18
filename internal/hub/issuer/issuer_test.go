package issuer

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zekihan/t3-mesh/internal/pki"
	"github.com/zekihan/t3-mesh/internal/policy"
)

func testCSR(t *testing.T, identity string) []byte {
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
	csr := testCSR(t, "agent-z-mac")

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

	assertPostedRequest(t, posted, csr)
}

func asMap(t *testing.T, v any) map[string]any {
	t.Helper()

	m, ok := v.(map[string]any)
	if !ok {
		t.Fatalf("%v is not an object", v)
	}

	return m
}

func assertPostedRequest(t *testing.T, posted map[string]any, csr []byte) {
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

	assertPostedSpec(t, asMap(t, posted["spec"]), csr)
}

func assertPostedSpec(t *testing.T, spec map[string]any, csr []byte) {
	t.Helper()

	if spec["request"] != base64.StdEncoding.EncodeToString(csr) {
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

			_, _, err := k.Issue(t.Context(), "agent-a", testCSR(t, "agent-a"))
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

	_, _, err := k.Issue(t.Context(), "agent-a", testCSR(t, "agent-a"))
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

	_, _, err := k.Issue(ctx, "agent-a", testCSR(t, "agent-a"))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v", err)
	}
}

func TestIssueInvalidIdentity(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()

	k := newIssuer(t, srv, tokenFile(t, "tok"), nil)
	for _, id := range []string{"", "Agent", "a/b", "-a", strings.Repeat("a", 41)} {
		_, _, err := k.Issue(t.Context(), id, testCSR(t, "agent-a"))
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

// recordingAPI is a Kubernetes API stand-in that records every CertificateRequest
// the issuer creates and answers it with a certificate as soon as it is read.
type recordingAPI struct {
	srv    *httptest.Server
	cert   []byte
	posted []map[string]any
	mu     sync.Mutex
}

func newRecordingAPI(t *testing.T) *recordingAPI {
	t.Helper()

	api := &recordingAPI{}
	api.cert, _ = testCert(t, "leaf")

	api.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		api.mu.Lock()
		defer api.mu.Unlock()

		if r.Method == http.MethodPost {
			var body map[string]any

			err := json.NewDecoder(r.Body).Decode(&body)
			if err != nil {
				t.Error(err)
			}

			api.posted = append(api.posted, body)

			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"metadata":{"name":"cr-1"}}`))

			return
		}

		_ = json.NewEncoder(w).Encode(map[string]any{
			"metadata": map[string]any{"name": "cr-1"},
			"status": map[string]any{
				"certificate": api.cert,
				"conditions":  []map[string]string{{"type": "Ready", "status": "True"}},
			},
		})
	}))

	t.Cleanup(api.srv.Close)

	return api
}

func (api *recordingAPI) requests() []map[string]any {
	api.mu.Lock()
	defer api.mu.Unlock()

	return slices.Clone(api.posted)
}

// postedCSR decodes the CSR of a recorded CertificateRequest.
func postedCSR(t *testing.T, posted map[string]any) *x509.CertificateRequest {
	t.Helper()

	raw, err := base64.StdEncoding.DecodeString(asString(t, asMap(t, posted["spec"])["request"]))
	if err != nil {
		t.Fatal(err)
	}

	block, _ := pem.Decode(raw)
	if block == nil {
		t.Fatal("posted request is not PEM")
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	return csr
}

func asString(t *testing.T, v any) string {
	t.Helper()

	s, ok := v.(string)
	if !ok {
		t.Fatalf("%v is not a string", v)
	}

	return s
}

func postedUsages(t *testing.T, posted map[string]any) []string {
	t.Helper()

	list, ok := asMap(t, posted["spec"])["usages"].([]any)
	if !ok {
		t.Fatalf("usages %v is not a list", asMap(t, posted["spec"])["usages"])
	}

	out := make([]string, 0, len(list))
	for _, u := range list {
		out = append(out, asString(t, u))
	}

	return out
}

func rawCSR(t *testing.T, key any, tmpl *x509.CertificateRequest) []byte {
	t.Helper()

	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatal(err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()

	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}

	return u
}

func TestIssueDeviceRequest(t *testing.T) {
	api := newRecordingAPI(t)
	k := newIssuer(t, api.srv, tokenFile(t, "tok"), nil)

	cert, _, err := k.Issue(t.Context(), "device-z-phone-mesh", testCSR(t, "device-z-phone-mesh"))
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(cert, api.cert) {
		t.Error("certificate mismatch")
	}

	reqs := api.requests()
	if len(reqs) != 1 {
		t.Fatalf("%d requests created", len(reqs))
	}

	meta := asMap(t, reqs[0]["metadata"])
	if meta["generateName"] != "t3-mesh-device-z-phone-mesh-" {
		t.Errorf("generateName %v", meta["generateName"])
	}

	labels := asMap(t, meta["labels"])
	if labels[LabelIdentity] != "device-z-phone-mesh" || labels[LabelManagedBy] != ManagedByValue {
		t.Errorf("labels %v", labels)
	}

	assertDeviceSpec(t, reqs[0])
	assertDeviceCSR(t, postedCSR(t, reqs[0]))
}

// assertDeviceSpec checks the exact set the device approver-policy allows: client
// auth and digital signature, never server auth; 8760h; the clients issuer; not a CA.
func assertDeviceSpec(t *testing.T, posted map[string]any) {
	t.Helper()

	spec := asMap(t, posted["spec"])

	got := postedUsages(t, posted)
	if !slices.Equal(got, []string{"client auth", "digital signature"}) {
		t.Errorf("usages %v", got)
	}

	if spec["duration"] != "8760h0m0s" {
		t.Errorf("duration %v", spec["duration"])
	}

	if isCA, present := spec["isCA"]; present && isCA != false {
		t.Errorf("isCA %v", isCA)
	}

	ref := asMap(t, spec["issuerRef"])
	if ref["name"] != "clients" || ref["kind"] != "Issuer" || ref["group"] != "cert-manager.io" {
		t.Errorf("issuerRef %v", ref)
	}
}

func assertDeviceCSR(t *testing.T, csr *x509.CertificateRequest) {
	t.Helper()

	if len(csr.URIs) != 1 || csr.URIs[0].String() != "urn:noqer:mtls:clients:device-z-phone-mesh" ||
		len(csr.DNSNames) != 0 || len(csr.IPAddresses) != 0 || len(csr.EmailAddresses) != 0 {
		t.Errorf("CSR SANs %v %v", csr.URIs, csr.DNSNames)
	}

	pub, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		t.Errorf("CSR key %T", csr.PublicKey)
	}
}

func TestIssueAgentKeepsItsUsages(t *testing.T) {
	api := newRecordingAPI(t)
	k := newIssuer(t, api.srv, tokenFile(t, "tok"), nil)

	_, _, err := k.Issue(t.Context(), "agent-z-mac", testCSR(t, "agent-z-mac"))
	if err != nil {
		t.Fatal(err)
	}

	reqs := api.requests()
	if len(reqs) != 1 {
		t.Fatalf("%d requests created", len(reqs))
	}

	want := []string{"client auth", "server auth", "digital signature"}
	if got := postedUsages(t, reqs[0]); !slices.Equal(got, want) {
		t.Errorf("usages %v", got)
	}
}

// Every request the hub creates carries the usages and the URI of exactly one
// kind, and a call that would mix them creates no request at all. The homelab
// policies deny a mixed request, so the hub must never send one.
func TestIssueNeverMixesKinds(t *testing.T) {
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

	agentURI := mustURL(t, "urn:noqer:mtls:clients:agent-z-mac")
	deviceURI := mustURL(t, "urn:noqer:mtls:clients:device-z-phone-mesh")
	phoneURI := mustURL(t, "urn:noqer:mtls:clients:z-phone")
	caExt := pkix.Extension{
		Id: asn1.ObjectIdentifier{2, 5, 29, 19}, Value: []byte{0x30, 0x03, 0x01, 0x01, 0xff},
	}

	cases := []struct {
		name     string
		identity string
		csr      []byte
		wantErr  bool
	}{
		{name: "agent", identity: "agent-z-mac", csr: testCSR(t, "agent-z-mac")},
		{name: "device", identity: "device-z-phone-mesh", csr: testCSR(t, "device-z-phone-mesh")},
		{
			name: "agent name with a device CSR", identity: "agent-z-mac", wantErr: true,
			csr: testCSR(t, "device-z-phone-mesh"),
		},
		{
			name: "device name with an agent CSR", identity: "device-z-phone-mesh", wantErr: true,
			csr: testCSR(t, "agent-z-mac"),
		},
		{
			name:     "device name with an agent and a device URI",
			identity: "device-z-phone-mesh",
			wantErr:  true,
			csr: rawCSR(
				t,
				key,
				&x509.CertificateRequest{URIs: []*url.URL{deviceURI, agentURI}},
			),
		},
		{
			name:     "agent name with an agent and a device URI",
			identity: "agent-z-mac",
			wantErr:  true,
			csr: rawCSR(
				t,
				key,
				&x509.CertificateRequest{URIs: []*url.URL{agentURI, deviceURI}},
			),
		},
		{
			name:     "device name with a KeyChain identity URI",
			identity: "device-z-phone-mesh",
			wantErr:  true,
			csr:      rawCSR(t, key, &x509.CertificateRequest{URIs: []*url.URL{phoneURI}}),
		},
		{
			name: "KeyChain identity", identity: "z-phone", wantErr: true,
			csr: rawCSR(t, key, &x509.CertificateRequest{URIs: []*url.URL{phoneURI}}),
		},
		{
			name: "device lookalike", identity: "device-z-phone", wantErr: true,
			csr: testCSR(t, "device-z-phone"),
		},
		{
			name: "device with P-384 key", identity: "device-z-phone-mesh", wantErr: true,
			csr: rawCSR(t, p384, &x509.CertificateRequest{URIs: []*url.URL{deviceURI}}),
		},
		{
			name: "device with RSA key", identity: "device-z-phone-mesh", wantErr: true,
			csr: rawCSR(t, rsaKey, &x509.CertificateRequest{URIs: []*url.URL{deviceURI}}),
		},
		{
			name: "device with a DNS SAN", identity: "device-z-phone-mesh", wantErr: true,
			csr: rawCSR(t, key, &x509.CertificateRequest{
				URIs: []*url.URL{deviceURI}, DNSNames: []string{"a.example"},
			}),
		},
		{
			name: "device asking to be a CA", identity: "device-z-phone-mesh", wantErr: true,
			csr: rawCSR(t, key, &x509.CertificateRequest{
				URIs: []*url.URL{deviceURI}, ExtraExtensions: []pkix.Extension{caExt},
			}),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			api := newRecordingAPI(t)
			k := newIssuer(t, api.srv, tokenFile(t, "tok"), nil)

			_, _, err := k.Issue(t.Context(), tc.identity, tc.csr)
			reqs := api.requests()

			if tc.wantErr {
				if err == nil || len(reqs) != 0 {
					t.Fatalf("err = %v, %d requests created", err, len(reqs))
				}

				return
			}

			if err != nil || len(reqs) != 1 {
				t.Fatalf("err = %v, %d requests created", err, len(reqs))
			}

			checkOneKind(t, reqs[0])
		})
	}
}

// checkOneKind asserts the invariant the two homelab policies rely on: the
// usages and the URI of a created request belong to the same kind.
func checkOneKind(t *testing.T, posted map[string]any) {
	t.Helper()

	csr := postedCSR(t, posted)
	if len(csr.URIs) != 1 {
		t.Fatalf("CSR has %d URIs", len(csr.URIs))
	}

	name, err := policy.IdentityFromURI(csr.URIs[0].String())
	if err != nil {
		t.Fatal(err)
	}

	hasServerAuth := slices.Contains(postedUsages(t, posted), "server auth")

	switch {
	case policy.IsAgent(name) && !hasServerAuth, policy.IsDevice(name) && hasServerAuth:
		t.Errorf("%s requested with usages %v", name, postedUsages(t, posted))
	case !policy.IsAgent(name) && !policy.IsDevice(name):
		t.Errorf("request for %q, which is neither an agent nor a device", name)
	}
}
