package hub

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/iotest"
	"time"

	"github.com/zekihan/t3-mesh/internal/hub/issuer"
	"github.com/zekihan/t3-mesh/internal/hub/issuer/issuertest"
	"github.com/zekihan/t3-mesh/internal/pki"
	"github.com/zekihan/t3-mesh/internal/policy"
)

const pemType = "application/x-pem-file"

type renewCall struct {
	notAfter    time.Time
	viewer      string
	fp          string
	contentType string
	method      string
	body        []byte
}

// renewAs posts a renewal as the given caller. The zero values are an enrolled
// device's valid request, so each test names only what it changes.
func (harness *env) renewAs(call *renewCall) apiResponse {
	harness.t.Helper()

	if call.method == "" {
		call.method = http.MethodPost
	}

	if call.contentType == "" {
		call.contentType = pemType
	}

	if call.notAfter.IsZero() {
		call.notAfter = farFuture
	}

	req, _ := http.NewRequestWithContext(
		harness.t.Context(),
		call.method,
		harness.viewer.URL+"/api/v1/renew",
		bytes.NewReader(call.body),
	)
	req.Host = apiHost
	req.Header.Set("Content-Type", call.contentType)
	setViewerHeaders(req.Header, call.viewer, call.fp, call.notAfter)

	resp, err := oneShotClient.Do(req)
	if err != nil {
		harness.t.Fatal(err)
	}

	defer func() { _ = resp.Body.Close() }()

	b, _ := io.ReadAll(resp.Body)

	return apiResponse{status: resp.StatusCode, body: string(b), header: resp.Header}
}

func newDeviceCSR(t *testing.T, identity string) []byte {
	t.Helper()

	return []byte(deviceCSR(t, identity))
}

// renewEnv is a hub with both devices configured and allowed on the API, and the
// phone's first leaf issued.
func renewEnv(t *testing.T) (*env, string) {
	t.Helper()

	harness := newEnv(t)
	harness.setConfig(
		cfgOpts{devices: bothDevices, api: append([]string{"z-phone"}, bothDevices...)},
	)
	harness.connect("agent-devbox", "devbox-body")

	fp := harness.newDeviceFP(devPhone)

	return harness, fp
}

// noIssuance asserts the hub asked the issuer for nothing for identity.
func noIssuance(t *testing.T, harness *env, identity, wantNewest string) {
	t.Helper()

	got, _ := harness.fake.Newest(t.Context(), identity)
	if got != wantNewest {
		t.Fatalf("newest for %s = %q, want %q: a certificate was issued", identity, got, wantNewest)
	}
}

func TestRenewDevice(t *testing.T) {
	harness, oldFP := renewEnv(t)

	// The old leaf's stream is open when the renewal lands.
	stream, closeStream := openStreamAs(t, harness, devPhone, oldFP, "/stream", farFuture)
	defer closeStream()

	resp := harness.renewAs(
		&renewCall{viewer: devPhone, fp: oldFP, body: newDeviceCSR(t, devPhone)},
	)
	if resp.status != http.StatusOK {
		t.Fatalf("status %d: %s", resp.status, resp.body)
	}

	if resp.header.Get("Content-Type") != "application/json" ||
		resp.header.Get("Cache-Control") != "no-store" {
		t.Fatalf("headers = %v", resp.header)
	}

	newFP := checkRenewReply(t, harness, resp.body)
	noIssuance(t, harness, devPhone, newFP)

	eventually(t, func() bool {
		return slices.Contains(
			harness.fake.PruneCalls(), issuertest.PruneCall{Identity: devPhone, Keep: 2},
		)
	})

	// The old leaf is refused at once, on viewer hosts and the API, and its stream ends.
	expectStreamClosed(t, stream)

	if code := harness.deviceViewerStatus(devPhone, oldFP); code != http.StatusForbidden {
		t.Errorf("old leaf on a viewer host got %d", code)
	}

	if code := harness.deviceAPIStatus(
		devPhone,
		oldFP,
		"/api/v1/machines",
	); code != http.StatusForbidden {
		t.Errorf("old leaf on the API got %d", code)
	}

	if code := harness.deviceViewerStatus(devPhone, newFP); code != http.StatusOK {
		t.Errorf("new leaf on a viewer host got %d", code)
	}

	// The old leaf cannot renew with a different key.
	again := harness.renewAs(
		&renewCall{viewer: devPhone, fp: oldFP, body: newDeviceCSR(t, devPhone)},
	)
	if again.status != http.StatusForbidden {
		t.Errorf("renewal with the superseded leaf got %d", again.status)
	}

	// The new leaf renews again.
	next := harness.renewAs(
		&renewCall{viewer: devPhone, fp: newFP, body: newDeviceCSR(t, devPhone)},
	)
	if next.status != http.StatusOK {
		t.Errorf("renewal with the new leaf got %d: %s", next.status, next.body)
	}
}

func recoveryCSR(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()

	csr, err := pki.CreateCSR(key, devPhone)
	if err != nil {
		t.Fatal(err)
	}

	return csr
}

func TestRenewalReplyRecovery(t *testing.T) {
	for _, scenario := range []string{
		"replay", "different key", "earlier leaf", "expired replay",
		"blocked previous leaf", "blocked issued leaf", "disabled identity",
	} {
		t.Run(scenario, func(t *testing.T) {
			harness, oldFP := renewEnv(t)

			key, err := pki.GenerateKey()
			if err != nil {
				t.Fatal(err)
			}

			previous := oldFP
			if scenario == "earlier leaf" {
				previous = harness.newDeviceFP(devPhone)
			}

			original := harness.renewAs(
				&renewCall{viewer: devPhone, fp: previous, body: recoveryCSR(t, key)},
			)
			if original.status != http.StatusOK {
				t.Fatalf("first renewal: %d %s", original.status, original.body)
			}

			newest := checkRenewReply(t, harness, original.body)

			cfg := cfgOpts{devices: bothDevices, api: bothDevices}
			call := renewCall{viewer: devPhone, fp: oldFP, body: recoveryCSR(t, key)}
			want := http.StatusForbidden

			switch scenario {
			case "replay":
				want = http.StatusOK
			case "different key":
				call.body = newDeviceCSR(t, devPhone)
			case "expired replay":
				harness.offset.Store(int64(renewalReplayWindow))
			case "blocked previous leaf":
				cfg.blocked = []string{oldFP}
			case "blocked issued leaf":
				cfg.blocked = []string{newest}
			case "disabled identity":
				cfg.disabled = []string{devPhone}
			}

			harness.setConfig(cfg)

			got := harness.renewAs(&call)
			if got.status != want {
				t.Fatalf("replay: %d, want %d: %s", got.status, want, got.body)
			}

			if want == http.StatusOK && got.body != original.body {
				t.Error("replay did not return the original certificate and chain")
			}

			noIssuance(t, harness, devPhone, newest)
		})
	}
}

// checkRenewReply checks the exact shape of a renewal reply and returns the
// fingerprint of the certificate it carries.
func checkRenewReply(t *testing.T, harness *env, body string) string {
	t.Helper()

	var reply map[string]string

	err := json.Unmarshal([]byte(body), &reply)
	if err != nil {
		t.Fatal(err)
	}

	keys := make([]string, 0, len(reply))
	for k := range reply {
		keys = append(keys, k)
	}

	slices.Sort(keys)

	if !slices.Equal(keys, []string{"caBundle", "caRevision", "certificate", "chain"}) {
		t.Fatalf("reply fields = %v", keys)
	}

	if reply["caBundle"] != string(harness.ca.CertPEM) || reply["caRevision"] != "trust-1" ||
		reply["chain"] != string(harness.ca.CertPEM) {
		t.Fatalf("reply = %v", reply)
	}

	certs, err := pki.ParseCertsPEM([]byte(reply["certificate"]))
	if err != nil || len(certs) != 1 {
		t.Fatalf("certificate: %v", err)
	}

	if id, _ := pki.CertIdentity(certs[0]); id != devPhone {
		t.Fatalf("identity %q", id)
	}

	err = pki.CheckDeviceLeaf(certs[0])
	if err != nil {
		t.Fatalf("leaf usages: %v", err)
	}

	return pki.Fingerprint(certs[0])
}

func TestRenewAcceptsCharsetParameter(t *testing.T) {
	harness, fp := renewEnv(t)

	resp := harness.renewAs(&renewCall{
		viewer: devPhone, fp: fp, body: newDeviceCSR(t, devPhone),
		contentType: pemType + "; charset=utf-8",
	})
	if resp.status != http.StatusOK {
		t.Fatalf("status %d: %s", resp.status, resp.body)
	}
}

type renewDeadlineRecorder struct {
	*httptest.ResponseRecorder

	deadline time.Time
}

func (rec *renewDeadlineRecorder) SetReadDeadline(deadline time.Time) error {
	rec.deadline = deadline

	return nil
}

func TestRenewBodyReadTimeout(t *testing.T) {
	harness, fp := renewEnv(t)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "https://"+apiHost+
		"/api/v1/renew", iotest.ErrReader(os.ErrDeadlineExceeded))
	req.Header.Set("Content-Type", pemType)
	setViewerHeaders(req.Header, devPhone, fp, farFuture)

	rec := &renewDeadlineRecorder{ResponseRecorder: httptest.NewRecorder()}

	harness.srv.ViewerHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestTimeout || rec.deadline.IsZero() {
		t.Fatalf("status %d, read deadline %v: %s", rec.Code, rec.deadline, rec.Body)
	}

	noIssuance(t, harness, devPhone, fp)
}

// The KeyChain identities are API callers, and the renewal endpoint refuses them.
func TestRenewRefusesKeyChainIdentity(t *testing.T) {
	harness, phoneFP := renewEnv(t)

	for _, csr := range [][]byte{
		newDeviceCSR(t, "z-phone"),
		newDeviceCSR(t, devPhone), // a device CSR from a KeyChain caller
		newDeviceCSR(t, "agent-devbox"),
	} {
		resp := harness.renewAs(&renewCall{viewer: "z-phone", fp: viewerFP, body: csr})
		if resp.status != http.StatusForbidden {
			t.Errorf("KeyChain caller got %d: %s", resp.status, resp.body)
		}
	}

	// Even a GET from a KeyChain caller is refused before the method is looked at.
	resp := harness.renewAs(&renewCall{viewer: "z-phone", fp: viewerFP, method: http.MethodGet})
	if resp.status != http.StatusForbidden {
		t.Errorf("KeyChain GET got %d", resp.status)
	}

	noIssuance(t, harness, "z-phone", "")
	noIssuance(t, harness, devPhone, phoneFP)
}

func TestRenewRefusals(t *testing.T) {
	cases := []struct {
		name       string
		call       renewCall
		cfg        cfgOpts
		wantStatus int
	}{
		{
			name: "other device's CSR", wantStatus: http.StatusForbidden,
			call: renewCall{viewer: devPhone, body: newDeviceCSR(t, devTablet)},
			cfg:  cfgOpts{devices: bothDevices, api: bothDevices},
		},
		{
			name: "agent CSR", wantStatus: http.StatusForbidden,
			call: renewCall{viewer: devPhone, body: newDeviceCSR(t, "agent-devbox")},
			cfg:  cfgOpts{devices: bothDevices, api: bothDevices},
		},
		{
			name: "disabled device", wantStatus: http.StatusForbidden,
			call: renewCall{viewer: devPhone, body: newDeviceCSR(t, devPhone)},
			cfg:  cfgOpts{devices: bothDevices, api: bothDevices, disabled: []string{devPhone}},
		},
		{
			name: "expired leaf", wantStatus: http.StatusForbidden,
			call: renewCall{
				viewer: devPhone, body: newDeviceCSR(t, devPhone),
				notAfter: time.Now().Add(-time.Minute),
			},
			cfg: cfgOpts{devices: bothDevices, api: bothDevices},
		},
		{
			name: "not in api.identities", wantStatus: http.StatusForbidden,
			call: renewCall{viewer: devPhone, body: newDeviceCSR(t, devPhone)},
			cfg:  cfgOpts{devices: bothDevices, api: []string{devTablet}},
		},
		{
			name: "not in devices", wantStatus: http.StatusForbidden,
			call: renewCall{viewer: devPhone, body: newDeviceCSR(t, devPhone)},
			cfg:  cfgOpts{devices: []string{devTablet}, api: bothDevices},
		},
		{
			name: "no devices at all", wantStatus: http.StatusForbidden,
			call: renewCall{viewer: devPhone, body: newDeviceCSR(t, devPhone)},
			cfg:  cfgOpts{api: bothDevices},
		},
		{
			name: "GET", wantStatus: http.StatusMethodNotAllowed,
			call: renewCall{viewer: devPhone, method: http.MethodGet},
			cfg:  cfgOpts{devices: bothDevices, api: bothDevices},
		},
		{
			name:       "no content type",
			wantStatus: http.StatusUnsupportedMediaType,
			call: renewCall{
				viewer:      devPhone,
				body:        newDeviceCSR(t, devPhone),
				contentType: "text/plain",
			},
			cfg: cfgOpts{devices: bothDevices, api: bothDevices},
		},
		{
			name: "json content type", wantStatus: http.StatusUnsupportedMediaType,
			call: renewCall{
				viewer: devPhone, body: newDeviceCSR(t, devPhone), contentType: "application/json",
			},
			cfg: cfgOpts{devices: bothDevices, api: bothDevices},
		},
		{
			name: "empty body", wantStatus: http.StatusBadRequest,
			call: renewCall{viewer: devPhone},
			cfg:  cfgOpts{devices: bothDevices, api: bothDevices},
		},
		{
			name: "oversized body", wantStatus: http.StatusRequestEntityTooLarge,
			call: renewCall{viewer: devPhone, body: bytes.Repeat([]byte("A"), renewMaxBody+1)},
			cfg:  cfgOpts{devices: bothDevices, api: bothDevices},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			harness := newEnv(t)
			harness.setConfig(tc.cfg)

			fp := harness.newDeviceFP(devPhone)
			tc.call.fp = fp

			resp := harness.renewAs(&tc.call)
			if resp.status != tc.wantStatus {
				t.Fatalf("status %d, want %d: %s", resp.status, tc.wantStatus, resp.body)
			}

			if tc.wantStatus == http.StatusMethodNotAllowed &&
				resp.header.Get("Allow") != http.MethodPost {
				t.Errorf("Allow = %q", resp.header.Get("Allow"))
			}

			noIssuance(t, harness, devPhone, fp)
			noIssuance(t, harness, devTablet, "")
		})
	}
}

func TestRenewRefusesSupersededLeaf(t *testing.T) {
	harness, oldFP := renewEnv(t)
	newFP := harness.newDeviceFP(devPhone)

	resp := harness.renewAs(
		&renewCall{viewer: devPhone, fp: oldFP, body: newDeviceCSR(t, devPhone)},
	)
	if resp.status != http.StatusForbidden {
		t.Fatalf("status %d: %s", resp.status, resp.body)
	}

	noIssuance(t, harness, devPhone, newFP)
}

func TestRenewRefusesBlockedLeaf(t *testing.T) {
	harness, fp := renewEnv(t)
	harness.setConfig(cfgOpts{devices: bothDevices, api: bothDevices, blocked: []string{fp}})

	resp := harness.renewAs(&renewCall{viewer: devPhone, fp: fp, body: newDeviceCSR(t, devPhone)})
	if resp.status != http.StatusForbidden {
		t.Fatalf("status %d: %s", resp.status, resp.body)
	}

	noIssuance(t, harness, devPhone, fp)
}

func TestRenewRejectsBadCSRs(t *testing.T) {
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

	raw := func(signer any, tmpl *x509.CertificateRequest) []byte {
		der, csrErr := x509.CreateCertificateRequest(rand.Reader, tmpl, signer)
		if csrErr != nil {
			t.Fatal(csrErr)
		}

		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
	}

	uri := func(identity string) *url.URL {
		u, parseErr := url.Parse(policy.IdentityURI(identity))
		if parseErr != nil {
			t.Fatal(parseErr)
		}

		return u
	}

	caExt := pkix.Extension{
		Id: asn1.ObjectIdentifier{2, 5, 29, 19}, Value: []byte{0x30, 0x03, 0x01, 0x01, 0xff},
	}

	cases := map[string][]byte{
		"garbage":  []byte("not a CSR"),
		"p384 key": raw(p384, &x509.CertificateRequest{URIs: []*url.URL{uri(devPhone)}}),
		"rsa key":  raw(rsaKey, &x509.CertificateRequest{URIs: []*url.URL{uri(devPhone)}}),
		"dns san": raw(
			key,
			&x509.CertificateRequest{
				URIs:     []*url.URL{uri(devPhone)},
				DNSNames: []string{"a.example"},
			},
		),
		"two uris": raw(
			key,
			&x509.CertificateRequest{URIs: []*url.URL{uri(devPhone), uri(devTablet)}},
		),
		"no uri": raw(key, &x509.CertificateRequest{}),
		"ca request": raw(
			key,
			&x509.CertificateRequest{
				URIs:            []*url.URL{uri(devPhone)},
				ExtraExtensions: []pkix.Extension{caExt},
			},
		),
		"subject": raw(
			key,
			&x509.CertificateRequest{
				URIs:    []*url.URL{uri(devPhone)},
				Subject: pkix.Name{CommonName: "x"},
			},
		),
	}

	for name, csr := range cases {
		t.Run(name, func(t *testing.T) {
			harness, fp := renewEnv(t)

			resp := harness.renewAs(&renewCall{viewer: devPhone, fp: fp, body: csr})
			if resp.status != http.StatusBadRequest {
				t.Fatalf("status %d, want 400: %s", resp.status, resp.body)
			}

			noIssuance(t, harness, devPhone, fp)
		})
	}
}

func TestRenewIssuerFailure(t *testing.T) {
	harness, fp := renewEnv(t)
	harness.fake.Sign = func([]byte) ([]byte, []byte, error) { return nil, nil, errLookupBoom }

	resp := harness.renewAs(&renewCall{viewer: devPhone, fp: fp, body: newDeviceCSR(t, devPhone)})
	if resp.status != http.StatusBadGateway {
		t.Fatalf("status %d", resp.status)
	}

	// The issuer's error text is not passed on.
	if strings.Contains(resp.body, errLookupBoom.Error()) {
		t.Errorf("body leaks the issuer error: %q", resp.body)
	}

	// The device keeps its leaf and can try again.
	if code := harness.deviceViewerStatus(devPhone, fp); code != http.StatusOK {
		t.Errorf("leaf got %d after a failed renewal", code)
	}
}

// A device certificate that could also be a TLS server certificate is never handed out.
func TestRenewRefusesServerAuthLeaf(t *testing.T) {
	harness, fp := renewEnv(t)
	harness.fake.Sign = func(csr []byte) ([]byte, []byte, error) {
		return harness.ca.SignCSRUsages(
			csr,
			time.Hour,
			[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		)
	}

	resp := harness.renewAs(&renewCall{viewer: devPhone, fp: fp, body: newDeviceCSR(t, devPhone)})
	if resp.status != http.StatusBadGateway || strings.Contains(resp.body, "BEGIN CERTIFICATE") {
		t.Fatalf("status %d: %s", resp.status, resp.body)
	}
}

func TestRenewRateLimitPerIdentity(t *testing.T) {
	harness, phoneFP := renewEnv(t)
	tabletFP := harness.newDeviceFP(devTablet)

	// Bad requests count too: they would otherwise be free to send in a loop.
	for i := range renewalMax {
		resp := harness.renewAs(&renewCall{viewer: devPhone, fp: phoneFP, body: []byte("garbage")})
		if resp.status != http.StatusBadRequest {
			t.Fatalf("attempt %d: status %d", i, resp.status)
		}
	}

	resp := harness.renewAs(
		&renewCall{viewer: devPhone, fp: phoneFP, body: newDeviceCSR(t, devPhone)},
	)
	if resp.status != http.StatusTooManyRequests || resp.header.Get("Retry-After") == "" {
		t.Fatalf(
			"over the limit: status %d, Retry-After %q",
			resp.status,
			resp.header.Get("Retry-After"),
		)
	}

	noIssuance(t, harness, devPhone, phoneFP)

	// The other device has its own budget.
	other := harness.renewAs(
		&renewCall{viewer: devTablet, fp: tabletFP, body: newDeviceCSR(t, devTablet)},
	)
	if other.status != http.StatusOK {
		t.Fatalf("tablet got %d: %s", other.status, other.body)
	}

	// The window slides.
	harness.offset.Store(int64(renewalWindow + time.Minute))

	again := harness.renewAs(&renewCall{
		viewer: devPhone, fp: phoneFP, body: newDeviceCSR(t, devPhone),
		notAfter: farFuture.Add(time.Hour),
	})
	if again.status != http.StatusOK {
		t.Fatalf("after the window: status %d: %s", again.status, again.body)
	}
}

func TestRenewOneAtATime(t *testing.T) {
	harness, fp := renewEnv(t)

	started, release := make(chan struct{}), make(chan struct{})

	var once sync.Once

	base := harness.fake.Sign
	harness.fake.Sign = func(csr []byte) ([]byte, []byte, error) {
		once.Do(func() { close(started) })
		<-release

		return base(csr)
	}

	first := make(chan apiResponse, 1)

	go func() {
		first <- harness.renewAs(&renewCall{viewer: devPhone, fp: fp, body: newDeviceCSR(t, devPhone)})
	}()

	<-started

	second := harness.renewAs(&renewCall{viewer: devPhone, fp: fp, body: newDeviceCSR(t, devPhone)})
	if second.status != http.StatusTooManyRequests {
		t.Errorf("concurrent renewal got %d", second.status)
	}

	close(release)

	if got := <-first; got.status != http.StatusOK {
		t.Errorf("first renewal got %d: %s", got.status, got.body)
	}
}

func TestWrongKeyReplayPreservesRenewalBudget(t *testing.T) {
	harness, oldFP := renewEnv(t)

	issued := harness.renewAs(
		&renewCall{viewer: devPhone, fp: oldFP, body: newDeviceCSR(t, devPhone)},
	)
	if issued.status != http.StatusOK {
		t.Fatalf("first renewal got %d: %s", issued.status, issued.body)
	}

	newFP := checkRenewReply(t, harness, issued.body)
	wrong := &renewCall{viewer: devPhone, fp: oldFP, body: newDeviceCSR(t, devPhone)}

	for i := range renewalMax {
		if resp := harness.renewAs(wrong); resp.status != http.StatusForbidden {
			t.Errorf("wrong-key replay %d got %d: %s", i, resp.status, resp.body)
		}
	}

	next := harness.renewAs(
		&renewCall{viewer: devPhone, fp: newFP, body: newDeviceCSR(t, devPhone)},
	)
	if next.status != http.StatusOK {
		t.Errorf("renewal from newest leaf got %d: %s", next.status, next.body)
	}
}

type pausedRenewalIssuer struct {
	issuer.Issuer

	issued  chan string
	release chan struct{}
	csr     []byte
}

func (stub *pausedRenewalIssuer) Issue(ctx context.Context, identity string,
	csr []byte,
) ([]byte, []byte, error) {
	cert, chain, err := stub.Issuer.Issue(ctx, identity, csr)
	if err != nil {
		return nil, nil, fmt.Errorf("test issuance: %w", err)
	}

	if !bytes.Equal(csr, stub.csr) {
		return cert, chain, nil
	}

	leaves, err := pki.ParseCertsPEM(cert)
	if err != nil {
		return nil, nil, fmt.Errorf("test issued leaf: %w", err)
	}

	stub.issued <- pki.Fingerprint(leaves[0])

	<-stub.release

	return cert, chain, nil
}

func startPausedRenewal(
	t *testing.T,
	csr []byte,
) (*env, *pausedRenewalIssuer, string, <-chan apiResponse) {
	t.Helper()

	stub := &pausedRenewalIssuer{
		csr:     csr,
		issued:  make(chan string, 1),
		release: make(chan struct{}),
	}
	harness := newEnvIssuer(t, func(h *env) issuer.Issuer {
		stub.Issuer = h.fake

		return stub
	})
	harness.setConfig(cfgOpts{devices: bothDevices, api: bothDevices})
	oldFP := harness.enrollDevice(devPhone)

	result := make(chan apiResponse, 1)
	go func() {
		result <- harness.renewAs(&renewCall{viewer: devPhone, fp: oldFP, body: csr})
	}()

	return harness, stub, oldFP, result
}

func TestRenewalKeepsNewerEnrollment(t *testing.T) {
	harness, stub, oldFP, result := startPausedRenewal(t, newDeviceCSR(t, devPhone))

	release := sync.OnceFunc(func() { close(stub.release) })
	defer release()

	select {
	case <-stub.issued:
	case <-time.After(5 * time.Second):
		t.Fatal("renewal did not reach the issuer")
	}

	// Model an enrollment issued independently of this hub's lock. A concurrent
	// admission lookup learns the enrolled leaf before renewal returns.
	cert, _, err := harness.fake.Issue(t.Context(), devPhone, newDeviceCSR(t, devPhone))
	if err != nil {
		t.Fatal(err)
	}

	leaves, err := pki.ParseCertsPEM(cert)
	if err != nil {
		t.Fatal(err)
	}

	enrolled := pki.Fingerprint(leaves[0])

	if code := harness.deviceAPIStatus(
		devPhone,
		enrolled,
		"/api/v1/machines",
	); code != http.StatusOK {
		t.Fatalf("newly enrolled leaf got %d", code)
	}

	release()

	if resp := <-result; resp.status != http.StatusConflict {
		t.Errorf("superseded renewal got %d: %s", resp.status, resp.body)
	}

	harness.srv.nmu.Lock()
	defer harness.srv.nmu.Unlock()

	if got := harness.srv.newest[devPhone]; got != enrolled {
		t.Errorf("newest leaf = %q, want enrollment leaf %q", got, enrolled)
	}

	if cached := harness.srv.renewalReplies[devPhone]; cached.leaf != nil {
		t.Errorf("cached rejected renewal of %s", oldFP)
	}
}
