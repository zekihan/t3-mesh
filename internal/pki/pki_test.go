package pki_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/zekihan/t3-mesh/internal/pki"
	"github.com/zekihan/t3-mesh/internal/pki/pkitest"
	"github.com/zekihan/t3-mesh/internal/policy"
)

func mustKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()

	k, err := pki.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	return k
}

func rawCSR(t *testing.T, key any, tmpl *x509.CertificateRequest) []byte {
	t.Helper()

	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatal(err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

func uri(t *testing.T, s string) *url.URL {
	t.Helper()

	u, err := url.Parse(s)
	if err != nil {
		t.Fatal(err)
	}

	return u
}

func TestKeyRoundTrip(t *testing.T) {
	key := mustKey(t)

	data, err := pki.EncodeKeyPEM(key)
	if err != nil {
		t.Fatal(err)
	}

	got, err := pki.ParseKeyPEM(data)
	if err != nil {
		t.Fatal(err)
	}

	if !got.Equal(key) {
		t.Fatal("key changed in round trip")
	}

	if _, err := pki.ParseKeyPEM([]byte("junk")); err == nil {
		t.Fatal("junk accepted")
	}

	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	data, err = pki.EncodeKeyPEM(p384)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := pki.ParseKeyPEM(data); err == nil {
		t.Fatal("P-384 key accepted")
	}
}

func TestCSRRoundTrip(t *testing.T) {
	key := mustKey(t)

	csrPEM, err := pki.CreateCSR(key, "agent-devbox")
	if err != nil {
		t.Fatal(err)
	}

	csr, name, err := pki.ValidateCSR(csrPEM)
	if err != nil {
		t.Fatal(err)
	}

	if name != "agent-devbox" {
		t.Fatalf("name = %q", name)
	}

	if csr.Subject.String() != "" {
		t.Fatalf("subject = %q", csr.Subject)
	}

	if _, err := pki.CreateCSR(key, "bad/name"); err == nil {
		t.Fatal("bad identity accepted")
	}
}

func TestValidateCSRRejects(t *testing.T) {
	key := mustKey(t)
	good := uri(t, policy.IdentityURI("agent-x"))
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	cases := map[string][]byte{
		"cn":        rawCSR(t, key, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "x"}, URIs: []*url.URL{good}}),
		"org":       rawCSR(t, key, &x509.CertificateRequest{Subject: pkix.Name{Organization: []string{"x"}}, URIs: []*url.URL{good}}),
		"dns":       rawCSR(t, key, &x509.CertificateRequest{DNSNames: []string{"a.example"}, URIs: []*url.URL{good}}),
		"ip":        rawCSR(t, key, &x509.CertificateRequest{IPAddresses: []net.IP{net.IPv4(1, 2, 3, 4)}, URIs: []*url.URL{good}}),
		"email":     rawCSR(t, key, &x509.CertificateRequest{EmailAddresses: []string{"a@b.c"}, URIs: []*url.URL{good}}),
		"no uri":    rawCSR(t, key, &x509.CertificateRequest{}),
		"two uris":  rawCSR(t, key, &x509.CertificateRequest{URIs: []*url.URL{good, uri(t, policy.IdentityURI("other"))}}),
		"bad uri":   rawCSR(t, key, &x509.CertificateRequest{URIs: []*url.URL{uri(t, "https://example.com/x")}}),
		"empty id":  rawCSR(t, key, &x509.CertificateRequest{URIs: []*url.URL{uri(t, policy.URIPrefix)}}),
		"p384":      rawCSR(t, p384, &x509.CertificateRequest{URIs: []*url.URL{good}}),
		"not pem":   []byte("nope"),
		"wrong typ": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1}}),
	}

	for name, csr := range cases {
		t.Run(name, func(t *testing.T) {
			if _, _, err := pki.ValidateCSR(csr); err == nil {
				t.Fatal("accepted")
			}
		})
	}

	t.Run("bad signature", func(t *testing.T) {
		csr := rawCSR(t, key, &x509.CertificateRequest{URIs: []*url.URL{good}})
		block, _ := pem.Decode(csr)
		block.Bytes[len(block.Bytes)-1] ^= 0xff

		if _, _, err := pki.ValidateCSR(pem.EncodeToMemory(block)); err == nil {
			t.Fatal("accepted")
		}
	})
}

func TestCertHelpers(t *testing.T) {
	ca := pkitest.NewCA(t, "ca")
	tc, certPEM, _ := ca.IssueIdentity(t, "z-arch", false, time.Now().Add(time.Hour))

	certs, err := pki.ParseCertsPEM(certPEM)
	if err != nil || len(certs) != 1 {
		t.Fatalf("parse: %v %d", err, len(certs))
	}

	id, err := pki.CertIdentity(certs[0])
	if err != nil || id != "z-arch" {
		t.Fatalf("identity %q %v", id, err)
	}

	fp := pki.Fingerprint(tc.Leaf)
	if len(fp) != 64 || fp != pki.Fingerprint(certs[0]) {
		t.Fatalf("fingerprint %q", fp)
	}

	if _, err := pki.ParseCertsPEM([]byte("x")); err == nil {
		t.Fatal("empty accepted")
	}

	if _, err := pki.PoolFromPEM(nil); err == nil {
		t.Fatal("empty pool accepted")
	}

	if _, err := pki.CertIdentity(ca.Cert); err == nil {
		t.Fatal("CA has no identity")
	}
}

func TestVerifyPeer(t *testing.T) {
	ca := pkitest.NewCA(t, "ca")
	other := pkitest.NewCA(t, "other")
	roots, err := pki.PoolFromPEM(ca.CertPEM)
	if err != nil {
		t.Fatal(err)
	}

	otherRoots, err := pki.PoolFromPEM(other.CertPEM)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	client, _, _ := ca.IssueIdentity(t, "z-mac", false, now.Add(time.Hour))
	server, _, _ := ca.IssueIdentity(t, "agent-a", true, now.Add(time.Hour))

	leaf, err := pki.VerifyPeer(client.Certificate, roots, x509.ExtKeyUsageClientAuth, now)
	if err != nil || leaf.URIs[0].String() != policy.IdentityURI("z-mac") {
		t.Fatalf("verify: %v", err)
	}

	if _, err := pki.VerifyPeer(server.Certificate, roots, x509.ExtKeyUsageServerAuth, now); err != nil {
		t.Fatalf("server usage: %v", err)
	}

	if _, err := pki.VerifyPeer(client.Certificate, otherRoots, x509.ExtKeyUsageClientAuth, now); err == nil {
		t.Fatal("wrong CA accepted")
	}

	if _, err := pki.VerifyPeer(client.Certificate, roots, x509.ExtKeyUsageServerAuth, now); err == nil {
		t.Fatal("wrong usage accepted")
	}

	if _, err := pki.VerifyPeer(client.Certificate, roots, x509.ExtKeyUsageClientAuth, now.Add(2*time.Hour)); err == nil {
		t.Fatal("expired accepted")
	}

	if _, err := pki.VerifyPeer(nil, roots, x509.ExtKeyUsageClientAuth, now); err == nil {
		t.Fatal("empty chain accepted")
	}

	if _, err := pki.VerifyPeer([][]byte{{1, 2}}, roots, x509.ExtKeyUsageClientAuth, now); err == nil {
		t.Fatal("garbage accepted")
	}
}

func TestWriteFileAtomic(t *testing.T) {
	p := filepath.Join(t.TempDir(), "f")

	for _, content := range []string{"one", "two"} {
		if err := pki.WriteFileAtomic(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}

		got, err := os.ReadFile(p)
		if err != nil || string(got) != content {
			t.Fatalf("got %q %v", got, err)
		}
	}

	st, err := os.Stat(p)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v %v", st.Mode(), err)
	}

	entries, err := os.ReadDir(filepath.Dir(p))
	if err != nil || len(entries) != 1 {
		t.Fatalf("leftover files: %v %v", entries, err)
	}

	if err := pki.WriteFileAtomic(filepath.Join(t.TempDir(), "no", "f"), nil, 0o600); err == nil {
		t.Fatal("missing dir accepted")
	}
}

// issue enrolls key with ca through a CSR and returns cert and chain PEM.
func issue(t *testing.T, ca *pkitest.CA, key *ecdsa.PrivateKey, identity string) (certPEM, chainPEM []byte) {
	t.Helper()

	csr, err := pki.CreateCSR(key, identity)
	if err != nil {
		t.Fatal(err)
	}

	certPEM, chainPEM, err = ca.SignCSR(csr, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	return certPEM, chainPEM
}

func mode(t *testing.T, p string) os.FileMode {
	t.Helper()

	st, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}

	return st.Mode().Perm()
}

func TestStoreRoundTrip(t *testing.T) {
	ca := pkitest.NewCA(t, "ca")
	dir := filepath.Join(t.TempDir(), "id")
	s := pki.Store{Dir: dir}

	if s.Exists() {
		t.Fatal("exists before save")
	}

	key := mustKey(t)
	if err := s.SaveKey(key); err != nil {
		t.Fatal(err)
	}

	if s.Exists() {
		t.Fatal("exists without cert")
	}

	certPEM, chain := issue(t, ca, key, "agent-devbox")
	if err := s.SaveCert(certPEM, chain); err != nil {
		t.Fatal(err)
	}

	if !s.Exists() {
		t.Fatal("not exists")
	}

	tc, leaf, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}

	if tc.Leaf != leaf || len(tc.Certificate) != 2 {
		t.Fatalf("leaf=%v chain=%d", tc.Leaf == leaf, len(tc.Certificate))
	}

	if id, _ := pki.CertIdentity(leaf); id != "agent-devbox" {
		t.Fatalf("id %q", id)
	}

	if m := mode(t, dir); m != 0o700 {
		t.Fatalf("dir mode %o", m)
	}

	if m := mode(t, filepath.Join(dir, "key.pem")); m != 0o600 {
		t.Fatalf("key mode %o", m)
	}

	if m := mode(t, filepath.Join(dir, "cert.pem")); m != 0o644 {
		t.Fatalf("cert mode %o", m)
	}

	// A cert for another key is refused.
	otherCert, otherChain := issue(t, ca, mustKey(t), "agent-devbox")
	if err := s.SaveCert(otherCert, otherChain); !errors.Is(err, pki.ErrKeyMismatch) {
		t.Fatalf("err = %v", err)
	}
}

func TestEnsureDirNarrows(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "id")
	if err := os.Mkdir(dir, 0o755); err != nil { //nolint:gosec // test needs wide mode
		t.Fatal(err)
	}

	if err := (pki.Store{Dir: dir}).EnsureDir(); err != nil {
		t.Fatal(err)
	}

	if m := mode(t, dir); m != 0o700 {
		t.Fatalf("mode %o", m)
	}
}

func saved(t *testing.T) (pki.Store, *pkitest.CA, *ecdsa.PrivateKey) {
	t.Helper()

	ca := pkitest.NewCA(t, "ca")
	s := pki.Store{Dir: filepath.Join(t.TempDir(), "id")}
	key := mustKey(t)

	if err := s.SaveKey(key); err != nil {
		t.Fatal(err)
	}

	c, ch := issue(t, ca, key, "agent-a")
	if err := s.SaveCert(c, ch); err != nil {
		t.Fatal(err)
	}

	return s, ca, key
}

func TestPromoteNext(t *testing.T) {
	s, ca, oldKey := saved(t)
	newKey := mustKey(t)
	c, ch := issue(t, ca, newKey, "agent-a")

	if err := s.SaveNext(newKey, c, ch); err != nil {
		t.Fatal(err)
	}

	if m := mode(t, filepath.Join(s.Dir, "next-key.pem")); m != 0o600 {
		t.Fatalf("next key mode %o", m)
	}

	tc, _, err := s.LoadNext()
	if err != nil {
		t.Fatal(err)
	}

	if !tc.PrivateKey.(*ecdsa.PrivateKey).Equal(newKey) { //nolint:forcetypeassert
		t.Fatal("wrong next key")
	}

	// Current is still the old pair.
	cur, _, err := s.Load()
	if err != nil || !cur.PrivateKey.(*ecdsa.PrivateKey).Equal(oldKey) { //nolint:forcetypeassert
		t.Fatalf("current changed: %v", err)
	}

	if err := s.PromoteNext(); err != nil {
		t.Fatal(err)
	}

	cur, _, err = s.Load()
	if err != nil || !cur.PrivateKey.(*ecdsa.PrivateKey).Equal(newKey) { //nolint:forcetypeassert
		t.Fatalf("not promoted: %v", err)
	}

	if _, _, err := s.LoadNext(); err == nil {
		t.Fatal("next still present")
	}
}

func TestPromoteCrashRecovery(t *testing.T) {
	s, ca, _ := saved(t)
	newKey := mustKey(t)
	c, ch := issue(t, ca, newKey, "agent-a")

	if err := s.SaveNext(newKey, c, ch); err != nil {
		t.Fatal(err)
	}

	// Simulate a crash after the key rename but before the cert rename.
	if err := os.Rename(filepath.Join(s.Dir, "next-key.pem"), filepath.Join(s.Dir, "key.pem")); err != nil {
		t.Fatal(err)
	}

	tc, _, err := s.Load()
	if err != nil {
		t.Fatalf("no recovery: %v", err)
	}

	if !tc.PrivateKey.(*ecdsa.PrivateKey).Equal(newKey) { //nolint:forcetypeassert
		t.Fatal("recovered wrong key")
	}

	if _, err := os.Stat(filepath.Join(s.Dir, "next-cert.pem")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("next-cert remains: %v", err)
	}
}

func TestLoadMismatchWithoutNext(t *testing.T) {
	s, _, _ := saved(t)

	if err := s.SaveKey(mustKey(t)); err != nil {
		t.Fatal(err)
	}

	if _, _, err := s.Load(); !errors.Is(err, pki.ErrKeyMismatch) {
		t.Fatalf("err = %v", err)
	}
}

func TestSaveNextMismatchAndDiscard(t *testing.T) {
	s, ca, _ := saved(t)
	c, ch := issue(t, ca, mustKey(t), "agent-a")

	if err := s.SaveNext(mustKey(t), c, ch); !errors.Is(err, pki.ErrKeyMismatch) {
		t.Fatalf("err = %v", err)
	}

	k := mustKey(t)
	c, ch = issue(t, ca, k, "agent-a")

	if err := s.SaveNext(k, c, ch); err != nil {
		t.Fatal(err)
	}

	if err := s.DiscardNext(); err != nil {
		t.Fatal(err)
	}

	if err := s.DiscardNext(); err != nil {
		t.Fatalf("second discard: %v", err)
	}

	if err := s.PromoteNext(); err == nil {
		t.Fatal("promote without next succeeded")
	}

	if !s.Exists() {
		t.Fatal("current lost")
	}
}
