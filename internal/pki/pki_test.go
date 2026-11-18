package pki_test

import (
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

	_, err = pki.ParseKeyPEM([]byte("junk"))
	if err == nil {
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

	_, err = pki.ParseKeyPEM(data)
	if err == nil {
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

	_, err = pki.CreateCSR(key, "bad/name")
	if err == nil {
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
		"cn": rawCSR(
			t,
			key,
			&x509.CertificateRequest{Subject: pkix.Name{CommonName: "x"}, URIs: []*url.URL{good}},
		),
		"org": rawCSR(
			t,
			key,
			&x509.CertificateRequest{
				Subject: pkix.Name{Organization: []string{"x"}},
				URIs:    []*url.URL{good},
			},
		),
		"dns": rawCSR(
			t,
			key,
			&x509.CertificateRequest{DNSNames: []string{"a.example"}, URIs: []*url.URL{good}},
		),
		"ip": rawCSR(
			t,
			key,
			&x509.CertificateRequest{
				IPAddresses: []net.IP{net.IPv4(1, 2, 3, 4)},
				URIs:        []*url.URL{good},
			},
		),
		"email": rawCSR(
			t,
			key,
			&x509.CertificateRequest{EmailAddresses: []string{"a@b.c"}, URIs: []*url.URL{good}},
		),
		"no uri": rawCSR(t, key, &x509.CertificateRequest{}),
		"two uris": rawCSR(
			t,
			key,
			&x509.CertificateRequest{URIs: []*url.URL{good, uri(t, policy.IdentityURI("other"))}},
		),
		"bad uri": rawCSR(
			t,
			key,
			&x509.CertificateRequest{URIs: []*url.URL{uri(t, "https://example.com/x")}},
		),
		"empty id": rawCSR(
			t,
			key,
			&x509.CertificateRequest{URIs: []*url.URL{uri(t, policy.URIPrefix)}},
		),
		"p384":      rawCSR(t, p384, &x509.CertificateRequest{URIs: []*url.URL{good}}),
		"not pem":   []byte("nope"),
		"wrong typ": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1}}),
	}

	for name, csr := range cases {
		t.Run(name, func(t *testing.T) {
			_, _, err := pki.ValidateCSR(csr)
			if err == nil {
				t.Fatal("accepted")
			}
		})
	}

	t.Run("bad signature", func(t *testing.T) {
		csr := rawCSR(t, key, &x509.CertificateRequest{URIs: []*url.URL{good}})
		block, _ := pem.Decode(csr)
		block.Bytes[len(block.Bytes)-1] ^= 0xff

		_, _, err := pki.ValidateCSR(pem.EncodeToMemory(block))
		if err == nil {
			t.Fatal("accepted")
		}
	})
}

func TestValidateDeviceCSR(t *testing.T) {
	key := mustKey(t)
	good := uri(t, policy.IdentityURI("device-z-phone-mesh"))

	csrPEM := rawCSR(t, key, &x509.CertificateRequest{URIs: []*url.URL{good}})

	_, name, err := pki.ValidateCSR(csrPEM)
	if err != nil || name != "device-z-phone-mesh" {
		t.Fatalf("good device CSR: %q %v", name, err)
	}

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// basicConstraints CA:TRUE, extKeyUsage serverAuth and a request for a
	// second SAN-like extension each ride in the extensionRequest attribute.
	caExt := pkix.Extension{
		Id:    asn1.ObjectIdentifier{2, 5, 29, 19},
		Value: []byte{0x30, 0x03, 0x01, 0x01, 0xff},
	}
	ekuExt := pkix.Extension{
		Id:    asn1.ObjectIdentifier{2, 5, 29, 37},
		Value: []byte{0x30, 0x0a, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01},
	}

	cases := map[string][]byte{
		"rsa key":  rawCSR(t, rsaKey, &x509.CertificateRequest{URIs: []*url.URL{good}}),
		"p384 key": rawCSR(t, p384, &x509.CertificateRequest{URIs: []*url.URL{good}}),
		"dns san": rawCSR(
			t,
			key,
			&x509.CertificateRequest{URIs: []*url.URL{good}, DNSNames: []string{"a.example"}},
		),
		"second uri": rawCSR(t, key, &x509.CertificateRequest{
			URIs: []*url.URL{good, uri(t, policy.IdentityURI("device-z-tablet-mesh"))},
		}),
		"agent uri too": rawCSR(t, key, &x509.CertificateRequest{
			URIs: []*url.URL{good, uri(t, policy.IdentityURI("agent-z-mac"))},
		}),
		"ca extension": rawCSR(t, key, &x509.CertificateRequest{
			URIs: []*url.URL{good}, ExtraExtensions: []pkix.Extension{caExt},
		}),
		"eku extension": rawCSR(t, key, &x509.CertificateRequest{
			URIs: []*url.URL{good}, ExtraExtensions: []pkix.Extension{ekuExt},
		}),
		"subject": rawCSR(t, key, &x509.CertificateRequest{
			URIs: []*url.URL{good}, Subject: pkix.Name{CommonName: "device-z-phone-mesh"},
		}),
	}

	for name, csr := range cases {
		t.Run(name, func(t *testing.T) {
			_, _, err := pki.ValidateCSR(csr)
			if err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestCheckDeviceLeaf(t *testing.T) {
	ca := pkitest.NewCA(t, "ca")
	key := mustKey(t)

	csrPEM, err := pki.CreateCSR(key, "device-z-phone-mesh")
	if err != nil {
		t.Fatal(err)
	}

	sign := func(usages []x509.ExtKeyUsage) *x509.Certificate {
		t.Helper()

		certPEM, _, signErr := ca.SignCSRUsages(csrPEM, time.Hour, usages)
		if signErr != nil {
			t.Fatal(signErr)
		}

		certs, parseErr := pki.ParseCertsPEM(certPEM)
		if parseErr != nil {
			t.Fatal(parseErr)
		}

		return certs[0]
	}

	// SignCSR picks client auth alone for a device CSR, as the hub's issuer does.
	signed, _, err := ca.SignCSR(csrPEM, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	certs, err := pki.ParseCertsPEM(signed)
	if err != nil {
		t.Fatal(err)
	}

	err = pki.CheckDeviceLeaf(certs[0])
	if err != nil {
		t.Fatalf("device leaf: %v", err)
	}

	bad := map[string]*x509.Certificate{
		"client and server": sign(
			[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		),
		"server only": sign([]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}),
		"any usage":   sign([]x509.ExtKeyUsage{x509.ExtKeyUsageAny}),
		"no usage":    sign(nil),
		"ca":          ca.Cert,
	}

	for name, leaf := range bad {
		t.Run(name, func(t *testing.T) {
			err := pki.CheckDeviceLeaf(leaf)
			if err == nil {
				t.Fatal("accepted")
			}
		})
	}
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

	_, err = pki.ParseCertsPEM([]byte("x"))
	if err == nil {
		t.Fatal("empty accepted")
	}

	_, err = pki.PoolFromPEM(nil)
	if err == nil {
		t.Fatal("empty pool accepted")
	}

	_, err = pki.CertIdentity(ca.Cert)
	if err == nil {
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

	_, err = pki.VerifyPeer(
		server.Certificate,
		roots,
		x509.ExtKeyUsageServerAuth,
		now,
	)
	if err != nil {
		t.Fatalf("server usage: %v", err)
	}

	_, err = pki.VerifyPeer(
		client.Certificate,
		otherRoots,
		x509.ExtKeyUsageClientAuth,
		now,
	)
	if err == nil {
		t.Fatal("wrong CA accepted")
	}

	_, err = pki.VerifyPeer(
		client.Certificate,
		roots,
		x509.ExtKeyUsageServerAuth,
		now,
	)
	if err == nil {
		t.Fatal("wrong usage accepted")
	}

	_, err = pki.VerifyPeer(
		client.Certificate,
		roots,
		x509.ExtKeyUsageClientAuth,
		now.Add(2*time.Hour),
	)
	if err == nil {
		t.Fatal("expired accepted")
	}

	_, err = pki.VerifyPeer(nil, roots, x509.ExtKeyUsageClientAuth, now)
	if err == nil {
		t.Fatal("empty chain accepted")
	}

	_, err = pki.VerifyPeer(
		[][]byte{{1, 2}},
		roots,
		x509.ExtKeyUsageClientAuth,
		now,
	)
	if err == nil {
		t.Fatal("garbage accepted")
	}
}

func TestWriteFileAtomic(t *testing.T) {
	path := filepath.Join(t.TempDir(), "f")

	for _, content := range []string{"one", "two"} {
		err := pki.WriteFileAtomic(path, []byte(content), 0o600)
		if err != nil {
			t.Fatal(err)
		}

		got, err := os.ReadFile(path)
		if err != nil || string(got) != content {
			t.Fatalf("got %q %v", got, err)
		}
	}

	st, err := os.Stat(path)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v %v", st.Mode(), err)
	}

	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil || len(entries) != 1 {
		t.Fatalf("leftover files: %v %v", entries, err)
	}

	err = pki.WriteFileAtomic(filepath.Join(t.TempDir(), "no", "f"), nil, 0o600)
	if err == nil {
		t.Fatal("missing dir accepted")
	}
}

// issue enrolls key with ca through a CSR and returns cert and chain PEM.
func issue(
	t *testing.T,
	ca *pkitest.CA,
	key *ecdsa.PrivateKey,
	identity string,
) ([]byte, []byte) {
	t.Helper()

	csr, err := pki.CreateCSR(key, identity)
	if err != nil {
		t.Fatal(err)
	}

	certPEM, chainPEM, err := ca.SignCSR(csr, time.Hour)
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
	store := pki.Store{Dir: dir}

	if store.Exists() {
		t.Fatal("exists before save")
	}

	key := mustKey(t)

	err := store.SaveKey(key)
	if err != nil {
		t.Fatal(err)
	}

	if store.Exists() {
		t.Fatal("exists without cert")
	}

	certPEM, chain := issue(t, ca, key, "agent-devbox")

	err = store.SaveCert(certPEM, chain)
	if err != nil {
		t.Fatal(err)
	}

	if !store.Exists() {
		t.Fatal("not exists")
	}

	tc, leaf, err := store.Load()
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

	err = store.SaveCert(otherCert, otherChain)
	if !errors.Is(err, pki.ErrKeyMismatch) {
		t.Fatalf("err = %v", err)
	}
}

func TestEnsureDirNarrows(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "id")

	err := os.Mkdir(dir, 0o755) //nolint:gosec // test needs wide mode
	if err != nil {
		t.Fatal(err)
	}

	err = (pki.Store{Dir: dir}).EnsureDir()
	if err != nil {
		t.Fatal(err)
	}

	if m := mode(t, dir); m != 0o700 {
		t.Fatalf("mode %o", m)
	}
}

func saved(t *testing.T) (pki.Store, *pkitest.CA, *ecdsa.PrivateKey) {
	t.Helper()

	ca := pkitest.NewCA(t, "ca")
	store := pki.Store{Dir: filepath.Join(t.TempDir(), "id")}
	key := mustKey(t)

	err := store.SaveKey(key)
	if err != nil {
		t.Fatal(err)
	}

	c, ch := issue(t, ca, key, "agent-a")

	err = store.SaveCert(c, ch)
	if err != nil {
		t.Fatal(err)
	}

	return store, ca, key
}

func TestPromoteNext(t *testing.T) {
	store, ca, oldKey := saved(t)
	newKey := mustKey(t)
	c, ch := issue(t, ca, newKey, "agent-a")

	err := store.SaveNext(newKey, c, ch)
	if err != nil {
		t.Fatal(err)
	}

	if m := mode(t, filepath.Join(store.Dir, "next-key.pem")); m != 0o600 {
		t.Fatalf("next key mode %o", m)
	}

	tc, _, err := store.LoadNext()
	if err != nil {
		t.Fatal(err)
	}

	if !sameKey(tc.PrivateKey, newKey) {
		t.Fatal("wrong next key")
	}

	// Current is still the old pair.
	cur, _, err := store.Load()
	if err != nil ||
		!sameKey(cur.PrivateKey, oldKey) {
		t.Fatalf("current changed: %v", err)
	}

	err = store.PromoteNext()
	if err != nil {
		t.Fatal(err)
	}

	cur, _, err = store.Load()
	if err != nil ||
		!sameKey(cur.PrivateKey, newKey) {
		t.Fatalf("not promoted: %v", err)
	}

	_, _, err = store.LoadNext()
	if err == nil {
		t.Fatal("next still present")
	}
}

func TestPromoteCrashRecovery(t *testing.T) {
	store, ca, _ := saved(t)
	newKey := mustKey(t)
	c, ch := issue(t, ca, newKey, "agent-a")

	err := store.SaveNext(newKey, c, ch)
	if err != nil {
		t.Fatal(err)
	}

	// Simulate a crash after the key rename but before the cert rename.
	err = os.Rename(
		filepath.Join(store.Dir, "next-key.pem"),
		filepath.Join(store.Dir, "key.pem"),
	)
	if err != nil {
		t.Fatal(err)
	}

	tc, _, err := store.Load()
	if err != nil {
		t.Fatalf("no recovery: %v", err)
	}

	if !sameKey(tc.PrivateKey, newKey) {
		t.Fatal("recovered wrong key")
	}

	_, err = os.Stat(filepath.Join(store.Dir, "next-cert.pem"))
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("next-cert remains: %v", err)
	}
}

func TestLoadMismatchWithoutNext(t *testing.T) {
	store, _, _ := saved(t)

	err := store.SaveKey(mustKey(t))
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = store.Load()
	if !errors.Is(err, pki.ErrKeyMismatch) {
		t.Fatalf("err = %v", err)
	}
}

func TestSaveNextMismatchAndDiscard(t *testing.T) {
	store, ca, _ := saved(t)
	crt, ch := issue(t, ca, mustKey(t), "agent-a")

	err := store.SaveNext(mustKey(t), crt, ch)
	if !errors.Is(err, pki.ErrKeyMismatch) {
		t.Fatalf("err = %v", err)
	}

	k := mustKey(t)
	crt, ch = issue(t, ca, k, "agent-a")

	err = store.SaveNext(k, crt, ch)
	if err != nil {
		t.Fatal(err)
	}

	err = store.DiscardNext()
	if err != nil {
		t.Fatal(err)
	}

	err = store.DiscardNext()
	if err != nil {
		t.Fatalf("second discard: %v", err)
	}

	err = store.PromoteNext()
	if err == nil {
		t.Fatal("promote without next succeeded")
	}

	if !store.Exists() {
		t.Fatal("current lost")
	}
}

// sameKey reports whether priv is key.
func sameKey(priv any, key *ecdsa.PrivateKey) bool {
	got, ok := priv.(*ecdsa.PrivateKey)

	return ok && got.Equal(key)
}
