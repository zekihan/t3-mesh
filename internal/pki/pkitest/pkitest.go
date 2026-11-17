// Package pkitest provides a throwaway CA for tests.
package pkitest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/zekihan/t3-mesh/internal/policy"
)

const (
	serialBits = 120
)

var errNoCSRBlock = errors.New("pkitest: no PEM block in CSR")

// CA is a self-signed test certificate authority.
type CA struct {
	Cert    *x509.Certificate
	Key     *ecdsa.PrivateKey
	CertPEM []byte
}

func serial(tb testing.TB) *big.Int {
	tb.Helper()

	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), serialBits))
	if err != nil {
		tb.Fatalf("serial: %v", err)
	}

	return n
}

func genKey(tb testing.TB) *ecdsa.PrivateKey {
	tb.Helper()

	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatalf("generate key: %v", err)
	}

	return k
}

// NewCA creates a CA with the given common name.
func NewCA(tb testing.TB, name string) *CA {
	tb.Helper()

	key := genKey(tb)
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial(tb),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		tb.Fatalf("create CA: %v", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		tb.Fatalf("parse CA: %v", err)
	}

	return &CA{
		Cert:    cert,
		Key:     key,
		CertPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
	}
}

func leafPair(tb testing.TB, der []byte, key *ecdsa.PrivateKey) (tls.Certificate, []byte, []byte) {
	tb.Helper()

	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		tb.Fatalf("parse leaf: %v", err)
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		tb.Fatalf("marshal key: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, certPEM, keyPEM
}

// IssueIdentity issues a leaf with one URI SAN for identity, valid from an
// hour ago until notAfter.
func (ca *CA) IssueIdentity(
	tb testing.TB,
	identity string,
	server bool,
	notAfter time.Time,
) (tls.Certificate, []byte, []byte) {
	tb.Helper()

	uri, err := url.Parse(policy.IdentityURI(identity))
	if err != nil {
		tb.Fatalf("parse identity URI: %v", err)
	}

	usage := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	if server {
		usage = append(usage, x509.ExtKeyUsageServerAuth)
	}

	key := genKey(tb)
	der := ca.issue(tb, &x509.Certificate{
		SerialNumber: serial(tb),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  usage,
		URIs:         []*url.URL{uri},
	}, &key.PublicKey)

	return leafPair(tb, der, key)
}

// IssueServer issues a serverAuth leaf for the given DNS names and IPs.
func (ca *CA) IssueServer(tb testing.TB, hosts ...string) tls.Certificate {
	tb.Helper()

	tmpl := &x509.Certificate{
		SerialNumber: serial(tb),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}

	key := genKey(tb)
	tc, _, _ := leafPair(tb, ca.issue(tb, tmpl, &key.PublicKey), key)

	return tc
}

// SignCSR signs a CSR, keeping the SANs it carries, with clientAuth and
// serverAuth for d. The chain is the CA certificate.
func (ca *CA) SignCSR(csrPEM []byte, dur time.Duration) ([]byte, []byte, error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return nil, nil, errNoCSRBlock
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("pkitest: parse CSR: %w", err)
	}

	err = csr.CheckSignature()
	if err != nil {
		return nil, nil, fmt.Errorf("pkitest: CSR signature: %w", err)
	}

	sn, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), serialBits))
	if err != nil {
		return nil, nil, fmt.Errorf("pkitest: serial: %w", err)
	}

	now := time.Now()

	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber:   sn,
		Subject:        csr.Subject,
		NotBefore:      now.Add(-time.Minute),
		NotAfter:       now.Add(dur),
		KeyUsage:       x509.KeyUsageDigitalSignature,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		URIs:           csr.URIs,
		DNSNames:       csr.DNSNames,
		IPAddresses:    csr.IPAddresses,
		EmailAddresses: csr.EmailAddresses,
	}, ca.Cert, csr.PublicKey, ca.Key)
	if err != nil {
		return nil, nil, fmt.Errorf("pkitest: sign: %w", err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), ca.CertPEM, nil
}

func (ca *CA) issue(tb testing.TB, tmpl *x509.Certificate, pub *ecdsa.PublicKey) []byte {
	tb.Helper()

	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, pub, ca.Key)
	if err != nil {
		tb.Fatalf("issue certificate: %v", err)
	}

	return der
}
