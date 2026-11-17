// Package pki handles identity keys, CSRs, certificate verification and the
// on-disk identity store.
package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/zekihan/t3-mesh/internal/policy"
)

var (
	errNoPrivateKeyBlock = errors.New("pki: no PRIVATE KEY PEM block")
	errKeyNotECDSA       = errors.New("pki: key is not ECDSA")
	errKeyNotP256        = errors.New("pki: key is not P-256")
	errNoCSRBlock        = errors.New("pki: no CERTIFICATE REQUEST PEM block")
	errCSRKeyNotP256     = errors.New("pki: CSR key is not ECDSA P-256")
	errCSRSubject        = errors.New("pki: CSR has subject attributes")
	errCSRSANs           = errors.New("pki: CSR has DNS, IP or email SANs")
	errURISANs           = errors.New("URI SANs, want 1")
	errNoCertBlocks      = errors.New("pki: no CERTIFICATE PEM blocks")
	errNoPeerCert        = errors.New("pki: no peer certificate")
)

// GenerateKey returns a new P-256 private key.
func GenerateKey() (*ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("pki: generate key: %w", err)
	}

	return key, nil
}

// EncodeKeyPEM encodes key as a PKCS#8 "PRIVATE KEY" PEM block.
func EncodeKeyPEM(key *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("pki: marshal key: %w", err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// ParseKeyPEM parses a PKCS#8 PEM P-256 private key.
func ParseKeyPEM(data []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, errNoPrivateKeyBlock
	}

	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("pki: parse key: %w", err)
	}

	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errKeyNotECDSA
	}

	if key.Curve != elliptic.P256() {
		return nil, errKeyNotP256
	}

	return key, nil
}

// CreateCSR returns a PEM CSR carrying only the identity URI SAN.
func CreateCSR(key *ecdsa.PrivateKey, identity string) ([]byte, error) {
	uriStr := policy.IdentityURI(identity)

	_, err := policy.IdentityFromURI(uriStr)
	if err != nil {
		return nil, fmt.Errorf("pki: %w", err)
	}

	uri, err := url.Parse(uriStr)
	if err != nil {
		return nil, fmt.Errorf("pki: parse identity URI: %w", err)
	}

	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		URIs: []*url.URL{uri},
	}, key)
	if err != nil {
		return nil, fmt.Errorf("pki: create CSR: %w", err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}

// ValidateCSR checks the CSR signature, that the key is ECDSA P-256, that it
// has exactly one URI SAN with the clients prefix, an empty subject and no
// DNS, IP or email SANs. It returns the parsed CSR and the identity name.
func ValidateCSR(csrPEM []byte) (*x509.CertificateRequest, string, error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, "", errNoCSRBlock
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, "", fmt.Errorf("pki: parse CSR: %w", err)
	}

	err = csr.CheckSignature()
	if err != nil {
		return nil, "", fmt.Errorf("pki: CSR signature: %w", err)
	}

	pub, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, "", errCSRKeyNotP256
	}

	if len(csr.Subject.Names) > 0 || len(csr.Subject.ExtraNames) > 0 {
		return nil, "", errCSRSubject
	}

	if len(csr.DNSNames) > 0 || len(csr.IPAddresses) > 0 || len(csr.EmailAddresses) > 0 {
		return nil, "", errCSRSANs
	}

	if len(csr.URIs) != 1 {
		return nil, "", fmt.Errorf("pki: CSR has %d %w", len(csr.URIs), errURISANs)
	}

	name, err := policy.IdentityFromURI(csr.URIs[0].String())
	if err != nil {
		return nil, "", fmt.Errorf("pki: CSR: %w", err)
	}

	return csr, name, nil
}

// Fingerprint returns the lowercase hex SHA-256 of the certificate DER.
func Fingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)

	return hex.EncodeToString(sum[:])
}

// CertIdentity returns the identity name of a certificate with exactly one URI
// SAN.
func CertIdentity(cert *x509.Certificate) (string, error) {
	if len(cert.URIs) != 1 {
		return "", fmt.Errorf("pki: certificate has %d %w", len(cert.URIs), errURISANs)
	}

	name, err := policy.IdentityFromURI(cert.URIs[0].String())
	if err != nil {
		return "", fmt.Errorf("pki: %w", err)
	}

	return name, nil
}

// ParseCertsPEM parses every CERTIFICATE block; it fails when there is none.
func ParseCertsPEM(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate

	for {
		var block *pem.Block

		block, data = pem.Decode(data)
		if block == nil {
			break
		}

		if block.Type != "CERTIFICATE" {
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("pki: parse certificate: %w", err)
		}

		certs = append(certs, cert)
	}

	if len(certs) == 0 {
		return nil, errNoCertBlocks
	}

	return certs, nil
}

// PoolFromPEM returns a pool of every certificate in data.
func PoolFromPEM(data []byte) (*x509.CertPool, error) {
	certs, err := ParseCertsPEM(data)
	if err != nil {
		return nil, err
	}

	pool := x509.NewCertPool()
	for _, c := range certs {
		pool.AddCert(c)
	}

	return pool, nil
}

// VerifyPeer verifies a TLS peer chain (leaf first) against roots for usage at
// now and returns the leaf.
func VerifyPeer(
	rawCerts [][]byte,
	roots *x509.CertPool,
	usage x509.ExtKeyUsage,
	now time.Time,
) (*x509.Certificate, error) {
	if len(rawCerts) == 0 {
		return nil, errNoPeerCert
	}

	certs := make([]*x509.Certificate, 0, len(rawCerts))

	for _, raw := range rawCerts {
		c, err := x509.ParseCertificate(raw)
		if err != nil {
			return nil, fmt.Errorf("pki: parse peer certificate: %w", err)
		}

		certs = append(certs, c)
	}

	inter := x509.NewCertPool()
	for _, c := range certs[1:] {
		inter.AddCert(c)
	}

	_, err := certs[0].Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inter,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{usage},
	})
	if err != nil {
		return nil, fmt.Errorf("pki: verify peer: %w", err)
	}

	return certs[0], nil
}

// WriteFileAtomic writes data to a temp file in the same directory, fsyncs,
// chmods, renames over path and fsyncs the directory.
func WriteFileAtomic(path string, data []byte, mode os.FileMode) (err error) {
	dir := filepath.Dir(path)

	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("pki: create temp file: %w", err)
	}

	defer func() {
		if err != nil {
			_ = tmp.Close()
			_ = os.Remove(tmp.Name())
		}
	}()

	err = tmp.Chmod(mode)
	if err != nil {
		return fmt.Errorf("pki: chmod temp file: %w", err)
	}

	_, err = tmp.Write(data)
	if err != nil {
		return fmt.Errorf("pki: write temp file: %w", err)
	}

	err = tmp.Sync()
	if err != nil {
		return fmt.Errorf("pki: sync temp file: %w", err)
	}

	err = tmp.Close()
	if err != nil {
		return fmt.Errorf("pki: close temp file: %w", err)
	}

	err = os.Rename(tmp.Name(), path)
	if err != nil {
		return fmt.Errorf("pki: rename temp file: %w", err)
	}

	return syncDir(dir)
}

func syncDir(dir string) error {
	dirFile, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("pki: open dir: %w", err)
	}

	defer func() { _ = dirFile.Close() }()

	err = dirFile.Sync()
	if err != nil {
		return fmt.Errorf("pki: sync dir: %w", err)
	}

	return nil
}
