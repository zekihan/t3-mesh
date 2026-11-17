package pki

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

const (
	keyFile      = "key.pem"
	certFile     = "cert.pem"
	nextKeyFile  = "next-key.pem"
	nextCertFile = "next-cert.pem"
)

// ErrKeyMismatch means a certificate does not match its private key.
var ErrKeyMismatch = errors.New("pki: certificate does not match key")

// Store is an identity directory holding the key and certificate chain, plus
// the next pair during renewal.
//
// PromoteNext renames next-key.pem over key.pem and then next-cert.pem over
// cert.pem. A crash between the two renames leaves a new key with the old
// certificate; the pair is never loadable as mismatched. Load detects the
// mismatch and, when next-cert.pem matches key.pem, finishes the promotion by
// renaming it into place. A crash before the first rename leaves the old pair
// intact with next-* still present.
type Store struct{ Dir string }

func (s Store) path(name string) string { return filepath.Join(s.Dir, name) }

// EnsureDir creates the directory with mode 0700 and narrows a wider mode.
func (s Store) EnsureDir() error {
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return fmt.Errorf("pki: create identity dir: %w", err)
	}

	if err := os.Chmod(s.Dir, 0o700); err != nil { //nolint:gosec // directory, 0700 is intended
		return fmt.Errorf("pki: chmod identity dir: %w", err)
	}

	return nil
}

// Exists reports whether key.pem and cert.pem are both present.
func (s Store) Exists() bool {
	return fileExists(s.path(keyFile)) && fileExists(s.path(certFile))
}

func fileExists(p string) bool {
	_, err := os.Stat(p)

	return err == nil
}

// SaveKey writes key.pem.
func (s Store) SaveKey(key *ecdsa.PrivateKey) error {
	return s.writeKey(keyFile, key)
}

func (s Store) writeKey(name string, key *ecdsa.PrivateKey) error {
	if err := s.EnsureDir(); err != nil {
		return err
	}

	data, err := EncodeKeyPEM(key)
	if err != nil {
		return err
	}

	return WriteFileAtomic(s.path(name), data, 0o600)
}

// SaveCert writes cert.pem as certPEM followed by chainPEM after checking that
// the leaf matches key.pem.
func (s Store) SaveCert(certPEM, chainPEM []byte) error {
	key, err := s.readKey(keyFile)
	if err != nil {
		return err
	}

	return s.writeCert(certFile, key, certPEM, chainPEM)
}

func (s Store) writeCert(name string, key *ecdsa.PrivateKey, certPEM, chainPEM []byte) error {
	bundle := joinPEM(certPEM, chainPEM)

	certs, err := ParseCertsPEM(bundle)
	if err != nil {
		return err
	}

	if !matches(certs[0], key) {
		return ErrKeyMismatch
	}

	if err := s.EnsureDir(); err != nil {
		return err
	}

	return WriteFileAtomic(s.path(name), bundle, 0o644)
}

// SaveNext writes next-key.pem and next-cert.pem after checking they match.
func (s Store) SaveNext(key *ecdsa.PrivateKey, certPEM, chainPEM []byte) error {
	bundle := joinPEM(certPEM, chainPEM)

	certs, err := ParseCertsPEM(bundle)
	if err != nil {
		return err
	}

	if !matches(certs[0], key) {
		return ErrKeyMismatch
	}

	if err := s.writeKey(nextKeyFile, key); err != nil {
		return err
	}

	return s.writeCert(nextCertFile, key, certPEM, chainPEM)
}

func joinPEM(a, b []byte) []byte {
	out := bytes.Clone(a)
	if len(out) > 0 && out[len(out)-1] != '\n' {
		out = append(out, '\n')
	}

	return append(out, b...)
}

func matches(cert *x509.Certificate, key *ecdsa.PrivateKey) bool {
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)

	return ok && pub.Equal(key.Public())
}

func (s Store) readKey(name string) (*ecdsa.PrivateKey, error) {
	data, err := os.ReadFile(s.path(name))
	if err != nil {
		return nil, fmt.Errorf("pki: read %s: %w", name, err)
	}

	return ParseKeyPEM(data)
}

func (s Store) loadPair(keyName, certName string) (tls.Certificate, *x509.Certificate, error) {
	key, err := s.readKey(keyName)
	if err != nil {
		return tls.Certificate{}, nil, err
	}

	data, err := os.ReadFile(s.path(certName))
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("pki: read %s: %w", certName, err)
	}

	certs, err := ParseCertsPEM(data)
	if err != nil {
		return tls.Certificate{}, nil, err
	}

	if !matches(certs[0], key) {
		return tls.Certificate{}, nil, ErrKeyMismatch
	}

	chain := make([][]byte, len(certs))
	for i, c := range certs {
		chain[i] = c.Raw
	}

	return tls.Certificate{Certificate: chain, PrivateKey: key, Leaf: certs[0]}, certs[0], nil
}

// Load returns the current identity. If key.pem and cert.pem do not match
// because a promotion was interrupted, it completes the promotion when
// next-cert.pem matches key.pem.
func (s Store) Load() (tls.Certificate, *x509.Certificate, error) {
	tc, leaf, err := s.loadPair(keyFile, certFile)
	if !errors.Is(err, ErrKeyMismatch) {
		return tc, leaf, err
	}

	if _, _, nerr := s.loadPair(keyFile, nextCertFile); nerr != nil {
		return tls.Certificate{}, nil, err
	}

	if rerr := s.renameSynced(nextCertFile, certFile); rerr != nil {
		return tls.Certificate{}, nil, rerr
	}

	return s.loadPair(keyFile, certFile)
}

// LoadNext returns the pending identity from next-key.pem and next-cert.pem.
func (s Store) LoadNext() (tls.Certificate, *x509.Certificate, error) {
	return s.loadPair(nextKeyFile, nextCertFile)
}

func (s Store) renameSynced(from, to string) error {
	if err := os.Rename(s.path(from), s.path(to)); err != nil {
		return fmt.Errorf("pki: rename %s: %w", from, err)
	}

	return syncDir(s.Dir)
}

// PromoteNext makes next-* the current identity; see Store for crash safety.
func (s Store) PromoteNext() error {
	if _, _, err := s.LoadNext(); err != nil {
		return fmt.Errorf("pki: next identity invalid: %w", err)
	}

	if err := s.renameSynced(nextKeyFile, keyFile); err != nil {
		return err
	}

	return s.renameSynced(nextCertFile, certFile)
}

// DiscardNext removes next-key.pem and next-cert.pem.
func (s Store) DiscardNext() error {
	for _, name := range []string{nextCertFile, nextKeyFile} {
		if err := os.Remove(s.path(name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("pki: remove %s: %w", name, err)
		}
	}

	return syncDir(s.Dir)
}
