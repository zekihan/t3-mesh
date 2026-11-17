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
	dirMode         = 0o700
	privateFileMode = 0o600
	publicFileMode  = 0o644
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

// EnsureDir creates the directory with mode 0700 and narrows a wider mode.
func (store Store) EnsureDir() error {
	err := os.MkdirAll(store.Dir, dirMode)
	if err != nil {
		return fmt.Errorf("pki: create identity dir: %w", err)
	}

	err = os.Chmod(store.Dir, dirMode)
	if err != nil {
		return fmt.Errorf("pki: chmod identity dir: %w", err)
	}

	return nil
}

// Exists reports whether key.pem and cert.pem are both present.
func (store Store) Exists() bool {
	return fileExists(store.path(keyFile)) && fileExists(store.path(certFile))
}

func fileExists(p string) bool {
	_, err := os.Stat(p)

	return err == nil
}

// SaveKey writes key.pem.
func (store Store) SaveKey(key *ecdsa.PrivateKey) error {
	return store.writeKey(keyFile, key)
}

// SaveCert writes cert.pem as certPEM followed by chainPEM after checking that
// the leaf matches key.pem.
func (store Store) SaveCert(certPEM, chainPEM []byte) error {
	key, err := store.readKey(keyFile)
	if err != nil {
		return err
	}

	return store.writeCert(certFile, key, certPEM, chainPEM)
}

// SaveNext writes next-key.pem and next-cert.pem after checking they match.
func (store Store) SaveNext(key *ecdsa.PrivateKey, certPEM, chainPEM []byte) error {
	bundle := joinPEM(certPEM, chainPEM)

	certs, err := ParseCertsPEM(bundle)
	if err != nil {
		return err
	}

	if !matches(certs[0], key) {
		return ErrKeyMismatch
	}

	err = store.writeKey(nextKeyFile, key)
	if err != nil {
		return err
	}

	return store.writeCert(nextCertFile, key, certPEM, chainPEM)
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

// Load returns the current identity. If key.pem and cert.pem do not match
// because a promotion was interrupted, it completes the promotion when
// next-cert.pem matches key.pem.
func (store Store) Load() (tls.Certificate, *x509.Certificate, error) {
	tc, leaf, err := store.loadPair(keyFile, certFile)
	if !errors.Is(err, ErrKeyMismatch) {
		return tc, leaf, err
	}

	_, _, nextErr := store.loadPair(keyFile, nextCertFile)
	if nextErr != nil {
		return tls.Certificate{}, nil, err
	}

	rerr := store.renameSynced(nextCertFile, certFile)
	if rerr != nil {
		return tls.Certificate{}, nil, rerr
	}

	return store.loadPair(keyFile, certFile)
}

// LoadNext returns the pending identity from next-key.pem and next-cert.pem.
func (store Store) LoadNext() (tls.Certificate, *x509.Certificate, error) {
	return store.loadPair(nextKeyFile, nextCertFile)
}

// PromoteNext makes next-* the current identity; see Store for crash safety.
func (store Store) PromoteNext() error {
	_, _, err := store.LoadNext()
	if err != nil {
		return fmt.Errorf("pki: next identity invalid: %w", err)
	}

	err = store.renameSynced(nextKeyFile, keyFile)
	if err != nil {
		return err
	}

	return store.renameSynced(nextCertFile, certFile)
}

// DiscardNext removes next-key.pem and next-cert.pem.
func (store Store) DiscardNext() error {
	for _, name := range []string{nextCertFile, nextKeyFile} {
		err := os.Remove(store.path(name))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("pki: remove %s: %w", name, err)
		}
	}

	return syncDir(store.Dir)
}

func (store Store) path(name string) string { return filepath.Join(store.Dir, name) }

func (store Store) writeKey(name string, key *ecdsa.PrivateKey) error {
	err := store.EnsureDir()
	if err != nil {
		return err
	}

	data, err := EncodeKeyPEM(key)
	if err != nil {
		return err
	}

	return WriteFileAtomic(store.path(name), data, privateFileMode)
}

func (store Store) writeCert(name string, key *ecdsa.PrivateKey, certPEM, chainPEM []byte) error {
	bundle := joinPEM(certPEM, chainPEM)

	certs, err := ParseCertsPEM(bundle)
	if err != nil {
		return err
	}

	if !matches(certs[0], key) {
		return ErrKeyMismatch
	}

	err = store.EnsureDir()
	if err != nil {
		return err
	}

	return WriteFileAtomic(store.path(name), bundle, publicFileMode)
}

func (store Store) readKey(name string) (*ecdsa.PrivateKey, error) {
	data, err := os.ReadFile(store.path(name))
	if err != nil {
		return nil, fmt.Errorf("pki: read %s: %w", name, err)
	}

	return ParseKeyPEM(data)
}

func (store Store) loadPair(keyName, certName string) (tls.Certificate, *x509.Certificate, error) {
	key, err := store.readKey(keyName)
	if err != nil {
		return tls.Certificate{}, nil, err
	}

	data, err := os.ReadFile(store.path(certName))
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

func (store Store) renameSynced(from, to string) error {
	err := os.Rename(store.path(from), store.path(to))
	if err != nil {
		return fmt.Errorf("pki: rename %s: %w", from, err)
	}

	return syncDir(store.Dir)
}
