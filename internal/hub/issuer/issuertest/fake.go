// Package issuertest provides a fake issuer.Issuer for tests.
package issuertest

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"sync"
)

var (
	errSignNotSet = errors.New("issuertest: Sign not set")
	errNoPEM      = errors.New("issuertest: Sign returned no PEM certificate")
)

// Fake is a thread-safe in-memory issuer.Issuer.
type Fake struct {
	Sign   func(csrPEM []byte) (certPEM, chainPEM []byte, err error)
	newest map[string]string
	mu     sync.Mutex
}

// Issue signs via Sign and records the leaf fingerprint as newest for identity.
func (fake *Fake) Issue(
	ctx context.Context,
	identity string,
	csrPEM []byte,
) ([]byte, []byte, error) {
	err := ctx.Err()
	if err != nil {
		return nil, nil, fmt.Errorf("issuertest: %w", err)
	}

	if fake.Sign == nil {
		return nil, nil, errSignNotSet
	}

	cert, chain, err := fake.Sign(csrPEM)
	if err != nil {
		return nil, nil, err
	}

	blk, _ := pem.Decode(cert)
	if blk == nil {
		return nil, nil, errNoPEM
	}

	leaf, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("issuertest: parse certificate: %w", err)
	}

	sum := sha256.Sum256(leaf.Raw)
	fake.SetNewest(identity, hex.EncodeToString(sum[:]))

	return cert, chain, nil
}

// Newest returns the recorded fingerprint for identity, or "".
func (fake *Fake) Newest(ctx context.Context, identity string) (string, error) {
	err := ctx.Err()
	if err != nil {
		return "", fmt.Errorf("issuertest: %w", err)
	}

	fake.mu.Lock()
	defer fake.mu.Unlock()

	return fake.newest[identity], nil
}

// SetNewest overrides the newest fingerprint for identity.
func (fake *Fake) SetNewest(identity, fp string) {
	fake.mu.Lock()
	defer fake.mu.Unlock()

	if fake.newest == nil {
		fake.newest = map[string]string{}
	}

	fake.newest[identity] = fp
}
