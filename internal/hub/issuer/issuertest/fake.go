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

// Fake is a thread-safe in-memory issuer.Issuer.
type Fake struct {
	Sign func(csrPEM []byte) (certPEM, chainPEM []byte, err error)

	mu     sync.Mutex
	newest map[string]string
}

// Issue signs via Sign and records the leaf fingerprint as newest for identity.
func (f *Fake) Issue(ctx context.Context, identity string, csrPEM []byte) ([]byte, []byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	if f.Sign == nil {
		return nil, nil, errors.New("issuertest: Sign not set")
	}
	cert, chain, err := f.Sign(csrPEM)
	if err != nil {
		return nil, nil, err
	}
	blk, _ := pem.Decode(cert)
	if blk == nil {
		return nil, nil, errors.New("issuertest: Sign returned no PEM certificate")
	}
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("issuertest: parse certificate: %w", err)
	}
	sum := sha256.Sum256(c.Raw)
	f.SetNewest(identity, hex.EncodeToString(sum[:]))
	return cert, chain, nil
}

// Newest returns the recorded fingerprint for identity, or "".
func (f *Fake) Newest(ctx context.Context, identity string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.newest[identity], nil
}

// SetNewest overrides the newest fingerprint for identity.
func (f *Fake) SetNewest(identity, fp string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.newest == nil {
		f.newest = map[string]string{}
	}
	f.newest[identity] = fp
}
