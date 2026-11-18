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
	"slices"
	"sync"
)

var (
	errSignNotSet = errors.New("issuertest: Sign not set")
	errNoPEM      = errors.New("issuertest: Sign returned no PEM certificate")
)

// Fake is a thread-safe in-memory issuer.Issuer.
type Fake struct {
	// PruneErr, if set, is returned by Prune.
	PruneErr error
	// NewestErr, if set, is returned by Newest.
	NewestErr error
	Sign      func(csrPEM []byte) (certPEM, chainPEM []byte, err error)
	newest    map[string]string
	pruned    []PruneCall
	mu        sync.Mutex
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

	if fake.NewestErr != nil {
		return "", fake.NewestErr
	}

	return fake.newest[identity], nil
}

// PruneCall records one Prune invocation.
type PruneCall struct {
	Identity string
	Keep     int
}

// Prune records the call and returns PruneErr.
func (fake *Fake) Prune(ctx context.Context, identity string, keep int) error {
	fake.mu.Lock()
	defer fake.mu.Unlock()

	fake.pruned = append(fake.pruned, PruneCall{Identity: identity, Keep: keep})

	return fake.PruneErr
}

// PruneCalls returns the recorded Prune invocations.
func (fake *Fake) PruneCalls() []PruneCall {
	fake.mu.Lock()
	defer fake.mu.Unlock()

	return slices.Clone(fake.pruned)
}

// SetNewestErr makes Newest fail with err; nil makes it work again.
func (fake *Fake) SetNewestErr(err error) {
	fake.mu.Lock()
	defer fake.mu.Unlock()

	fake.NewestErr = err
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
