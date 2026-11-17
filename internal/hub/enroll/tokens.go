// Package enroll implements agent enrollment on the hub: single-use tokens,
// the admin unix socket that mints them and the enrollment connection handler.
package enroll

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"time"
)

// TokenTTL is how long an enrollment token stays valid.
const TokenTTL = 15 * time.Minute

// ErrInvalidToken is returned by Redeem for unknown, used or expired tokens.
var ErrInvalidToken = errors.New("enroll: invalid or expired token")

type tokenEntry struct {
	identity string
	expires  time.Time
}

// Tokens is an in-memory store of single-use enrollment tokens. Only SHA-256
// hashes of tokens are kept.
type Tokens struct {
	now func() time.Time

	mu         sync.Mutex
	byHash     map[[32]byte]tokenEntry
	byIdentity map[string][32]byte
}

// NewTokens returns an empty store using now as its clock.
func NewTokens(now func() time.Time) *Tokens {
	if now == nil {
		now = time.Now
	}

	return &Tokens{
		now:        now,
		byHash:     map[[32]byte]tokenEntry{},
		byIdentity: map[string][32]byte{},
	}
}

// Create mints a token bound to identity, replacing any previous one for it.
func (t *Tokens) Create(identity string) (string, time.Time, error) {
	if identity == "" {
		return "", time.Time{}, errors.New("enroll: empty identity")
	}

	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", time.Time{}, fmt.Errorf("enroll: generate token: %w", err)
	}

	token := base64.RawURLEncoding.EncodeToString(raw[:])
	hash := sha256.Sum256([]byte(token))

	t.mu.Lock()
	defer t.mu.Unlock()

	t.pruneLocked()

	if old, ok := t.byIdentity[identity]; ok {
		delete(t.byHash, old)
	}

	expires := t.now().Add(TokenTTL)
	t.byHash[hash] = tokenEntry{identity: identity, expires: expires}
	t.byIdentity[identity] = hash

	return token, expires, nil
}

// Outstanding reports whether any unexpired token exists.
func (t *Tokens) Outstanding() bool {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.pruneLocked()

	return len(t.byHash) > 0
}

// Redeem consumes token and returns the identity it is bound to.
func (t *Tokens) Redeem(token string) (string, error) {
	hash := sha256.Sum256([]byte(token))

	t.mu.Lock()
	defer t.mu.Unlock()

	entry, ok := t.byHash[hash]
	if !ok {
		return "", ErrInvalidToken
	}

	delete(t.byHash, hash)
	delete(t.byIdentity, entry.identity)

	if !t.now().Before(entry.expires) {
		return "", ErrInvalidToken
	}

	return entry.identity, nil
}

func (t *Tokens) pruneLocked() {
	now := t.now()

	for hash, entry := range t.byHash {
		if !now.Before(entry.expires) {
			delete(t.byHash, hash)
			delete(t.byIdentity, entry.identity)
		}
	}
}
