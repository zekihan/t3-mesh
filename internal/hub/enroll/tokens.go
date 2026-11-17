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

var errEmptyIdentity = errors.New("enroll: empty identity")

type tokenEntry struct {
	expires  time.Time
	identity string
}

// Tokens is an in-memory store of single-use enrollment tokens. Only SHA-256
// hashes of tokens are kept.
type Tokens struct {
	now        func() time.Time
	byHash     map[[32]byte]tokenEntry
	byIdentity map[string][32]byte
	mu         sync.Mutex
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
func (tokens *Tokens) Create(identity string) (string, time.Time, error) {
	if identity == "" {
		return "", time.Time{}, errEmptyIdentity
	}

	var raw [32]byte

	_, err := rand.Read(raw[:])
	if err != nil {
		return "", time.Time{}, fmt.Errorf("enroll: generate token: %w", err)
	}

	token := base64.RawURLEncoding.EncodeToString(raw[:])
	hash := sha256.Sum256([]byte(token))

	tokens.mu.Lock()
	defer tokens.mu.Unlock()

	tokens.pruneLocked()

	if old, ok := tokens.byIdentity[identity]; ok {
		delete(tokens.byHash, old)
	}

	expires := tokens.now().Add(TokenTTL)
	tokens.byHash[hash] = tokenEntry{identity: identity, expires: expires}
	tokens.byIdentity[identity] = hash

	return token, expires, nil
}

// Outstanding reports whether any unexpired token exists.
func (tokens *Tokens) Outstanding() bool {
	tokens.mu.Lock()
	defer tokens.mu.Unlock()

	tokens.pruneLocked()

	return len(tokens.byHash) > 0
}

// Redeem consumes token and returns the identity it is bound to.
func (tokens *Tokens) Redeem(token string) (string, error) {
	hash := sha256.Sum256([]byte(token))

	tokens.mu.Lock()
	defer tokens.mu.Unlock()

	entry, ok := tokens.byHash[hash]
	if !ok {
		return "", ErrInvalidToken
	}

	delete(tokens.byHash, hash)
	delete(tokens.byIdentity, entry.identity)

	if !tokens.now().Before(entry.expires) {
		return "", ErrInvalidToken
	}

	return entry.identity, nil
}

func (tokens *Tokens) pruneLocked() {
	now := tokens.now()

	for hash, entry := range tokens.byHash {
		if !now.Before(entry.expires) {
			delete(tokens.byHash, hash)
			delete(tokens.byIdentity, entry.identity)
		}
	}
}
