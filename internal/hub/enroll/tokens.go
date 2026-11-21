// Package enroll implements agent enrollment on the hub: single-use tokens,
// the admin unix socket that mints them and the enrollment connection handler.
package enroll

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/zekihan/t3-mesh/internal/policy"
)

// TokenTTL is how long an enrollment token stays valid.
const TokenTTL = 15 * time.Minute

// ErrInvalidToken is returned by Redeem for unknown, used or expired tokens.
var ErrInvalidToken = errors.New("enroll: invalid or expired token")

var errEmptyIdentity = errors.New("enroll: empty identity")

const (
	tokenBytes    = 32
	tokenIDBytes  = 16
	tokenIDPrefix = 8
)

var (
	tokenPrefix       = regexp.MustCompile(`^[a-f0-9]{1,32}$`)
	errTokenPrefix    = errors.New("enroll: invalid token ID prefix")
	errNoToken        = errors.New("enroll: no outstanding token matches the ID prefix")
	errAmbiguousToken = errors.New("enroll: token ID prefix is ambiguous")
)

// TokenInfo identifies a token without exposing its secret or its hash.
type TokenInfo struct {
	Expires  time.Time `json:"expires"`
	ID       string    `json:"id"`
	Identity string    `json:"identity"`
	Kind     string    `json:"kind"`
}

type tokenEntry struct {
	expires  time.Time
	identity string
	id       string
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

	var raw [tokenBytes + tokenIDBytes]byte

	_, err := rand.Read(raw[:])
	if err != nil {
		return "", time.Time{}, fmt.Errorf("enroll: generate token: %w", err)
	}

	token := base64.RawURLEncoding.EncodeToString(raw[:tokenBytes])
	id := hex.EncodeToString(raw[tokenBytes:])
	hash := sha256.Sum256([]byte(token))

	tokens.mu.Lock()
	defer tokens.mu.Unlock()

	tokens.pruneLocked()

	if old, ok := tokens.byIdentity[identity]; ok {
		delete(tokens.byHash, old)
	}

	expires := tokens.now().Add(TokenTTL)
	tokens.byHash[hash] = tokenEntry{identity: identity, expires: expires, id: id}
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

// List returns a display prefix for each outstanding token.
func (tokens *Tokens) List() []TokenInfo {
	tokens.mu.Lock()
	defer tokens.mu.Unlock()

	tokens.pruneLocked()

	info := make([]TokenInfo, 0, len(tokens.byHash))
	for _, entry := range tokens.byHash {
		kind := KindAgent
		if policy.IsDevice(entry.identity) {
			kind = KindDevice
		}

		info = append(info, TokenInfo{
			ID: entry.id, Identity: entry.identity, Kind: kind, Expires: entry.expires.UTC(),
		})
	}

	slices.SortFunc(info, func(left, right TokenInfo) int {
		return strings.Compare(left.ID, right.ID)
	})

	lengths := make([]int, len(info))
	for i, entry := range info {
		length := tokenIDPrefix
		for length < len(entry.ID) &&
			((i > 0 && strings.HasPrefix(info[i-1].ID, entry.ID[:length])) ||
				(i+1 < len(info) && strings.HasPrefix(info[i+1].ID, entry.ID[:length]))) {
			length++
		}

		lengths[i] = length
	}

	for i, length := range lengths {
		info[i].ID = info[i].ID[:length]
	}

	return info
}

// Revoke consumes an outstanding token identified by an unambiguous prefix.
func (tokens *Tokens) Revoke(prefix string) error {
	if !tokenPrefix.MatchString(prefix) {
		return errTokenPrefix
	}

	tokens.mu.Lock()
	defer tokens.mu.Unlock()

	tokens.pruneLocked()

	var (
		found [32]byte
		match bool
	)

	for hash, entry := range tokens.byHash {
		if !strings.HasPrefix(entry.id, prefix) {
			continue
		}

		if match {
			return errAmbiguousToken
		}

		found, match = hash, true
	}

	if !match {
		return errNoToken
	}

	delete(tokens.byIdentity, tokens.byHash[found].identity)
	delete(tokens.byHash, found)

	return nil
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
