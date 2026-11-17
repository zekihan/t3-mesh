package release

import (
	"errors"
	"fmt"
	"strings"
	"sync"

	"aead.dev/minisign"
)

var errNoTrustedKeys = errors.New("no trusted keys")

// TrustedKeys are the compiled-in minisign public keys (current and next), as
// the base64 line of a minisign .pub file.
//
// PLACEHOLDERS: replace before the first release, or override at link time
// with -ldflags "-X github.com/zekihan/t3-mesh/internal/release.TrustedKeysOverride=KEY1,KEY2".
var TrustedKeys = []string{
	"PLACEHOLDER-REPLACE-WITH-CURRENT-MINISIGN-PUBLIC-KEY",
	"PLACEHOLDER-REPLACE-WITH-NEXT-MINISIGN-PUBLIC-KEY",
}

// TrustedKeysOverride, when non-empty, is a comma-separated key list that
// replaces TrustedKeys. It exists so -ldflags -X can set the keys.
var TrustedKeysOverride string

var keysMu sync.Mutex

// SetTrustedKeys replaces the compiled-in keys (for tests) and returns a
// function that restores the previous ones.
func SetTrustedKeys(keys []string) func() {
	keysMu.Lock()
	defer keysMu.Unlock()

	oldKeys, oldOverride := TrustedKeys, TrustedKeysOverride
	TrustedKeys, TrustedKeysOverride = keys, ""

	return func() {
		keysMu.Lock()
		defer keysMu.Unlock()

		TrustedKeys, TrustedKeysOverride = oldKeys, oldOverride
	}
}

// ParseKeys parses minisign public key strings. Every entry must parse.
func ParseKeys(keys []string) ([]minisign.PublicKey, error) {
	var out []minisign.PublicKey

	for i, s := range keys {
		var pub minisign.PublicKey

		err := pub.UnmarshalText([]byte(strings.TrimSpace(s)))
		if err != nil {
			return nil, fmt.Errorf("trusted key %d: %w", i, err)
		}

		out = append(out, pub)
	}

	if len(out) == 0 {
		return nil, errNoTrustedKeys
	}

	return out, nil
}

// DefaultKeys parses the compiled-in trusted keys. It fails while the
// placeholders are still in place, so an unconfigured build never verifies.
func DefaultKeys() ([]minisign.PublicKey, error) {
	keysMu.Lock()

	keys := TrustedKeys
	if TrustedKeysOverride != "" {
		keys = strings.Split(TrustedKeysOverride, ",")
	}
	keysMu.Unlock()

	return ParseKeys(keys)
}
