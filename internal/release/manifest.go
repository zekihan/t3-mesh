package release

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"aead.dev/minisign"
)

var (
	errUnknownPlatform   = errors.New("unknown platform")
	errDuplicatePlatform = errors.New("duplicate platform")
	errInvalidName       = errors.New("invalid name")
	errInvalidSHA256     = errors.New("invalid sha256")
	errNoKeysConfigured  = errors.New("no trusted keys configured")
	errNoSignature       = errors.New("no signature found")
	errBadSignature      = errors.New("manifest signature verification failed")
)

// Fixed release asset names. The signature asset holds one or more
// concatenated minisign signatures (see VerifyManifest).
const (
	ManifestAsset  = "manifest.json"
	SignatureAsset = "manifest.json.minisig"
)

// Supported platforms.
const (
	PlatformLinuxAMD64  = "linux-amd64"
	PlatformDarwinARM64 = "darwin-arm64"
)

// Asset is one platform binary in a release.
type Asset struct {
	Platform string `json:"platform"`
	Name     string `json:"name"`
	SHA256   string `json:"sha256"`
}

// Manifest describes a release. It is signed as the exact bytes published.
type Manifest struct {
	Version         string  `json:"version"`
	MinStateVersion string  `json:"minStateVersion"`
	Assets          []Asset `json:"assets"`
}

// Asset returns the asset for platform.
func (man Manifest) Asset(platform string) (Asset, bool) {
	for _, a := range man.Assets {
		if a.Platform == platform {
			return a, true
		}
	}

	return Asset{}, false
}

// Validate checks the manifest's fields.
func (man Manifest) Validate() error {
	_, err := ParseVersion(man.Version)
	if err != nil {
		return fmt.Errorf("manifest version: %w", err)
	}

	_, err = ParseVersion(man.MinStateVersion)
	if err != nil {
		return fmt.Errorf("manifest minStateVersion: %w", err)
	}

	seen := map[string]bool{}

	for _, asset := range man.Assets {
		if asset.Platform != PlatformLinuxAMD64 && asset.Platform != PlatformDarwinARM64 {
			return fmt.Errorf("manifest asset: %w %q", errUnknownPlatform, asset.Platform)
		}

		if seen[asset.Platform] {
			return fmt.Errorf("manifest asset: %w %q", errDuplicatePlatform, asset.Platform)
		}

		seen[asset.Platform] = true
		if !validAssetName(asset.Name) {
			return fmt.Errorf(
				"manifest asset %s: %w %q",
				asset.Platform,
				errInvalidName,
				asset.Name,
			)
		}

		digest, decodeErr := hex.DecodeString(asset.SHA256)
		if decodeErr != nil || len(digest) != sha256.Size {
			return fmt.Errorf("manifest asset %s: %w", asset.Platform, errInvalidSHA256)
		}
	}

	return nil
}

func validAssetName(n string) bool {
	if n == "" || strings.HasPrefix(n, ".") || n == ManifestAsset || n == SignatureAsset {
		return false
	}

	for _, r := range n {
		if !isAlnum(r) && r != '-' && r != '_' && r != '.' {
			return false
		}
	}

	return true
}

func isAlnum(r rune) bool {
	return r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z'
}

// VerifyManifest checks that at least one signature in sig verifies data under
// at least one of keys, then parses and validates the manifest.
//
// The sig argument is the content of manifest.json.minisig: one or more minisign signature
// files (4 lines each, starting with "untrusted comment: ") concatenated.
// During key rotation CI appends the signature from each key, so verification
// succeeds if ANY signature verifies with ANY trusted key.
func VerifyManifest(data, sig []byte, keys []minisign.PublicKey) (Manifest, error) {
	if len(keys) == 0 {
		return Manifest{}, errNoKeysConfigured
	}

	sigs := splitSignatures(sig)
	if len(sigs) == 0 {
		return Manifest{}, errNoSignature
	}

	ok := false

	for _, s := range sigs {
		for _, k := range keys {
			if minisign.Verify(k, data, s) {
				ok = true
			}
		}
	}

	if !ok {
		return Manifest{}, errBadSignature
	}

	var man Manifest

	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()

	err := dec.Decode(&man)
	if err != nil {
		return Manifest{}, fmt.Errorf("parse manifest: %w", err)
	}

	err = man.Validate()
	if err != nil {
		return Manifest{}, err
	}

	return man, nil
}

// splitSignatures splits concatenated minisign signature files at each
// "untrusted comment: " line.
func splitSignatures(sig []byte) [][]byte {
	var (
		out [][]byte
		cur []string
	)

	flush := func() {
		if len(cur) > 0 {
			out = append(out, []byte(strings.Join(cur, "\n")+"\n"))
			cur = nil
		}
	}

	for line := range strings.SplitSeq(strings.ReplaceAll(string(sig), "\r\n", "\n"), "\n") {
		if strings.HasPrefix(line, "untrusted comment: ") {
			flush()
		}

		if line == "" {
			continue
		}

		cur = append(cur, line)
	}

	flush()

	return out
}
