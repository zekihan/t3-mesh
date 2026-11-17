package release

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"aead.dev/minisign"
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
func (m Manifest) Asset(platform string) (Asset, bool) {
	for _, a := range m.Assets {
		if a.Platform == platform {
			return a, true
		}
	}
	return Asset{}, false
}

// Validate checks the manifest's fields.
func (m Manifest) Validate() error {
	if _, err := ParseVersion(m.Version); err != nil {
		return fmt.Errorf("manifest version: %w", err)
	}
	if _, err := ParseVersion(m.MinStateVersion); err != nil {
		return fmt.Errorf("manifest minStateVersion: %w", err)
	}
	seen := map[string]bool{}
	for _, a := range m.Assets {
		if a.Platform != PlatformLinuxAMD64 && a.Platform != PlatformDarwinARM64 {
			return fmt.Errorf("manifest asset: unknown platform %q", a.Platform)
		}
		if seen[a.Platform] {
			return fmt.Errorf("manifest asset: duplicate platform %q", a.Platform)
		}
		seen[a.Platform] = true
		if !validAssetName(a.Name) {
			return fmt.Errorf("manifest asset %s: invalid name %q", a.Platform, a.Name)
		}
		if b, err := hex.DecodeString(a.SHA256); err != nil || len(b) != 32 {
			return fmt.Errorf("manifest asset %s: invalid sha256", a.Platform)
		}
	}
	return nil
}

func validAssetName(n string) bool {
	if n == "" || strings.HasPrefix(n, ".") || n == ManifestAsset || n == SignatureAsset {
		return false
	}
	for _, r := range n {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r == '-' || r == '_' || r == '.') {
			return false
		}
	}
	return true
}

// VerifyManifest checks that at least one signature in sig verifies data under
// at least one of keys, then parses and validates the manifest.
//
// sig is the content of manifest.json.minisig: one or more minisign signature
// files (4 lines each, starting with "untrusted comment: ") concatenated.
// During key rotation CI appends the signature from each key, so verification
// succeeds if ANY signature verifies with ANY trusted key.
func VerifyManifest(data, sig []byte, keys []minisign.PublicKey) (Manifest, error) {
	if len(keys) == 0 {
		return Manifest{}, errors.New("no trusted keys configured")
	}
	sigs := splitSignatures(sig)
	if len(sigs) == 0 {
		return Manifest{}, errors.New("no signature found")
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
		return Manifest{}, errors.New("manifest signature verification failed")
	}
	var m Manifest
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return Manifest{}, fmt.Errorf("parse manifest: %w", err)
	}
	if err := m.Validate(); err != nil {
		return Manifest{}, err
	}
	return m, nil
}

// splitSignatures splits concatenated minisign signature files at each
// "untrusted comment: " line.
func splitSignatures(sig []byte) [][]byte {
	var out [][]byte
	var cur []string
	flush := func() {
		if len(cur) > 0 {
			out = append(out, []byte(strings.Join(cur, "\n")+"\n"))
			cur = nil
		}
	}
	for _, line := range strings.Split(strings.ReplaceAll(string(sig), "\r\n", "\n"), "\n") {
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
