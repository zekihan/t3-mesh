// Package state persists the agent's cache of hub-provided state.
package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/zekihan/t3-mesh/internal/proto"
)

// FormatVersion is the cache file format written by this package.
const FormatVersion = 1

const (
	fileName = "cache.json"
	dirMode  = 0o700
	fileMode = 0o600
)

// Cache is the agent's on-disk copy of state last received from the hub.
type Cache struct {
	FormatVersion  int               `json:"formatVersion"`
	Machine        string            `json:"machine"`
	Home           bool              `json:"home"`
	Rules          proto.Rules       `json:"rules"`
	Peers          proto.PeerTable   `json:"peers"`
	Revocations    proto.Revocations `json:"revocations"`
	TrustBundle    proto.TrustBundle `json:"trustBundle"`
	Release        proto.Release     `json:"release"`
	LastHubContact time.Time         `json:"lastHubContact"`
	HomeGatewayMAC string            `json:"homeGatewayMAC,omitempty"`
	HomeCIDRs      []string          `json:"homeCIDRs,omitempty"`
}

// Load reads the cache in dir. A missing file yields an empty cache. A file written
// by a newer format version is an error, since its contents may be misread.
func Load(dir string) (*Cache, error) {
	data, err := os.ReadFile(filepath.Join(dir, fileName))
	if errors.Is(err, fs.ErrNotExist) {
		return &Cache{FormatVersion: FormatVersion}, nil
	}

	if err != nil {
		return nil, fmt.Errorf("state: read cache: %w", err)
	}

	var c Cache
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("state: decode cache: %w", err)
	}

	if c.FormatVersion < 1 || c.FormatVersion > FormatVersion {
		return nil, fmt.Errorf("state: unsupported cache format version %d", c.FormatVersion)
	}

	return &c, nil
}

// Save writes c to dir atomically: a temporary file in dir is fsynced and renamed
// over cache.json, so readers see either the old or the new file, never a partial one.
func Save(dir string, c *Cache) error {
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return fmt.Errorf("state: create dir: %w", err)
	}

	out := *c
	out.FormatVersion = FormatVersion

	data, err := json.MarshalIndent(&out, "", "  ")
	if err != nil {
		return fmt.Errorf("state: encode cache: %w", err)
	}

	tmp, err := os.CreateTemp(dir, ".cache-*.tmp")
	if err != nil {
		return fmt.Errorf("state: create temp file: %w", err)
	}

	tmpName := tmp.Name()
	if err := writeSync(tmp, data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)

		return err
	}

	if err := os.Rename(tmpName, filepath.Join(dir, fileName)); err != nil {
		_ = os.Remove(tmpName)

		return fmt.Errorf("state: rename cache: %w", err)
	}

	return syncDir(dir)
}

func writeSync(f *os.File, data []byte) error {
	if err := f.Chmod(fileMode); err != nil {
		return fmt.Errorf("state: chmod temp file: %w", err)
	}

	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("state: write temp file: %w", err)
	}

	if err := f.Sync(); err != nil {
		return fmt.Errorf("state: sync temp file: %w", err)
	}

	if err := f.Close(); err != nil {
		return fmt.Errorf("state: close temp file: %w", err)
	}

	return nil
}

func syncDir(dir string) error {
	d, err := os.Open(dir) //nolint:gosec // dir is the agent's own state directory
	if err != nil {
		return fmt.Errorf("state: open dir: %w", err)
	}

	defer func() { _ = d.Close() }()

	if err := d.Sync(); err != nil {
		return fmt.Errorf("state: sync dir: %w", err)
	}

	return nil
}

// WithinWindow reports whether the hub was last contacted no more than ttl before now.
// A cache that has never seen the hub is never within the window.
// maxClockSkew is how far now may lag LastHubContact before the window closes.
const maxClockSkew = 5 * time.Minute

func (c *Cache) WithinWindow(now time.Time, ttl time.Duration) bool {
	if c.LastHubContact.IsZero() {
		return false
	}

	age := now.Sub(c.LastHubContact)

	// A clock that moved back past the last contact must not keep the window
	// open indefinitely; tolerate only small skew.
	return age >= -maxClockSkew && age <= ttl
}

// Apply copies every non-nil field of u into the cache.
func (c *Cache) Apply(u proto.Update) {
	if u.Home != nil {
		c.Home = *u.Home
	}

	if u.Rules != nil {
		c.Rules = *u.Rules
	}

	if u.Peers != nil {
		c.Peers = *u.Peers
	}

	if u.Revocations != nil {
		c.Revocations = *u.Revocations
	}

	if u.TrustBundle != nil {
		c.TrustBundle = *u.TrustBundle
	}

	if u.HomeCIDRs != nil {
		c.HomeCIDRs = u.HomeCIDRs
	}
}
