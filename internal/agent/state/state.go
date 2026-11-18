// Package state persists the agent's cache of hub-provided state.
package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/zekihan/t3-mesh/internal/proto"
)

// FormatVersion is the cache file format written by this package.
const FormatVersion = 1

var errUnsupportedFormat = errors.New("state: unsupported cache format version")

const (
	fileName = "cache.json"
	dirMode  = 0o700
	fileMode = 0o600
)

// Cache is the agent's on-disk copy of state last received from the hub.
type Cache struct {
	Rules          proto.Rules       `json:"rules"`
	LastHubContact time.Time         `json:"lastHubContact"`
	Release        proto.Release     `json:"release"`
	TrustBundle    proto.TrustBundle `json:"trustBundle"`
	Machine        string            `json:"machine"`
	HomeGatewayMAC string            `json:"homeGatewayMAC,omitempty"` //nolint:tagliatelle // persisted key
	Revocations    proto.Revocations `json:"revocations"`
	Peers          proto.PeerTable   `json:"peers"`
	// DeviceLeaves is the newest leaf of every enrolled device the hub told this
	// agent about. The field is optional and the format version stays 1: a release
	// before it ignores the key when reading and drops it when it next saves,
	// and the hub sends the list again at the next HelloAck.
	DeviceLeaves  proto.DeviceLeaves `json:"deviceLeaves,omitzero"`
	HomeCIDRs     []string           `json:"homeCIDRs,omitempty"` //nolint:tagliatelle // persisted key
	FormatVersion int                `json:"formatVersion"`
	Home          bool               `json:"home"`
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

	var cache Cache

	err = json.Unmarshal(data, &cache)
	if err != nil {
		return nil, fmt.Errorf("state: decode cache: %w", err)
	}

	if cache.FormatVersion < 1 || cache.FormatVersion > FormatVersion {
		return nil, fmt.Errorf("%w %d", errUnsupportedFormat, cache.FormatVersion)
	}

	return &cache, nil
}

// Save writes c to dir atomically: a temporary file in dir is fsynced and renamed
// over cache.json, so readers see either the old or the new file, never a partial one.
func Save(dir string, c *Cache) error {
	err := os.MkdirAll(dir, dirMode)
	if err != nil {
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

	err = writeSync(tmp, data)
	if err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)

		return err
	}

	err = os.Rename(tmpName, filepath.Join(dir, fileName))
	if err != nil {
		_ = os.Remove(tmpName)

		return fmt.Errorf("state: rename cache: %w", err)
	}

	return syncDir(dir)
}

func writeSync(file *os.File, data []byte) error {
	err := file.Chmod(fileMode)
	if err != nil {
		return fmt.Errorf("state: chmod temp file: %w", err)
	}

	_, err = file.Write(data)
	if err != nil {
		return fmt.Errorf("state: write temp file: %w", err)
	}

	err = file.Sync()
	if err != nil {
		return fmt.Errorf("state: sync temp file: %w", err)
	}

	err = file.Close()
	if err != nil {
		return fmt.Errorf("state: close temp file: %w", err)
	}

	return nil
}

func syncDir(dir string) error {
	dirFile, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("state: open dir: %w", err)
	}

	defer func() { _ = dirFile.Close() }()

	err = dirFile.Sync()
	if err != nil {
		return fmt.Errorf("state: sync dir: %w", err)
	}

	return nil
}

// WithinWindow reports whether the hub was last contacted no more than ttl before now.
// A cache that has never seen the hub is never within the window.
// MaxClockSkew is how far now may lag LastHubContact before the window closes.
const maxClockSkew = 5 * time.Minute

func (cache *Cache) WithinWindow(now time.Time, ttl time.Duration) bool {
	if cache.LastHubContact.IsZero() {
		return false
	}

	age := now.Sub(cache.LastHubContact)

	// A clock that moved back past the last contact must not keep the window
	// open indefinitely; tolerate only small skew.
	return age >= -maxClockSkew && age <= ttl
}

// Apply copies every non-nil field of u into the cache.
func (cache *Cache) Apply(update proto.Update) {
	if update.Home != nil {
		cache.Home = *update.Home
	}

	if update.Rules != nil {
		cache.Rules = *update.Rules
	}

	if update.Peers != nil {
		cache.Peers = *update.Peers
	}

	if update.Revocations != nil {
		cache.Revocations = *update.Revocations
	}

	if update.TrustBundle != nil {
		cache.TrustBundle = *update.TrustBundle
	}

	if update.HomeCIDRs != nil {
		cache.HomeCIDRs = slices.Clone(*update.HomeCIDRs)
	}

	if update.DeviceLeaves != nil {
		cache.DeviceLeaves = cloneDeviceLeaves(update.DeviceLeaves)
	}
}

func cloneDeviceLeaves(in *proto.DeviceLeaves) proto.DeviceLeaves {
	return proto.DeviceLeaves{Revision: in.Revision, Leaves: slices.Clone(in.Leaves)}
}

// ApplyAck copies the device leaves of a HelloAck into the cache. A nil list
// means the hub could not tell or predates them, and the cached one stays.
func (cache *Cache) ApplyAck(ack *proto.HelloAck) {
	if ack.DeviceLeaves != nil {
		cache.DeviceLeaves = cloneDeviceLeaves(ack.DeviceLeaves)
	}
}
