package release

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"aead.dev/minisign"
)

// DefaultBaseURL is the compiled-in release download prefix.
const DefaultBaseURL = "https://github.com/zekihan/t3-mesh/releases/download/"

// Download size limits.
const (
	MaxManifestSize  = 1 << 20
	MaxSignatureSize = 64 << 10
	MaxBinarySize    = 256 << 20
)

// Downloader fetches and verifies releases. URLs are built only from BaseURL,
// a validated version and fixed or signed asset names.
type Downloader struct {
	BaseURL string // default DefaultBaseURL
	Client  *http.Client
	Keys    []minisign.PublicKey // default DefaultKeys()
}

func (d *Downloader) client() *http.Client {
	if d.Client != nil {
		return d.Client
	}
	return http.DefaultClient
}

func (d *Downloader) assetURL(version, name string) (string, error) {
	if _, err := ParseVersion(version); err != nil {
		return "", err
	}
	base := d.BaseURL
	if base == "" {
		base = DefaultBaseURL
	}
	if !strings.HasSuffix(base, "/") {
		base += "/"
	}
	return base + version + "/" + name, nil
}

// Fetch downloads and verifies the manifest of version.
func (d *Downloader) Fetch(ctx context.Context, version string) (Manifest, error) {
	keys := d.Keys
	if keys == nil {
		var err error
		if keys, err = DefaultKeys(); err != nil {
			return Manifest{}, err
		}
	}
	data, err := d.get(ctx, version, ManifestAsset, MaxManifestSize)
	if err != nil {
		return Manifest{}, err
	}
	sig, err := d.get(ctx, version, SignatureAsset, MaxSignatureSize)
	if err != nil {
		return Manifest{}, err
	}
	m, err := VerifyManifest(data, sig, keys)
	if err != nil {
		return Manifest{}, fmt.Errorf("release %s: %w", version, err)
	}
	if m.Version != version {
		return Manifest{}, fmt.Errorf("release %s: manifest is for %s", version, m.Version)
	}
	return m, nil
}

func (d *Downloader) get(ctx context.Context, version, name string, limit int64) ([]byte, error) {
	rc, err := d.open(ctx, version, name)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	b, err := io.ReadAll(io.LimitReader(rc, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", name, err)
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%s exceeds %d bytes", name, limit)
	}
	return b, nil
}

func (d *Downloader) open(ctx context.Context, version, name string) (io.ReadCloser, error) {
	u, err := d.assetURL(version, name)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	resp, err := d.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", name, err)
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("download %s: http status %d", name, resp.StatusCode)
	}
	return resp.Body, nil
}

// Download fetches the binary for platform listed in m (which must come from
// Fetch or VerifyManifest), checks its SHA-256 and atomically writes it to
// destPath with mode 0755.
func (d *Downloader) Download(
	ctx context.Context,
	m Manifest,
	platform, destPath string,
) (err error) {
	a, ok := m.Asset(platform)
	if !ok {
		return fmt.Errorf("release %s has no asset for %s", m.Version, platform)
	}
	if err := m.Validate(); err != nil {
		return err
	}
	rc, err := d.open(ctx, m.Version, a.Name)
	if err != nil {
		return err
	}
	defer rc.Close()

	dir := filepath.Dir(destPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".download-*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	defer func() {
		if err != nil {
			tmp.Close()
			os.Remove(tmp.Name())
		}
	}()
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(rc, MaxBinarySize+1))
	if err != nil {
		return fmt.Errorf("download %s: %w", a.Name, err)
	}
	if n > MaxBinarySize {
		return fmt.Errorf("%s exceeds %d bytes", a.Name, int64(MaxBinarySize))
	}
	if got := hex.EncodeToString(h.Sum(nil)); !strings.EqualFold(got, a.SHA256) {
		return errors.New("sha256 mismatch for " + a.Name)
	}
	if err = tmp.Chmod(0o755); err != nil {
		return fmt.Errorf("chmod: %w", err)
	}
	if err = tmp.Sync(); err != nil {
		return fmt.Errorf("sync: %w", err)
	}
	if err = tmp.Close(); err != nil {
		return fmt.Errorf("close: %w", err)
	}
	if err = os.Rename(tmp.Name(), destPath); err != nil {
		return fmt.Errorf("install %s: %w", destPath, err)
	}
	return nil
}
