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

const (
	binaryMode = 0o755
	dirMode    = 0o755
)

var (
	errManifestVersion = errors.New("manifest is for")
	errExceeds         = errors.New("exceeds")
	errHTTPStatus      = errors.New("http status")
	errNoAsset         = errors.New("no asset for")
	errSHA256Mismatch  = errors.New("sha256 mismatch")
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

// Fetch downloads and verifies the manifest of version.
func (dl *Downloader) Fetch(ctx context.Context, version string) (Manifest, error) {
	keys := dl.Keys
	if keys == nil {
		var err error

		keys, err = DefaultKeys()
		if err != nil {
			return Manifest{}, err
		}
	}

	data, err := dl.get(ctx, version, ManifestAsset, MaxManifestSize)
	if err != nil {
		return Manifest{}, err
	}

	sig, err := dl.get(ctx, version, SignatureAsset, MaxSignatureSize)
	if err != nil {
		return Manifest{}, err
	}

	man, err := VerifyManifest(data, sig, keys)
	if err != nil {
		return Manifest{}, fmt.Errorf("release %s: %w", version, err)
	}

	if man.Version != version {
		return Manifest{}, fmt.Errorf("release %s: %w %s", version, errManifestVersion, man.Version)
	}

	return man, nil
}

// Download fetches the binary for platform listed in m (which must come from
// Fetch or VerifyManifest), checks its SHA-256 and atomically writes it to
// destPath with mode 0755.
func (dl *Downloader) Download(
	ctx context.Context,
	man Manifest,
	platform, destPath string,
) (err error) {
	asset, ok := man.Asset(platform)
	if !ok {
		return fmt.Errorf("release %s has %w %s", man.Version, errNoAsset, platform)
	}

	err = man.Validate()
	if err != nil {
		return err
	}

	rc, err := dl.open(ctx, man.Version, asset.Name)
	if err != nil {
		return err
	}
	defer rc.Close()

	dir := filepath.Dir(destPath)

	err = os.MkdirAll(dir, dirMode)
	if err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}

	tmp, err := os.CreateTemp(dir, ".download-*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tmp.Close()
			_ = os.Remove(tmp.Name())
		}
	}()

	sum := sha256.New()

	n, err := io.Copy(io.MultiWriter(tmp, sum), io.LimitReader(rc, MaxBinarySize+1))
	if err != nil {
		return fmt.Errorf("download %s: %w", asset.Name, err)
	}

	if n > MaxBinarySize {
		return fmt.Errorf("%s %w %d bytes", asset.Name, errExceeds, int64(MaxBinarySize))
	}

	if got := hex.EncodeToString(sum.Sum(nil)); !strings.EqualFold(got, asset.SHA256) {
		return fmt.Errorf("%w for %s", errSHA256Mismatch, asset.Name)
	}

	err = tmp.Chmod(binaryMode)
	if err != nil {
		return fmt.Errorf("chmod: %w", err)
	}

	err = tmp.Sync()
	if err != nil {
		return fmt.Errorf("sync: %w", err)
	}

	err = tmp.Close()
	if err != nil {
		return fmt.Errorf("close: %w", err)
	}

	err = os.Rename(tmp.Name(), destPath)
	if err != nil {
		return fmt.Errorf("install %s: %w", destPath, err)
	}

	return nil
}

func (dl *Downloader) client() *http.Client {
	if dl.Client != nil {
		return dl.Client
	}

	return http.DefaultClient
}

func (dl *Downloader) assetURL(version, name string) (string, error) {
	_, err := ParseVersion(version)
	if err != nil {
		return "", err
	}

	base := dl.BaseURL
	if base == "" {
		base = DefaultBaseURL
	}

	if !strings.HasSuffix(base, "/") {
		base += "/"
	}

	return base + version + "/" + name, nil
}

func (dl *Downloader) get(ctx context.Context, version, name string, limit int64) ([]byte, error) {
	rc, err := dl.open(ctx, version, name)
	if err != nil {
		return nil, err
	}
	defer rc.Close()

	data, err := io.ReadAll(io.LimitReader(rc, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", name, err)
	}

	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s %w %d bytes", name, errExceeds, limit)
	}

	return data, nil
}

func (dl *Downloader) open(ctx context.Context, version, name string) (io.ReadCloser, error) {
	u, err := dl.assetURL(version, name)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}

	resp, err := dl.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", name, err)
	}

	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()

		return nil, fmt.Errorf("download %s: %w %d", name, errHTTPStatus, resp.StatusCode)
	}

	return resp.Body, nil
}
