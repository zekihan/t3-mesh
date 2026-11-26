package release

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const testDownloadTimeout = 250 * time.Millisecond

func TestFetchTimeout(t *testing.T) {
	for _, asset := range []string{ManifestAsset, SignatureAsset} {
		t.Run(asset, func(t *testing.T) {
			srv := httptest.NewServer(
				http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if asset == SignatureAsset {
						if strings.HasSuffix(r.URL.Path, "/"+ManifestAsset) {
							_, _ = w.Write([]byte("{}"))

							return
						}

						// Send the signature headers and stall while reading the body.
						_ = http.NewResponseController(w).Flush()
					}

					<-r.Context().Done()
				}),
			)
			t.Cleanup(srv.Close)
			dl := &Downloader{BaseURL: srv.URL, ManifestTimeout: testDownloadTimeout}

			// Use a parent without a deadline so only the download can time out.
			errs := make(chan error, 1)

			go func() {
				_, err := dl.Fetch(t.Context(), "v1.2.3")
				errs <- err
			}()

			select {
			case err := <-errs:
				if !errors.Is(err, context.DeadlineExceeded) ||
					!strings.Contains(err.Error(), asset+":") {
					t.Fatalf("Fetch error = %v, want deadline exceeded for %s", err, asset)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("Fetch did not finish within its deadline")
			}
		})
	}
}

func TestDownloadTimeoutCleansUpPartialBinary(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("partial"))
		_ = http.NewResponseController(w).Flush()

		<-r.Context().Done()
	}))
	t.Cleanup(srv.Close)

	var man Manifest

	err := json.Unmarshal(manifestJSON(t, "v1.2.3", []byte("full binary")), &man)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	dest := filepath.Join(dir, "agent")
	dl := &Downloader{BaseURL: srv.URL, BinaryTimeout: testDownloadTimeout}

	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()

	err = dl.Download(ctx, man, PlatformLinuxAMD64, dest)
	if !errors.Is(err, context.DeadlineExceeded) || ctx.Err() != nil {
		t.Fatalf("Download error=%v parent error=%v, want binary deadline exceeded", err, ctx.Err())
	}

	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("download directory has entries %v, read error %v", entries, err)
	}
}
