package hubconfig

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zekihan/t3-mesh/internal/hub/kube"
)

func TestConfigMapWatchAndMountFallback(t *testing.T) {
	fix := newFixture(t, goodConfig, time.Now().Add(time.Hour*24*90))

	watcher, err := NewWatcher(fix.p, nil)
	if err != nil {
		t.Fatal(err)
	}

	start := time.Now()

	var offset atomic.Int64

	watcher.now = func() time.Time { return start.Add(time.Duration(offset.Load())) }

	changed := strings.Replace(goodConfig, "v0.3.0", "v0.9.9", 1)
	active, drop := make(chan struct{}), make(chan struct{})

	fake := configMapAPI(t, changed, drop)
	defer fake.Close()

	write(t, fix.root, "token", "fake")

	client, err := kube.New(fake.URL, "", filepath.Join(fix.root, "token"), fake.Client())
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})

	defer func() { cancel(); <-done }()

	go func() {
		defer close(done)

		watcher.watchConfigMap(ctx, client, "hub", "hub-config", &watcher.configSource,
			func(_, next *Snapshot) {
				if next.Release.Version == "v0.9.9" {
					select {
					case <-active:
					default:
						close(active)
					}
				}
			})
	}()

	select {
	case <-active:
	case <-time.After(5 * time.Second):
		t.Fatal("watch did not apply API update")
	}

	close(drop)
	waitForWatchDisconnect(t, watcher)

	// The mount skips the API revision and projects a newer revocation.
	revoked := strings.Replace(goodConfig, "[z-old]", "[z-old, z-phone]", 1)
	write(t, fix.p.ConfigDir, ConfigFile, revoked)
	offset.Store(int64(watchGracePeriod - time.Second))
	watcher.Reload(nil)

	if got := watcher.Current().Release.Version; got != "v0.9.9" {
		t.Fatalf("mount won during grace period: %s", got)
	}

	// The stale alert samples the mount even while the API snapshot is retained.
	if stale, reason := watcher.Stale(watcher.now().Add(StalePolicyAfter + time.Second)); !stale {
		t.Errorf("mounted policy difference did not raise stale alert: %s", reason)
	}

	offset.Store(int64(watchGracePeriod))
	watcher.Reload(nil)

	if got := watcher.Current(); !slices.Contains(got.Revocations.DisabledIdentities, "z-phone") {
		t.Errorf("mount did not apply newer revocation at grace expiry: %+v", got.Revocations)
	}

	if stale, reason := watcher.Stale(watcher.now().Add(StalePolicyAfter + time.Second)); stale {
		t.Errorf("stale after applying mounted policy: %s", reason)
	}
}

func waitForWatchDisconnect(t *testing.T, watcher *Watcher) {
	t.Helper()

	// Wait for the API watch to record the disconnect.
	deadline := time.Now().Add(5 * time.Second)

	for {
		watcher.reloadMu.Lock()
		live := watcher.configSource.live != nil
		watcher.reloadMu.Unlock()

		if !live {
			return
		}

		if time.Now().After(deadline) {
			t.Fatal("watch did not disconnect")
		}

		<-time.After(time.Millisecond)
	}
}

func configMapAPI(t *testing.T, changed string, drop <-chan struct{}) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		if r.URL.Path != "/api/v1/namespaces/hub/configmaps" ||
			query.Get("fieldSelector") != "metadata.name=hub-config" ||
			r.Header.Get("Authorization") != "Bearer fake" {
			t.Errorf("unexpected API request: %s", r.URL)
			w.WriteHeader(http.StatusBadRequest)

			return
		}

		select {
		case <-drop:
			w.WriteHeader(http.StatusForbidden)

			return
		default:
		}

		item := kube.ConfigMap{
			Metadata: kube.Metadata{Name: "hub-config", ResourceVersion: "1"},
			Data:     map[string]string{ConfigFile: goodConfig},
		}

		switch query.Get("watch") {
		case "":
			fmt.Fprintf(
				w,
				`{"metadata":{"resourceVersion":"2"},"items":[%s]}`,
				jsonForTest(t, item),
			)
		case "true":
			if query.Get("resourceVersion") != "2" {
				t.Errorf("watch query: %v", query)
			}

			item.Data[ConfigFile] = changed
			fmt.Fprintf(w, "{\"type\":\"MODIFIED\",\"object\":%s}\n", jsonForTest(t, item))

			flushErr := http.NewResponseController(w).Flush()
			if flushErr != nil {
				t.Error(flushErr)
			}

			select {
			case <-drop:
			case <-r.Context().Done():
			}
		}
	}))
}

func jsonForTest(t *testing.T, item kube.ConfigMap) []byte {
	t.Helper()

	data, err := json.Marshal(item)
	if err != nil {
		t.Error(err)
	}

	return data
}
