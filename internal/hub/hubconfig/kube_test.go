package hubconfig

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
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
	// Wait for the watch to hand back to the mount before checking the fence.
	deadline := time.Now().Add(500 * time.Millisecond)

	for {
		watcher.reloadMu.Lock()
		live := watcher.configSource.live != nil
		watcher.reloadMu.Unlock()

		if !live {
			break
		}

		if time.Now().After(deadline) {
			t.Fatal("watch did not disconnect")
		}

		<-time.After(time.Millisecond)
	}

	watcher.Reload(nil)

	if got := watcher.Current().Release.Version; got != "v0.9.9" {
		t.Fatalf("lagging mount rolled back API version to %s", got)
	}

	write(t, fix.p.ConfigDir, ConfigFile, changed)
	watcher.Reload(nil)
	write(t, fix.p.ConfigDir, ConfigFile, goodConfig)
	watcher.Reload(nil)

	if got := watcher.Current().Release.Version; got != "v0.3.0" {
		t.Errorf("caught-up mount does not apply updates: %s", got)
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
