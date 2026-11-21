package hub

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zekihan/t3-mesh/internal/hub/kube"
)

func TestLastSeenRestoresAndRetriesConflict(t *testing.T) {
	harness := newEnv(t)
	api := &stateAPI{t: t, previous: time.Now().UTC().Add(-time.Hour).Truncate(time.Second)}

	fake := httptest.NewServer(http.HandlerFunc(api.serve))
	defer fake.Close()

	tokenPath := filepath.Join(t.TempDir(), "token")

	err := os.WriteFile(tokenPath, []byte("fake"), 0o600)
	if err != nil {
		t.Fatal(err)
	}

	client, err := kube.New(fake.URL, "", tokenPath, fake.Client())
	if err != nil {
		t.Fatal(err)
	}

	store := NewLastSeenStore(harness.srv, client, "mesh")
	store.Load(t.Context())

	resp := httptest.NewRecorder()
	harness.srv.writeOffline(resp, "devbox")

	if resp.Code != http.StatusBadGateway ||
		resp.Header().Get("Content-Type") != "text/html; charset=utf-8" ||
		!strings.Contains(resp.Body.String(), `<meta http-equiv="refresh" content="15">`) ||
		!strings.Contains(resp.Body.String(), api.previous.Format(time.RFC3339)) {
		t.Fatalf("offline page: %d %v %s", resp.Code, resp.Header(), resp.Body)
	}

	devbox := harness.connect("agent-devbox", "devbox-body")

	err = harness.srv.Disconnect("devbox")
	if err != nil {
		t.Fatal(err)
	}

	devbox.waitClosed()

	store.Flush(t.Context())
	store.Flush(t.Context())

	if puts, reads := api.updates.Load(), api.reads.Load(); puts != 2 || reads != 3 {
		t.Fatalf("API got %d reads and %d updates, want 3 reads and 2 updates", reads, puts)
	}
}

type stateAPI struct {
	previous time.Time
	t        *testing.T
	reads    atomic.Int32
	updates  atomic.Int32
}

func (api *stateAPI) serve(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/api/v1/namespaces/mesh/configmaps/t3-mesh-hub-state" ||
		r.Header.Get("Authorization") != "Bearer fake" {
		api.t.Errorf("unexpected API request: %s %s", r.Method, r.URL)
		w.WriteHeader(http.StatusBadRequest)

		return
	}

	switch r.Method {
	case http.MethodGet:
		api.reads.Add(1)
		revision := api.updates.Load() + 1
		seen := fmt.Sprintf(`{"devbox":%q}`, api.previous.Format(time.RFC3339))
		fmt.Fprintf(
			w,
			`{"metadata":{"resourceVersion":"%d","labels":{"keep":"yes"}},`+
				`"data":{"ownedByOther":"keep","lastSeen.json":%q}}`,
			revision, seen,
		)
	case http.MethodPut:
		if api.updates.Add(1) == 1 {
			w.WriteHeader(http.StatusConflict)

			return
		}

		api.checkUpdate(r)
		fmt.Fprintln(w, "{}")
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (api *stateAPI) checkUpdate(r *http.Request) {
	var body struct {
		Data     map[string]string `json:"data"`
		Metadata struct {
			Labels  map[string]string `json:"labels"`
			Version string            `json:"resourceVersion"`
		} `json:"metadata"`
	}

	err := json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		api.t.Error(err)

		return
	}

	if body.Metadata.Version != "2" || body.Metadata.Labels["keep"] != "yes" ||
		body.Data["ownedByOther"] != "keep" {
		api.t.Errorf("update dropped metadata or another data key: %+v", body)
	}

	var seen map[string]time.Time

	err = json.Unmarshal([]byte(body.Data[lastSeenKey]), &seen)
	if err != nil || !seen["devbox"].After(api.previous) {
		api.t.Errorf("updated last seen: %v, err = %v", seen, err)
	}
}
