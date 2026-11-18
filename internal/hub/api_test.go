package hub

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

const apiHost = "hub.mesh.test"

type apiResponse struct {
	header http.Header
	body   string
	status int
}

func (harness *env) api(
	method, host, viewer, fp string,
	notAfter time.Time,
	path string,
) apiResponse {
	harness.t.Helper()

	req, _ := http.NewRequestWithContext(
		harness.t.Context(),
		method,
		harness.viewer.URL+path,
		http.NoBody,
	)
	req.Host = host
	setViewerHeaders(req.Header, viewer, fp, notAfter)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		harness.t.Fatal(err)
	}

	defer func() { _ = resp.Body.Close() }()

	b, _ := io.ReadAll(resp.Body)

	return apiResponse{status: resp.StatusCode, body: string(b), header: resp.Header}
}

func (harness *env) machines(viewer string) apiResponse {
	harness.t.Helper()

	return harness.api(http.MethodGet, apiHost, viewer, viewerFP, farFuture, "/api/v1/machines")
}

func decodeMachines(t *testing.T, body string) []apiMachine {
	t.Helper()

	var doc apiMachines

	err := json.Unmarshal([]byte(body), &doc)
	if err != nil {
		t.Fatalf("decode %q: %v", body, err)
	}

	return doc.Machines
}

func TestAPIMachines(t *testing.T) {
	harness := newEnv(t)
	harness.setConfig(cfgOpts{api: []string{"z-phone", "z-viewer", "z-other"}})
	harness.connect("agent-devbox", "devbox-body")

	resp := harness.machines("z-phone")
	if resp.status != http.StatusOK {
		t.Fatalf("status %d: %s", resp.status, resp.body)
	}

	if resp.header.Get("Cache-Control") != "no-store" ||
		resp.header.Get("Content-Type") != "application/json" {
		t.Fatalf("headers = %v", resp.header)
	}

	got := decodeMachines(t, resp.body)
	if len(got) != 2 ||
		got[0].Name != "devbox" || got[1].Name != "z-arch" {
		t.Fatalf("machines = %+v", got)
	}

	if !got[0].Online || got[0].ViewerURL != "https://t3.devbox.mesh.test" ||
		got[0].LastSeen == nil {
		t.Errorf("devbox = %+v", got[0])
	}

	_, err := time.Parse(time.RFC3339, *got[0].LastSeen)
	if err != nil {
		t.Errorf("lastSeen %q: %v", *got[0].LastSeen, err)
	}

	if got[1].Online || got[1].LastSeen != nil ||
		got[1].ViewerURL != "https://t3.z-arch.mesh.test" {
		t.Errorf("z-arch = %+v", got[1])
	}
}

func TestAPIMachinesNeverSeenIsNull(t *testing.T) {
	harness := newEnv(t)
	harness.setConfig(cfgOpts{api: []string{"z-phone"}})

	var raw struct {
		Machines []map[string]any `json:"machines"`
	}

	err := json.Unmarshal([]byte(harness.machines("z-phone").body), &raw)
	if err != nil {
		t.Fatal(err)
	}

	if v, ok := raw.Machines[1]["lastSeen"]; !ok || v != nil {
		t.Errorf("lastSeen = %v, present %v", v, ok)
	}
}

func TestAPIMachinesFilteredPerCaller(t *testing.T) {
	harness := newEnv(t)
	harness.setConfig(cfgOpts{api: []string{"z-phone", "z-viewer", "z-other"}})

	// z-viewer is listed on mesh-t3-devbox only; z-other on no machine.
	got := decodeMachines(t, harness.machines("z-viewer").body)
	if len(got) != 1 || got[0].Name != "devbox" {
		t.Errorf("z-viewer sees %+v", got)
	}

	resp := harness.machines("z-other")
	if resp.status != http.StatusOK || resp.body != "{\"machines\":[]}\n" {
		t.Errorf("z-other: %d %q", resp.status, resp.body)
	}
}

func TestAPIMachinesLastSeenAfterDisconnect(t *testing.T) {
	harness := newEnv(t)
	harness.setConfig(cfgOpts{api: []string{"z-phone"}})

	fakeAgent := harness.connect("agent-z-arch", "")
	fakeAgent.close()

	eventually(t, func() bool {
		got := decodeMachines(t, harness.machines("z-phone").body)

		return !got[1].Online && got[1].LastSeen != nil
	})
}

func TestAPIFollowsConfigReload(t *testing.T) {
	harness := newEnv(t)
	harness.setConfig(cfgOpts{api: []string{"z-phone"}})

	if resp := harness.machines("z-phone"); resp.status != http.StatusOK {
		t.Fatalf("status %d", resp.status)
	}

	harness.setConfig(cfgOpts{api: []string{"z-viewer"}})

	if resp := harness.machines("z-phone"); resp.status != http.StatusForbidden {
		t.Fatalf("removed caller got %d", resp.status)
	}
}

func TestAPIRejections(t *testing.T) {
	harness := newEnv(t)
	harness.setConfig(cfgOpts{api: []string{"z-phone"}})

	cases := []struct {
		notAfter time.Time
		name     string
		viewer   string
		fp       string
	}{
		{name: "no viewer header", viewer: "", fp: viewerFP, notAfter: farFuture},
		{name: "no fingerprint", viewer: "z-phone", fp: "", notAfter: farFuture},
		{name: "no not-after", viewer: "z-phone", fp: viewerFP},
		{name: "bad fingerprint", viewer: "z-phone", fp: "xyz", notAfter: farFuture},
		{name: "bare name", viewer: "=z-phone", fp: viewerFP, notAfter: farFuture},
		{name: "foreign URI", viewer: "=urn:other:z-phone", fp: viewerFP, notAfter: farFuture},
		{name: "agent identity", viewer: "agent-z-arch", fp: viewerFP, notAfter: farFuture},
		{
			name: "expired", viewer: "z-phone", fp: viewerFP,
			notAfter: time.Now().Add(-time.Minute),
		},
		{name: "valid but unlisted", viewer: "z-viewer", fp: viewerFP, notAfter: farFuture},
		{name: "valid but unknown", viewer: "z-nobody", fp: viewerFP, notAfter: farFuture},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Every path and method is refused alike, so nothing leaks to a
			// caller that is not admitted.
			for _, path := range []string{"/api/v1/machines", "/api/v1/nope", "/"} {
				resp := harness.api(http.MethodGet, apiHost, tc.viewer, tc.fp, tc.notAfter, path)
				if resp.status != http.StatusForbidden {
					t.Errorf("GET %s: status %d, want 403", path, resp.status)
				}

				if resp.header.Get("Cache-Control") != "no-store" {
					t.Errorf("GET %s: Cache-Control = %q", path, resp.header.Get("Cache-Control"))
				}
			}

			resp := harness.api(
				http.MethodPost, apiHost, tc.viewer, tc.fp, tc.notAfter, "/api/v1/machines",
			)
			if resp.status != http.StatusForbidden {
				t.Errorf("POST: status %d, want 403", resp.status)
			}
		})
	}
}

func TestAPIRefusesRevokedCallers(t *testing.T) {
	harness := newEnv(t)
	harness.setConfig(cfgOpts{api: []string{"z-phone"}})

	if resp := harness.machines("z-phone"); resp.status != http.StatusOK {
		t.Fatalf("status %d", resp.status)
	}

	harness.setConfig(cfgOpts{api: []string{"z-phone"}, blocked: []string{viewerFP}})

	if resp := harness.machines("z-phone"); resp.status != http.StatusForbidden {
		t.Errorf("blocked leaf got %d", resp.status)
	}

	harness.setConfig(cfgOpts{api: []string{"z-phone"}, disabled: []string{"z-phone"}})

	if resp := harness.machines("z-phone"); resp.status != http.StatusForbidden {
		t.Errorf("disabled identity got %d", resp.status)
	}
}

func TestAPIRoutingAndMethods(t *testing.T) {
	harness := newEnv(t)
	harness.setConfig(cfgOpts{api: []string{"z-phone"}})

	for _, path := range []string{"/", "/api", "/api/v1", "/api/v1/machines/", "/api/v1/fleet", "/status"} {
		resp := harness.api(http.MethodGet, apiHost, "z-phone", viewerFP, farFuture, path)
		if resp.status != http.StatusNotFound {
			t.Errorf("GET %s: status %d, want 404", path, resp.status)
		}

		if resp.header.Get("Cache-Control") != "no-store" {
			t.Errorf("GET %s: Cache-Control = %q", path, resp.header.Get("Cache-Control"))
		}
	}

	for _, method := range []string{
		http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch, http.MethodHead,
	} {
		resp := harness.api(method, apiHost, "z-phone", viewerFP, farFuture, "/api/v1/machines")
		if resp.status != http.StatusMethodNotAllowed ||
			resp.header.Get("Allow") != http.MethodGet {
			t.Errorf("%s: status %d, Allow %q", method, resp.status, resp.header.Get("Allow"))
		}
	}

	// Host matching ignores case, a trailing dot and a port.
	for _, host := range []string{"HUB.mesh.test", "hub.mesh.test.", "hub.mesh.test:443"} {
		resp := harness.api(
			http.MethodGet, host, "z-phone", viewerFP, farFuture, "/api/v1/machines",
		)
		if resp.status != http.StatusOK {
			t.Errorf("host %q: status %d", host, resp.status)
		}
	}
}

func TestAPIHostIsNotAViewerHost(t *testing.T) {
	harness := newEnv(t)
	harness.setConfig(cfgOpts{api: []string{"z-phone"}})
	harness.connect("agent-devbox", "devbox-body")

	// On a viewer host the same path goes to the machine's service (the test
	// backend answers 404 for it), never to the API, which would answer JSON.
	status, body := harness.get(
		"t3.devbox.mesh.test", "z-phone", viewerFP, farFuture, "/api/v1/machines",
	)
	if status != http.StatusNotFound || body != "404 page not found\n" {
		t.Errorf("viewer host: %d %q", status, body)
	}

	status, body = harness.get("t3.devbox.mesh.test", "z-phone", viewerFP, farFuture, "/hdr")
	if status != http.StatusOK || !strings.HasPrefix(body, "devbox-body") {
		t.Errorf("viewer host /hdr: %d %q", status, body)
	}
}
