package hub

import (
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/zekihan/t3-mesh/internal/hub/hubconfig"
	"github.com/zekihan/t3-mesh/internal/proto"
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

func (harness *env) fleet(viewer, realIP string) apiResponse {
	harness.t.Helper()

	req, _ := http.NewRequestWithContext(
		harness.t.Context(),
		http.MethodGet,
		harness.viewer.URL+"/api/v1/fleet",
		http.NoBody,
	)
	req.Host = apiHost
	setViewerHeaders(req.Header, viewer, viewerFP, farFuture)

	if realIP != "" {
		req.Header.Set("X-Real-IP", realIP)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		harness.t.Fatal(err)
	}

	defer func() { _ = resp.Body.Close() }()

	b, _ := io.ReadAll(resp.Body)

	return apiResponse{status: resp.StatusCode, body: string(b), header: resp.Header}
}

func decodeFleet(t *testing.T, body string) apiFleet {
	t.Helper()

	var doc apiFleet

	err := json.Unmarshal([]byte(body), &doc)
	if err != nil {
		t.Fatalf("decode %q: %v", body, err)
	}

	return doc
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
			for _, path := range []string{"/api/v1/machines", "/api/v1/fleet", "/api/v1/nope", "/"} {
				resp := harness.api(http.MethodGet, apiHost, tc.viewer, tc.fp, tc.notAfter, path)
				if resp.status != http.StatusForbidden {
					t.Errorf("GET %s: status %d, want 403", path, resp.status)
				}

				if resp.header.Get("Cache-Control") != "no-store" {
					t.Errorf("GET %s: Cache-Control = %q", path, resp.header.Get("Cache-Control"))
				}
			}

			for _, path := range []string{"/api/v1/machines", "/api/v1/fleet"} {
				resp := harness.api(
					http.MethodPost, apiHost, tc.viewer, tc.fp, tc.notAfter, path,
				)
				if resp.status != http.StatusForbidden {
					t.Errorf("POST %s: status %d, want 403", path, resp.status)
				}
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

	for _, path := range []string{"/", "/api", "/api/v1", "/api/v1/machines/", "/api/v1/fleet/", "/status"} {
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
		for _, path := range []string{"/api/v1/machines", "/api/v1/fleet"} {
			resp := harness.api(method, apiHost, "z-phone", viewerFP, farFuture, path)
			if resp.status != http.StatusMethodNotAllowed ||
				resp.header.Get("Allow") != http.MethodGet ||
				resp.header.Get("Cache-Control") != "no-store" {
				t.Errorf(
					"%s %s: status %d, Allow %q",
					method, path, resp.status, resp.header.Get("Allow"),
				)
			}
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

// fleetFixture connects devbox with a certificate that is about to expire and an
// agent that runs a version other than the desired one, and leaves z-arch never
// seen, so the fleet has a firing alert of each kind on both machines.
func fleetFixture(t *testing.T) *env {
	t.Helper()

	harness := newEnv(t)
	harness.setConfig(cfgOpts{api: []string{"z-phone", "z-viewer", "z-other"}, release: "v0.5.0"})

	cert := harness.newCert("agent-devbox", time.Now().Add(5*24*time.Hour))

	fakeAgent, err := harness.connectWith("agent-devbox", &cert, "devbox-body")
	if err != nil {
		t.Fatal(err)
	}

	err = fakeAgent.ctrl.Send(proto.Status{Version: "v0.4.0", RulesRevision: "r1"})
	if err != nil {
		t.Fatal(err)
	}

	eventually(t, func() bool {
		var st statusDoc
		getJSON(t, harness.ops.URL+"/status", &st)

		return st.Machines["devbox"].Version == "v0.4.0"
	})

	harness.offset.Store(int64(61 * time.Minute))

	return harness
}

func firingNames(alerts map[string]bool) []string {
	out := []string{}

	for name, firing := range alerts {
		if firing {
			out = append(out, name)
		}
	}

	slices.Sort(out)

	return out
}

func fmtStatusTime(ts *time.Time) string {
	if ts == nil {
		return ""
	}

	return ts.UTC().Format(time.RFC3339)
}

func derefOr(s *string) string {
	if s == nil {
		return ""
	}

	return *s
}

func TestAPIFleetMatchesStatus(t *testing.T) {
	harness := fleetFixture(t)

	resp := harness.fleet("z-phone", "127.0.0.9")
	if resp.status != http.StatusOK {
		t.Fatalf("status %d: %s", resp.status, resp.body)
	}

	if resp.header.Get("Cache-Control") != "no-store" ||
		resp.header.Get("Content-Type") != "application/json" {
		t.Fatalf("headers = %v", resp.header)
	}

	var st statusDoc
	getJSON(t, harness.ops.URL+"/status", &st)

	doc := decodeFleet(t, resp.body)
	if len(doc.Machines) != 2 || doc.Machines[0].Name != "devbox" ||
		doc.Machines[1].Name != "z-arch" {
		t.Fatalf("machines = %+v", doc.Machines)
	}

	for _, got := range doc.Machines {
		want := st.Machines[got.Name]

		if got.Online != want.Connected {
			t.Errorf("%s online = %v, status %v", got.Name, got.Online, want.Connected)
		}

		if wantAlerts := firingNames(want.Alerts); !slices.Equal(got.Alerts, wantAlerts) {
			t.Errorf("%s alerts = %v, status %v", got.Name, got.Alerts, wantAlerts)
		}

		if got.ViewerURL != "https://t3."+got.Name+".mesh.test" {
			t.Errorf("%s viewerUrl = %q", got.Name, got.ViewerURL)
		}
	}

	devboxStatus := st.Machines["devbox"]

	checkFleetDevbox(t, &doc.Machines[0], &devboxStatus)
}

func checkFleetDevbox(t *testing.T, devbox *apiFleetMachine, want *machineStatus) {
	t.Helper()

	if !devbox.Online || derefOr(devbox.AgentVersion) != "v0.4.0" {
		t.Errorf("devbox = %+v", devbox)
	}

	if got := derefOr(devbox.CertNotAfter); got == "" || got != fmtStatusTime(want.CertNotAfter) {
		t.Errorf("certNotAfter = %q, status %v", got, want.CertNotAfter)
	}

	if derefOr(devbox.Tunnel.Path) != "LAN" || want.Path != "LAN" {
		t.Errorf("tunnel path = %v, status %q", devbox.Tunnel.Path, want.Path)
	}

	since := derefOr(devbox.Tunnel.ConnectedSince)
	if since == "" || since != fmtStatusTime(want.ConnectedSince) {
		t.Errorf("connectedSince = %q, status %v", since, want.ConnectedSince)
	}

	seen := derefOr(devbox.LastSeen)
	if seen == "" || seen != fmtStatusTime(want.LastSeen) {
		t.Errorf("lastSeen = %q, status %v", seen, want.LastSeen)
	}

	if !slices.Equal(devbox.Alerts, []string{"cert-expiry", "update-failed"}) {
		t.Errorf("devbox alerts = %v", devbox.Alerts)
	}
}

func TestAPIFleetOfflineMachine(t *testing.T) {
	harness := fleetFixture(t)

	var raw struct {
		Machines []map[string]any `json:"machines"`
	}

	err := json.Unmarshal([]byte(harness.fleet("z-phone", "").body), &raw)
	if err != nil {
		t.Fatal(err)
	}

	arch := raw.Machines[1]

	for _, key := range []string{"lastSeen", "agentVersion", "certNotAfter"} {
		if v, ok := arch[key]; !ok || v != nil {
			t.Errorf("z-arch %s = %v, present %v", key, v, ok)
		}
	}

	tun, _ := arch["tunnel"].(map[string]any)
	for _, key := range []string{"path", "connectedSince"} {
		if v, ok := tun[key]; !ok || v != nil {
			t.Errorf("z-arch tunnel.%s = %v, present %v", key, v, ok)
		}
	}

	alerts, _ := arch["alerts"].([]any)
	if len(alerts) != 1 || alerts[0] != "disconnected" {
		t.Errorf("z-arch alerts = %v", arch["alerts"])
	}

	if arch["online"] != false {
		t.Errorf("z-arch online = %v", arch["online"])
	}
}

func TestAPIFleetNoAlertsIsEmptyArray(t *testing.T) {
	harness := newEnv(t)
	harness.setConfig(cfgOpts{api: []string{"z-phone"}})
	harness.connect("agent-devbox", "devbox-body")

	body := harness.fleet("z-phone", "").body
	if !strings.Contains(body, `"alerts":[]`) {
		t.Errorf("body = %s", body)
	}

	doc := decodeFleet(t, body)
	if len(doc.Machines[0].Alerts) != 0 || doc.Machines[0].Alerts == nil {
		t.Errorf("alerts = %#v", doc.Machines[0].Alerts)
	}
}

func TestAPIFleetAfterDisconnect(t *testing.T) {
	harness := newEnv(t)
	harness.setConfig(cfgOpts{api: []string{"z-phone"}})

	harness.connect("agent-devbox", "devbox-body").close()

	eventually(t, func() bool {
		got := decodeFleet(t, harness.fleet("z-phone", "").body).Machines[0]

		return !got.Online && got.LastSeen != nil && got.Tunnel.Path == nil &&
			got.Tunnel.ConnectedSince == nil
	})
}

func TestAPIFleetFilteredPerCaller(t *testing.T) {
	harness := newEnv(t)
	harness.setConfig(cfgOpts{api: []string{"z-phone", "z-viewer", "z-other"}})

	// z-viewer is listed on mesh-t3-devbox only; z-other on no machine.
	got := decodeFleet(t, harness.fleet("z-viewer", "").body).Machines
	if len(got) != 1 || got[0].Name != "devbox" {
		t.Errorf("z-viewer sees %+v", got)
	}

	resp := harness.fleet("z-other", "127.0.0.1")
	if resp.status != http.StatusOK ||
		resp.body != "{\"caller\":{\"path\":\"LAN\"},\"machines\":[]}\n" {
		t.Errorf("z-other: %d %q", resp.status, resp.body)
	}

	resp = harness.fleet("z-other", "")
	if resp.body != "{\"caller\":{\"path\":null},\"machines\":[]}\n" {
		t.Errorf("z-other without X-Real-IP: %q", resp.body)
	}
}

func TestAPIFleetCallerPath(t *testing.T) {
	harness := newEnv(t)
	harness.setConfig(cfgOpts{api: []string{"z-phone"}})

	// The test config's only home CIDR is 127.0.0.0/8.
	cases := []struct {
		name string
		ip   string
		want string
	}{
		{name: "ipv4 inside", ip: "127.0.0.1", want: "LAN"},
		{name: "ipv4 outside", ip: "203.0.113.7", want: "OCI"},
		{name: "ipv4-mapped inside", ip: "::ffff:127.0.0.1", want: "LAN"},
		{name: "ipv6 outside", ip: "2001:db8::1", want: "OCI"},
		{name: "ipv6 loopback outside", ip: "::1", want: "OCI"},
		{name: "padded", ip: " 127.0.0.1 ", want: "LAN"},
		{name: "missing", ip: "", want: ""},
		{name: "garbage", ip: "not-an-ip", want: ""},
		{name: "with port", ip: "127.0.0.1:443", want: ""},
		{name: "list", ip: "127.0.0.1, 203.0.113.7", want: ""},
		{name: "cidr", ip: "127.0.0.0/8", want: ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := harness.fleet("z-phone", tc.ip)
			if resp.status != http.StatusOK {
				t.Fatalf("status %d", resp.status)
			}

			got := decodeFleet(t, resp.body).Caller.Path

			switch {
			case tc.want == "" && got != nil:
				t.Errorf("path = %q, want null", *got)
			case tc.want != "" && (got == nil || *got != tc.want):
				t.Errorf("path = %v, want %q", got, tc.want)
			}
		})
	}
}

func TestAPIFleetCallerPathIPv6Home(t *testing.T) {
	harness := newEnv(t)
	writeFile(
		t,
		filepath.Join(harness.paths.ConfigDir, hubconfig.ConfigFile),
		strings.Replace(
			cfgOpts{api: []string{"z-phone"}}.yaml(),
			"[127.0.0.0/8]", "[127.0.0.0/8, \"fd12:3456:789a::/48\"]", 1,
		),
	)
	harness.watcher.Reload(harness.srv.OnConfigChange)

	for ip, want := range map[string]string{
		"fd12:3456:789a:1::81": "LAN",
		"fd12:3456:789b::1":    "OCI",
	} {
		got := decodeFleet(t, harness.fleet("z-phone", ip).body).Caller.Path
		if got == nil || *got != want {
			t.Errorf("%s: path = %v, want %s", ip, got, want)
		}
	}
}

func TestAPIFleetIgnoresPeerAddress(t *testing.T) {
	harness := newEnv(t)
	harness.setConfig(cfgOpts{api: []string{"z-phone"}})

	// The test client connects from 127.0.0.1, inside the home CIDR; only
	// X-Real-IP decides.
	got := decodeFleet(t, harness.fleet("z-phone", "198.51.100.1").body).Caller.Path
	if got == nil || *got != "OCI" {
		t.Errorf("path = %v, want OCI", got)
	}

	got = decodeFleet(t, harness.fleet("z-phone", "").body).Caller.Path
	if got != nil {
		t.Errorf("path = %v, want null without X-Real-IP", *got)
	}
}
