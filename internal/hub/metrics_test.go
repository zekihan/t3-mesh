package hub

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func scrapeOps(t *testing.T, handler http.Handler, path string) (int, string) {
	t.Helper()

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, path, http.NoBody)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	body, err := io.ReadAll(recorder.Result().Body)
	if err != nil {
		t.Fatal(err)
	}

	return recorder.Code, string(body)
}

func TestOpsServesMetrics(t *testing.T) {
	harness := newEnv(t)

	if code, _ := scrapeOps(t, harness.srv.OpsHandler(), "/status"); code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}

	code, body := scrapeOps(t, harness.srv.OpsHandler(), "/metrics")
	if code != http.StatusOK {
		t.Fatalf("metrics = %d, want 200", code)
	}

	for _, want := range []string{
		"t3mesh_connected_machines 0",
		"t3mesh_open_streams 0",
		"go_goroutines",
		"process_resident_memory_bytes",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics missing %q:\n%s", want, body)
		}
	}
}

func TestOpsMiddlewareCountsByRoute(t *testing.T) {
	harness := newEnv(t)
	reg := harness.srv.MetricsRegistry()

	handler := reg.Middleware(harness.srv.OpsHandler())

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/healthz", http.NoBody)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("healthz = %d, want 200", recorder.Code)
	}

	_, body := scrapeOps(t, reg.Handler(), "/metrics")

	for _, want := range []string{
		`http_requests_total{method="GET",route="/healthz",status="200"} 1`,
		`http_request_duration_seconds_bucket{method="GET",route="/healthz",status="200"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics missing %q:\n%s", want, body)
		}
	}
}

func TestViewerMiddlewareUsesFixedRoute(t *testing.T) {
	harness := newEnv(t)
	reg := harness.srv.MetricsRegistry()

	handler := reg.MiddlewareWithRoute("viewer", harness.srv.ViewerHandler())

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/anything", http.NoBody)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("viewer without headers = %d, want 403", recorder.Code)
	}

	_, body := scrapeOps(t, reg.Handler(), "/metrics")

	const want = `http_requests_total{method="GET",route="viewer",status="403"} 1`
	if !strings.Contains(body, want) {
		t.Errorf("metrics missing %q:\n%s", want, body)
	}
}
