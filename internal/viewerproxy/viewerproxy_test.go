package viewerproxy_test

import (
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"testing"

	"github.com/zekihan/t3-mesh/internal/viewerproxy"
)

// seen is what the backend received.
type seen struct {
	header http.Header
	host   string
}

func proxy(t *testing.T, strip bool) (string, chan seen) {
	t.Helper()

	got := make(chan seen, 1)

	backend := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got <- seen{header: r.Header.Clone(), host: r.Host}
	}))
	t.Cleanup(backend.Close)

	target, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatal(err)
	}

	front := httptest.NewServer(&httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			if strip {
				viewerproxy.StripClientForwarding(pr.Out.Header)
			}

			viewerproxy.Rewrite(pr)
			// The backend is not reachable under the viewer host name.
			pr.Out.URL.Host = target.Host
		},
	})
	t.Cleanup(front.Close)

	return front.URL, got
}

func send(t *testing.T, base string, hdr map[string]string) {
	t.Helper()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, base, http.NoBody)
	if err != nil {
		t.Fatal(err)
	}

	req.Host = "t3.z-arch.mesh.noqer.com"

	for k, v := range hdr {
		req.Header.Set(k, v)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	_ = resp.Body.Close()
}

var forged = map[string]string{
	"X-Mtls-Mesh-Viewer":      "urn:noqer:mtls:clients:z-phone",
	"X-Mtls-Anything":         "1",
	"Forwarded":               "for=203.0.113.9",
	"X-Forwarded-For":         "203.0.113.9",
	"X-Forwarded-Host":        "evil.example",
	"X-Forwarded-Proto":       "http",
	"X-Forwarded-Port":        "8080",
	"X-Forwarded-Server":      "evil",
	"X-Real-Ip":               "203.0.113.9",
	"X-Custom-Kept":           "yes",
	"X-Forwarded-Prefix-Like": "kept-or-not",
}

func TestRewriteKeepsHostAndSetsProto(t *testing.T) {
	t.Parallel()

	base, got := proxy(t, false)
	send(t, base, forged)

	res := <-got

	if res.host != "t3.z-arch.mesh.noqer.com" {
		t.Errorf("Host = %q, want it forwarded unchanged", res.host)
	}

	if v := res.header.Get("X-Forwarded-Proto"); v != "https" {
		t.Errorf("X-Forwarded-Proto = %q, want https", v)
	}

	dropped := []string{
		"X-Mtls-Mesh-Viewer", "X-Mtls-Anything", "Forwarded", "X-Forwarded-For", "X-Forwarded-Host",
	}

	for _, name := range dropped {
		if v := res.header.Get(name); v != "" {
			t.Errorf("%s = %q reached the backend", name, v)
		}
	}

	if v := res.header.Get("X-Custom-Kept"); v != "yes" {
		t.Errorf("unrelated header = %q, want it kept", v)
	}
}

func TestStripClientForwardingDropsEveryForwardedHeader(t *testing.T) {
	t.Parallel()

	base, got := proxy(t, true)
	send(t, base, forged)

	res := <-got

	for k := range res.header {
		switch k {
		case "Forwarded", "X-Real-Ip", "X-Mtls-Mesh-Viewer", "X-Mtls-Anything",
			"X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Port",
			"X-Forwarded-Server", "X-Forwarded-Prefix-Like":
			t.Errorf("%s reached the backend", k)
		}
	}

	if v := res.header.Get("X-Forwarded-Proto"); v != "https" {
		t.Errorf("X-Forwarded-Proto = %q, want https", v)
	}

	if res.header.Get("X-Custom-Kept") != "yes" {
		t.Error("unrelated header was dropped")
	}

	if res.host != "t3.z-arch.mesh.noqer.com" {
		t.Errorf("Host = %q", res.host)
	}
}
