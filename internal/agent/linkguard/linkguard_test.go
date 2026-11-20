package linkguard

import (
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
)

const port = 27301

var trusted = []string{DesktopOrigin}

func newRequest(t *testing.T, host string, headers map[string]string) *http.Request {
	t.Helper()

	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", http.NoBody)
	r.Host = host

	for k, v := range headers {
		r.Header.Set(k, v)
	}

	return r
}

func TestCheck(t *testing.T) {
	tests := []struct {
		headers map[string]string
		name    string
		host    string
		pass    bool
	}{
		{name: "native client, valid host, no headers", host: "127.0.0.1:27301", pass: true},
		{name: "localhost host", host: "localhost:27301", pass: true},
		{name: "localhost host uppercase", host: "LocalHost:27301", pass: true},
		{
			name: "same-origin fetch", host: "127.0.0.1:27301",
			headers: map[string]string{"Sec-Fetch-Site": "same-origin"}, pass: true,
		},
		{
			name: "navigation none", host: "127.0.0.1:27301",
			headers: map[string]string{"Sec-Fetch-Site": "none"}, pass: true,
		},
		{
			name: "origin 127.0.0.1", host: "127.0.0.1:27301",
			headers: map[string]string{"Origin": "http://127.0.0.1:27301"}, pass: true,
		},
		{
			name: "origin localhost", host: "localhost:27301",
			headers: map[string]string{"Origin": "http://localhost:27301"}, pass: true,
		},
		{
			name: "origin localhost uppercase", host: "localhost:27301",
			headers: map[string]string{"Origin": "http://LOCALHOST:27301"}, pass: true,
		},
		{
			name: "origin and same-origin together",
			host: "127.0.0.1:27301",
			headers: map[string]string{
				"Origin":         "http://127.0.0.1:27301",
				"Sec-Fetch-Site": "same-origin",
			},
			pass: true,
		},

		{name: "missing host", host: "", pass: false},
		{name: "host no port", host: "127.0.0.1", pass: false},
		{name: "host with trailing dot", host: "127.0.0.1.:27301", pass: false},
		{name: "host other port", host: "127.0.0.1:27302", pass: false},
		{name: "host default port", host: "127.0.0.1:80", pass: false},
		{name: "host other loopback", host: "127.0.0.2:27301", pass: false},
		{name: "host ipv6 loopback", host: "[::1]:27301", pass: false},
		{name: "host rebinding name", host: "evil.example:27301", pass: false},
		{name: "host localhost subdomain", host: "localhost.evil.example:27301", pass: false},
		{name: "host with userinfo-like", host: "127.0.0.1:27301@evil.example", pass: false},
		{name: "host lookalike prefix", host: "127.0.0.1:272011", pass: false},
		{name: "host public address", host: "192.168.1.5:27301", pass: false},

		{
			name: "origin null", host: "127.0.0.1:27301",
			headers: map[string]string{"Origin": "null"}, pass: false,
		},
		{
			name: "origin empty", host: "127.0.0.1:27301",
			headers: map[string]string{"Origin": ""}, pass: false,
		},
		{
			name: "origin https scheme", host: "127.0.0.1:27301",
			headers: map[string]string{"Origin": "https://127.0.0.1:27301"}, pass: false,
		},
		{
			name: "origin https localhost", host: "localhost:27301",
			headers: map[string]string{"Origin": "https://localhost:27301"}, pass: false,
		},
		{
			name: "origin other port", host: "127.0.0.1:27301",
			headers: map[string]string{"Origin": "http://127.0.0.1:27302"}, pass: false,
		},
		{
			name: "origin no port", host: "127.0.0.1:27301",
			headers: map[string]string{"Origin": "http://127.0.0.1"}, pass: false,
		},
		{
			name: "origin foreign", host: "127.0.0.1:27301",
			headers: map[string]string{"Origin": "http://evil.example"}, pass: false,
		},
		{
			name: "origin foreign with loopback suffix",
			host: "127.0.0.1:27301",
			headers: map[string]string{
				"Origin": "http://127.0.0.1:27301.evil.example",
			},
			pass: false,
		},
		{
			name: "origin trailing slash", host: "127.0.0.1:27301",
			headers: map[string]string{"Origin": "http://127.0.0.1:27301/"}, pass: false,
		},
		{
			name: "origin localhost on ip host", host: "127.0.0.1:27301",
			headers: map[string]string{"Origin": "http://localhost:27301"}, pass: true,
		},

		{
			name: "sec-fetch-site cross-site", host: "127.0.0.1:27301",
			headers: map[string]string{"Sec-Fetch-Site": "cross-site"}, pass: false,
		},
		{
			name: "sec-fetch-site cross-site no origin", host: "127.0.0.1:27301",
			headers: map[string]string{"Sec-Fetch-Site": "cross-site"}, pass: false,
		},
		{
			name: "sec-fetch-site same-site", host: "127.0.0.1:27301",
			headers: map[string]string{"Sec-Fetch-Site": "same-site"}, pass: false,
		},
		{
			name: "sec-fetch-site empty", host: "127.0.0.1:27301",
			headers: map[string]string{"Sec-Fetch-Site": ""}, pass: false,
		},
		{
			name: "sec-fetch-site garbage", host: "127.0.0.1:27301",
			headers: map[string]string{"Sec-Fetch-Site": "same-origin, cross-site"}, pass: false,
		},
		{
			name: "same-origin with foreign origin",
			host: "127.0.0.1:27301",
			headers: map[string]string{
				"Origin":         "http://evil.example",
				"Sec-Fetch-Site": "same-origin",
			},
			pass: false,
		},
		{
			name: "valid origin with cross-site",
			host: "127.0.0.1:27301",
			headers: map[string]string{
				"Origin":         "http://127.0.0.1:27301",
				"Sec-Fetch-Site": "cross-site",
			},
			pass: false,
		},
		{
			name: "valid host with bad origin and good sec-fetch-site", host: "localhost:27301",
			headers: map[string]string{"Origin": "null", "Sec-Fetch-Site": "none"}, pass: false,
		},
		{
			name: "desktop app cross-site fetch",
			host: "127.0.0.1:27301",
			headers: map[string]string{
				"Origin":         DesktopOrigin,
				"Sec-Fetch-Site": "cross-site",
			},
			pass: true,
		},
		{
			name:    "desktop origin with rebinding host",
			host:    "evil.example:27301",
			headers: map[string]string{"Origin": DesktopOrigin},
			pass:    false,
		},
		{
			name: "desktop-like origin is not trusted",
			host: "127.0.0.1:27301",
			headers: map[string]string{
				"Origin":         "t3code://app.evil.example",
				"Sec-Fetch-Site": "cross-site",
			},
			pass: false,
		},
		{
			name:    "web page with cross-site fetch and no origin",
			host:    "127.0.0.1:27301",
			headers: map[string]string{"Sec-Fetch-Site": "cross-site"},
			pass:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Check(newRequest(t, tt.host, tt.headers), port, trusted)
			if tt.pass && err != nil {
				t.Fatalf("Check rejected: %v", err)
			}

			if !tt.pass {
				if err == nil {
					t.Fatal("Check accepted")
				}

				if !errors.Is(err, ErrForbidden) {
					t.Fatalf("err = %v, want ErrForbidden", err)
				}
			}
		})
	}
}

func TestCheckTrustedOriginWithDefaultPort(t *testing.T) {
	tests := []struct {
		want   error
		name   string
		origin string
		allow  string
	}{
		{name: "http", origin: "http://ui.example.test", allow: "http://ui.example.test:80"},
		{name: "https", origin: "https://ui.example.test", allow: "https://ui.example.test:443"},
		{name: "https IPv6", origin: "https://[::1]", allow: "https://[::1]:443"},
		{
			name:   "padded port",
			origin: "https://ui.example.test",
			allow:  "https://ui.example.test:0443",
		},
		{
			name:   "different port",
			origin: "https://ui.example.test",
			allow:  "https://ui.example.test:8443",
			want:   ErrForbidden,
		},
		{
			name:   "different scheme",
			origin: "http://ui.example.test",
			allow:  "https://ui.example.test:443",
			want:   ErrForbidden,
		},
		{
			name:   "different host",
			origin: "https://other.example.test",
			allow:  "https://ui.example.test:443",
			want:   ErrForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newRequest(t, "127.0.0.1:27301", map[string]string{
				"Origin": tt.origin, "Sec-Fetch-Site": "cross-site",
			})

			err := Check(r, port, []string{tt.allow})
			if !errors.Is(err, tt.want) {
				t.Fatalf("Check = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestCheckWebSocketUpgrade(t *testing.T) {
	upgrade := func(host, origin string) *http.Request {
		r := newRequest(t, host, map[string]string{
			"Connection": "Upgrade",
			"Upgrade":    "websocket",
		})
		if origin != "" {
			r.Header.Set("Origin", origin)
		}

		return r
	}

	err := Check(upgrade("127.0.0.1:27301", ""), port, trusted)
	if err != nil {
		t.Fatalf("native websocket rejected: %v", err)
	}

	err = Check(upgrade("localhost:27301", "http://localhost:27301"), port, trusted)
	if err != nil {
		t.Fatalf("local websocket rejected: %v", err)
	}

	err = Check(upgrade("127.0.0.1:27301", "http://evil.example"), port, trusted)
	if err == nil {
		t.Fatal("foreign-origin websocket accepted")
	}

	err = Check(upgrade("127.0.0.1:27301", "null"), port, trusted)
	if err == nil {
		t.Fatal("null-origin websocket accepted")
	}
}

func TestCheckPortIsPartOfHost(t *testing.T) {
	r := newRequest(t, "127.0.0.1:27302", nil)

	err := Check(r, 27302, trusted)
	if err != nil {
		t.Fatalf("port 27302 rejected: %v", err)
	}

	err = Check(r, 27301, trusted)
	if err == nil {
		t.Fatal("request for port 27302 accepted on port 27301")
	}
}

func TestMiddleware(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true

		w.WriteHeader(http.StatusTeapot)
	})

	handler := Middleware(port, trusted, "t3", slog.New(slog.DiscardHandler), next)

	tests := []struct {
		headers    map[string]string
		name       string
		host       string
		wantStatus int
		wantCalled bool
	}{
		{
			name:       "native client passes",
			host:       "127.0.0.1:27301",
			wantStatus: http.StatusTeapot,
			wantCalled: true,
		},
		{
			name:       "localhost passes",
			host:       "localhost:27301",
			wantStatus: http.StatusTeapot,
			wantCalled: true,
		},
		{name: "bad host gets 403", host: "evil.example:27301", wantStatus: http.StatusForbidden},
		{
			name:       "null origin gets 403",
			host:       "127.0.0.1:27301",
			headers:    map[string]string{"Origin": "null"},
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "cross-site gets 403",
			host:       "127.0.0.1:27301",
			headers:    map[string]string{"Sec-Fetch-Site": "cross-site"},
			wantStatus: http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			called = false
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, newRequest(t, tt.host, tt.headers))

			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tt.wantStatus)
			}

			if called != tt.wantCalled {
				t.Fatalf("next called = %v, want %v", called, tt.wantCalled)
			}

			if !tt.wantCalled && rec.Body.String() != "forbidden\n" {
				t.Fatalf("body = %q", rec.Body.String())
			}
		})
	}
}

func TestMiddlewareSignedAssetImage(t *testing.T) {
	const asset = "/api/assets/cGF5bG9hZA.c2lnbmF0dXJl/dashboard.png"

	tests := []struct {
		change  func(*http.Request)
		name    string
		service string
		allow   bool
	}{
		{name: "signed asset image", allow: true},
		{name: "other service", service: "other"},
		{name: "foreign host", change: func(r *http.Request) { r.Host = "example.com" }},
		{
			name:   "foreign origin",
			change: func(r *http.Request) { r.Header.Set("Origin", "https://example.com") },
		},
		{name: "null origin", change: func(r *http.Request) { r.Header.Set("Origin", "null") }},
		{
			name:   "duplicate fetch site",
			change: func(r *http.Request) { r.Header.Add("Sec-Fetch-Site", "same-site") },
		},
		{name: "cors", change: func(r *http.Request) { r.Header.Set("Sec-Fetch-Mode", "cors") }},
		{
			name:   "iframe",
			change: func(r *http.Request) { r.Header.Set("Sec-Fetch-Dest", "iframe") },
		},
		{name: "post", change: func(r *http.Request) { r.Method = http.MethodPost }},
		{name: "upgrade", change: func(r *http.Request) { r.Header.Set("Upgrade", "websocket") }},
		{name: "other endpoint", change: func(r *http.Request) { r.URL.Path = "/api/other" }},
		{
			name:   "missing signature",
			change: func(r *http.Request) { r.URL.Path = "/api/assets/cGF5bG9hZA/dashboard.png" },
		},
		{
			name:   "path separator",
			change: func(r *http.Request) { r.URL.Path = asset + "/nested.png" },
		},
		{
			name:   "dot segment",
			change: func(r *http.Request) { r.URL.Path = "/api/assets/cGF5bG9hZA.c2lnbmF0dXJl/.." },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequestWithContext(
				t.Context(),
				http.MethodGet,
				"http://127.0.0.1:27301"+asset,
				http.NoBody,
			)
			r.Header.Set("Sec-Fetch-Site", "cross-site")
			r.Header.Set("Sec-Fetch-Mode", "no-cors")
			r.Header.Set("Sec-Fetch-Dest", "image")
			r.Header.Set("Cookie", "session=ambient")
			r.Header.Set("Authorization", "Bearer ambient")

			service := tt.service
			if service == "" {
				service = "t3"
			}

			want := http.StatusForbidden
			if tt.allow {
				want = http.StatusNoContent
			}

			if tt.change != nil {
				tt.change(r)
			}

			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != asset || r.Header.Get("Cookie") != "" ||
					r.Header.Get("Authorization") != "" {
					t.Fatal("proxy received changed asset path or ambient credentials")
				}

				w.WriteHeader(http.StatusNoContent)
			})
			rec := httptest.NewRecorder()
			Middleware(
				port,
				trusted,
				service,
				slog.New(slog.DiscardHandler),
				next,
			).ServeHTTP(rec, r)

			if rec.Code != want {
				t.Fatalf("status = %d, want %d", rec.Code, want)
			}
		})
	}
}
