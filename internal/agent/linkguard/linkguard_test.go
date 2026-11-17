package linkguard

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

const port = 27301

func newRequest(host string, headers map[string]string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	r.Host = host

	for k, v := range headers {
		r.Header.Set(k, v)
	}

	return r
}

func TestCheck(t *testing.T) {
	tests := []struct {
		name    string
		host    string
		headers map[string]string
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Check(newRequest(tt.host, tt.headers), port)
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

func TestCheckWebSocketUpgrade(t *testing.T) {
	upgrade := func(host, origin string) *http.Request {
		r := newRequest(host, map[string]string{
			"Connection": "Upgrade",
			"Upgrade":    "websocket",
		})
		if origin != "" {
			r.Header.Set("Origin", origin)
		}

		return r
	}

	if err := Check(upgrade("127.0.0.1:27301", ""), port); err != nil {
		t.Fatalf("native websocket rejected: %v", err)
	}

	if err := Check(upgrade("localhost:27301", "http://localhost:27301"), port); err != nil {
		t.Fatalf("local websocket rejected: %v", err)
	}

	if err := Check(upgrade("127.0.0.1:27301", "http://evil.example"), port); err == nil {
		t.Fatal("foreign-origin websocket accepted")
	}

	if err := Check(upgrade("127.0.0.1:27301", "null"), port); err == nil {
		t.Fatal("null-origin websocket accepted")
	}
}

func TestCheckPortIsPartOfHost(t *testing.T) {
	r := newRequest("127.0.0.1:27302", nil)
	if err := Check(r, 27302); err != nil {
		t.Fatalf("port 27302 rejected: %v", err)
	}

	if err := Check(r, 27301); err == nil {
		t.Fatal("request for port 27302 accepted on port 27301")
	}
}

func TestMiddleware(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true

		w.WriteHeader(http.StatusTeapot)
	})

	h := Middleware(port, next)

	tests := []struct {
		name       string
		host       string
		headers    map[string]string
		wantStatus int
		wantCalled bool
	}{
		{"native client passes", "127.0.0.1:27301", nil, http.StatusTeapot, true},
		{"localhost passes", "localhost:27301", nil, http.StatusTeapot, true},
		{"bad host gets 403", "evil.example:27301", nil, http.StatusForbidden, false},
		{
			"null origin gets 403", "127.0.0.1:27301",
			map[string]string{"Origin": "null"},
			http.StatusForbidden, false,
		},
		{
			"cross-site gets 403", "127.0.0.1:27301",
			map[string]string{"Sec-Fetch-Site": "cross-site"},
			http.StatusForbidden, false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			called = false
			rec := httptest.NewRecorder()

			h.ServeHTTP(rec, newRequest(tt.host, tt.headers))

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
