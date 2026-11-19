// Package linkguard checks requests arriving on unauthenticated loopback link ports
// against DNS rebinding and cross-site browser requests.
package linkguard

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
)

// ErrForbidden is returned by Check when a request must not pass a link port.
var ErrForbidden = errors.New("linkguard: forbidden")

// DesktopOrigin is the origin of the T3 Code desktop app's renderer. The app
// registers the t3code scheme itself, so no web page can send this origin, and
// the renderer reaches environments with cross-site fetches from it.
const DesktopOrigin = "t3code://app"

// Check returns nil if r may pass through link port port. It rejects a request
// whose Host is not 127.0.0.1:<port> or localhost:<port>. A request with an
// Origin passes only if that origin is http://127.0.0.1:<port>,
// http://localhost:<port> or one of trusted; one with Sec-Fetch-Site passes only
// if it is same-origin or none, or the request carries a trusted Origin.
// Trusted HTTP(S) origins with an explicit default port also match the browser's
// Origin without the port.
// Requests with neither header (native clients) pass when Host is valid.
// WebSocket upgrades are checked the same way.
func Check(r *http.Request, port int, trusted []string) error {
	portStr := strconv.Itoa(port)
	if !matchesAny(r.Host, "127.0.0.1:"+portStr, "localhost:"+portStr) {
		return fmt.Errorf("%w: host %q", ErrForbidden, r.Host)
	}

	origins := r.Header.Values("Origin")
	trustedOrigin := len(origins) > 0

	for _, origin := range origins {
		if matchesTrustedOrigin(origin, trusted) {
			continue
		}

		trustedOrigin = false

		if !matchesAny(origin, "http://127.0.0.1:"+portStr, "http://localhost:"+portStr) {
			return fmt.Errorf("%w: origin %q", ErrForbidden, origin)
		}
	}

	if trustedOrigin {
		return nil
	}

	for _, site := range r.Header.Values("Sec-Fetch-Site") {
		if !matchesAny(site, "same-origin", "none") {
			return fmt.Errorf("%w: sec-fetch-site %q", ErrForbidden, site)
		}
	}

	return nil
}

func matchesTrustedOrigin(origin string, trusted []string) bool {
	for _, allowed := range trusted {
		if strings.EqualFold(origin, allowed) {
			return true
		}

		scheme, authority, _ := strings.Cut(allowed, "://")

		var defaultPort string

		switch strings.ToLower(scheme) {
		case "http":
			defaultPort = "80"
		case "https":
			defaultPort = "443"
		default:
			continue
		}

		host, port, err := net.SplitHostPort(authority)
		if err == nil && host != "" && strings.TrimLeft(port, "0") == defaultPort &&
			strings.EqualFold(origin, strings.TrimSuffix(allowed, ":"+port)) {
			return true
		}
	}

	return false
}

// Middleware wraps h, answering 403 without calling h when Check fails for port,
// and logging why.
func Middleware(port int, trusted []string, log *slog.Logger, handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := Check(r, port, trusted)
		if err != nil {
			log.InfoContext(
				r.Context(),
				"Link request refused",
				slog.Int("port", port),
				slog.String("method", r.Method),
				slog.String("reason", err.Error()),
			)
			http.Error(w, "forbidden", http.StatusForbidden)

			return
		}

		handler.ServeHTTP(w, r)
	})
}

// matchesAny compares s with each candidate, ignoring case. Only "localhost" can vary
// in case in practice, and the digits and scheme are unaffected by folding.
func matchesAny(s string, candidates ...string) bool {
	for _, c := range candidates {
		if strings.EqualFold(s, c) {
			return true
		}
	}

	return false
}
