// Package linkguard checks requests arriving on unauthenticated loopback link ports
// against DNS rebinding and cross-site browser requests.
package linkguard

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// ErrForbidden is returned by Check when a request must not pass a link port.
var ErrForbidden = errors.New("linkguard: forbidden")

// Check returns nil if r may pass through link port port. It rejects a request whose
// Host is not 127.0.0.1:<port> or localhost:<port>, whose Origin is present and not
// http://127.0.0.1:<port> or http://localhost:<port>, or whose Sec-Fetch-Site is
// present and not same-origin or none. Requests with neither Origin nor
// Sec-Fetch-Site (native clients) pass when Host is valid. WebSocket upgrades are
// checked the same way.
func Check(r *http.Request, port int) error {
	portStr := strconv.Itoa(port)

	if !matchesAny(r.Host, "127.0.0.1:"+portStr, "localhost:"+portStr) {
		return fmt.Errorf("%w: host %q", ErrForbidden, r.Host)
	}

	for _, origin := range r.Header.Values("Origin") {
		if !matchesAny(origin, "http://127.0.0.1:"+portStr, "http://localhost:"+portStr) {
			return fmt.Errorf("%w: origin %q", ErrForbidden, origin)
		}
	}

	for _, site := range r.Header.Values("Sec-Fetch-Site") {
		if !matchesAny(site, "same-origin", "none") {
			return fmt.Errorf("%w: sec-fetch-site %q", ErrForbidden, site)
		}
	}

	return nil
}

// Middleware wraps h, answering 403 without calling h when Check fails for port.
func Middleware(port int, handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := Check(r, port)
		if err != nil {
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
