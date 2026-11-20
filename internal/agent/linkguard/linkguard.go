// Package linkguard checks requests arriving on unauthenticated loopback link ports
// against DNS rebinding and cross-site browser requests.
package linkguard

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// ErrForbidden is returned by Check when a request must not pass a link port.
var ErrForbidden = errors.New("linkguard: forbidden")

var assetTokenPattern = regexp.MustCompile(`^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$`)

type assetRequest uint8

const (
	notAsset assetRequest = iota
	assetImage
	assetHTMLFrame
)

type htmlFrameContextKey struct{}

var errUnexpectedHTMLFrameResponse = errors.New("linkguard: unexpected HTML frame response")

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
	return check(r, port, trusted, false)
}

func check(r *http.Request, port int, trusted []string, signedAsset bool) error {
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

	if trustedOrigin || signedAsset {
		return nil
	}

	for _, site := range r.Header.Values("Sec-Fetch-Site") {
		if !matchesAny(site, "same-origin", "none") {
			return fmt.Errorf("%w: sec-fetch-site %q", ErrForbidden, site)
		}
	}

	return nil
}

// The desktop renderer's image and frame GETs omit Origin. T3 still verifies
// the asset URL signature and expiry before serving the bytes.
func t3AssetRequest(r *http.Request) assetRequest {
	if r.Method != http.MethodGet || len(r.Header.Values("Origin")) != 0 ||
		r.Header.Get("Upgrade") != "" ||
		!slices.Equal(r.Header.Values("Sec-Fetch-Site"), []string{"cross-site"}) {
		return notAsset
	}

	token, filename, ok := assetPath(r.URL.Path)
	if !ok {
		return notAsset
	}

	mode := r.Header.Values("Sec-Fetch-Mode")
	dest := r.Header.Values("Sec-Fetch-Dest")

	switch {
	case slices.Equal(mode, []string{"no-cors"}) && slices.Equal(dest, []string{"image"}):
		return assetImage
	case slices.Equal(mode, []string{"navigate"}) && slices.Equal(dest, []string{"iframe"}) &&
		inlineHTMLAttachment(token, filename):
		return assetHTMLFrame
	default:
		return notAsset
	}
}

func assetPath(path string) (string, string, bool) {
	asset, ok := strings.CutPrefix(path, "/api/assets/")
	if !ok {
		return "", "", false
	}

	token, filename, ok := strings.Cut(asset, "/")

	return token, filename, ok && assetTokenPattern.MatchString(token) && filename != "" &&
		filename != "." && filename != ".." && !strings.ContainsAny(filename, "/\\")
}

// Read only the claims needed to narrow the exception. The upstream T3 server
// authenticates the token before using any claims to resolve an attachment.
func inlineHTMLAttachment(token, filename string) bool {
	payload, _, _ := strings.Cut(token, ".")

	decoded, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return false
	}

	var claims struct {
		Kind     string `json:"kind"`
		FileName string `json:"fileName"`
		MIMEType string `json:"mimeType"`
		Version  int    `json:"version"`
		Download bool   `json:"download"`
	}

	return json.Unmarshal(decoded, &claims) == nil && claims.Version == 1 &&
		claims.Kind == "attachment" && claims.MIMEType == "text/html" &&
		claims.FileName == filename && !claims.Download
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
func Middleware(
	port int,
	trusted []string,
	service string,
	log *slog.Logger,
	handler http.Handler,
) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asset := notAsset
		if service == "t3" {
			asset = t3AssetRequest(r)
		}

		err := check(r, port, trusted, asset != notAsset)
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

		if asset != notAsset {
			ctx := r.Context()
			if asset == assetHTMLFrame {
				ctx = context.WithValue(ctx, htmlFrameContextKey{}, true)
			}

			r = r.Clone(ctx)
			r.Header.Del("Cookie")
			r.Header.Del("Authorization")
		}

		handler.ServeHTTP(w, r)
	})
}

// GuardAssetResponse applies to frames admitted by the signed asset exception.
// Enforce an opaque origin even if the embedding page omits its own sandbox.
func GuardAssetResponse(resp *http.Response) error {
	if resp.Request.Context().Value(htmlFrameContextKey{}) == nil {
		return nil
	}

	switch {
	case resp.StatusCode == http.StatusOK:
		mediaType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
		if err != nil || mediaType != "text/html" || len(resp.Header.Values("Content-Type")) != 1 {
			return errUnexpectedHTMLFrameResponse
		}
	case resp.StatusCode < http.StatusBadRequest:
		return errUnexpectedHTMLFrameResponse
	}

	resp.Header.Add("Content-Security-Policy", "sandbox allow-scripts allow-forms")
	resp.Header.Set("X-Content-Type-Options", "nosniff")
	resp.Header.Set("Referrer-Policy", "no-referrer")
	resp.Header.Set("Cache-Control", "no-store")
	resp.Header.Del("Set-Cookie")
	resp.Header.Del("Refresh")

	return nil
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
