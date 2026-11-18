// Package viewerproxy holds the request rewriting shared by every path that carries
// a viewer's HTTP or WebSocket request to a machine's T3: the hub's viewer proxy and
// the agent's device listener. Both therefore treat a request the same way, which is
// what lets an unpaired request get the same answer on either.
package viewerproxy

import (
	"net/http"
	"net/http/httputil"
	"strings"
)

// Rewrite is the ReverseProxy.Rewrite of a viewer request. It drops every
// X-Mtls-* header, forwards Host unchanged, and sets X-Forwarded-Proto to https,
// because viewers always reach their machine over TLS and T3 marks its session
// cookie Secure on that basis. ReverseProxy has already removed Forwarded,
// X-Forwarded-For, X-Forwarded-Host and X-Forwarded-Proto from the outbound
// request, and Rewrite adds no X-Forwarded-For.
func Rewrite(pr *httputil.ProxyRequest) {
	for k := range pr.Out.Header {
		if strings.HasPrefix(strings.ToLower(k), "x-mtls-") {
			delete(pr.Out.Header, k)
		}
	}

	pr.Out.URL.Scheme = "http"
	pr.Out.URL.Host = pr.In.Host
	pr.Out.Host = pr.In.Host
	pr.Out.Header.Set("X-Forwarded-Proto", "https")
}

// StripClientForwarding removes the headers that only a trusted proxy may set, for a
// listener whose clients are not behind one: Forwarded, every X-Forwarded-* and
// X-Real-Ip. On the hub they come from Traefik, which overwrites what a client sent;
// on the agent's device listener there is no proxy in front, so whatever arrives is
// the client's.
func StripClientForwarding(header http.Header) {
	for k := range header {
		lower := strings.ToLower(k)

		if lower == "forwarded" || lower == "x-real-ip" ||
			strings.HasPrefix(lower, "x-forwarded-") {
			delete(header, k)
		}
	}
}
