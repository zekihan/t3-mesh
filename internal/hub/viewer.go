package hub

import (
	"context"
	"fmt"
	"html"
	"net"
	"net/http"
	"net/http/httputil"
	"regexp"
	"strings"
	"time"

	"github.com/zekihan/t3-mesh/internal/policy"
	"github.com/zekihan/t3-mesh/internal/proto"
)

// Viewer headers set by traefik-mtls-authz.
const (
	HeaderViewer      = "X-Mtls-Mesh-Viewer"
	HeaderFingerprint = "X-Mtls-Mesh-Fingerprint"
	HeaderNotAfter    = "X-Mtls-Mesh-Not-After"
)

var fingerprintRe = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)

// ViewerHandler returns the handler for viewer HTTP and WebSocket traffic.
//
// Connection isolation: every request gets its own http.Transport with
// DisableKeepAlives, and its dial function is bound to that request's viewer.
// A tunnel stream is therefore opened for exactly one request and is never
// reused by, or handed to, another viewer or fingerprint. A stream costs no
// handshake, so nothing is lost by not pooling.
func (s *Server) ViewerHandler() http.Handler {
	return http.HandlerFunc(s.serveViewer)
}

func (s *Server) serveViewer(w http.ResponseWriter, r *http.Request) {
	viewer, fp, notAfter, ok := viewerIdentity(r)
	if !ok {
		s.log.Info("reject", "kind", "viewer", "reason", "missing or invalid viewer headers", "host", r.Host)
		http.Error(w, "forbidden", http.StatusForbidden)

		return
	}

	snap := s.cfg.Current()

	machine, svc, ok := snap.HostTarget(r.Host)
	if !ok {
		http.NotFound(w, r)

		return
	}

	pol := policy.Session{Identity: viewer, Fingerprint: fp, NotAfter: notAfter, Svc: svc, Machine: machine}
	if err := s.checkNow(pol); err != nil {
		s.log.Info("reject", "kind", "viewer", "viewer", viewer, "target", policy.Target(svc, machine), "reason", err.Error())
		http.Error(w, "forbidden", http.StatusForbidden)

		return
	}

	if s.liveSession(machine) == nil {
		s.writeOffline(w, machine)

		return
	}

	tr := &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			return s.dialViewer(pol)
		},
	}

	rp := &httputil.ReverseProxy{
		Transport:     tr,
		FlushInterval: -1,
		Rewrite: func(pr *httputil.ProxyRequest) {
			for k := range pr.Out.Header {
				if strings.HasPrefix(strings.ToLower(k), "x-mtls-") {
					delete(pr.Out.Header, k)
				}
			}

			pr.Out.URL.Scheme = "http"
			pr.Out.URL.Host = pr.In.Host
			pr.Out.Host = pr.In.Host
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			s.log.Debug("viewer upstream error", "viewer", viewer, "target", policy.Target(svc, machine), "error", err.Error())
			http.Error(w, "bad gateway", http.StatusBadGateway)
		},
	}

	rp.ServeHTTP(w, r)
}

func viewerIdentity(r *http.Request) (viewer, fp string, notAfter time.Time, ok bool) {
	get := func(name string) (string, bool) {
		v := r.Header.Values(name)
		if len(v) != 1 || strings.TrimSpace(v[0]) == "" {
			return "", false
		}

		return strings.TrimSpace(v[0]), true
	}

	viewer, ok1 := get(HeaderViewer)
	fpRaw, ok2 := get(HeaderFingerprint)
	naRaw, ok3 := get(HeaderNotAfter)

	if !ok1 || !ok2 || !ok3 || strings.ContainsAny(viewer, " \t:/") || policy.IsAgent(viewer) || !fingerprintRe.MatchString(fpRaw) {
		return "", "", time.Time{}, false
	}

	notAfter, err := time.Parse(time.RFC3339, naRaw)
	if err != nil {
		return "", "", time.Time{}, false
	}

	return viewer, strings.ToLower(fpRaw), notAfter, true
}

func (s *Server) writeOffline(w http.ResponseWriter, machine string) {
	s.mu.Lock()

	var last time.Time
	if m := s.machines[machine]; m != nil {
		last = m.lastSeen
	}
	s.mu.Unlock()

	seen := "not seen since the hub started"
	if !last.IsZero() {
		seen = "last seen " + last.UTC().Format(time.RFC3339)
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusBadGateway)
	_, _ = fmt.Fprintf(w, "<!doctype html><html><head><title>%[1]s is offline</title></head><body><h1>%[1]s is offline</h1><p>The machine is not connected to the mesh (%[2]s).</p></body></html>\n",
		html.EscapeString(machine), html.EscapeString(seen))
}

// dialViewer opens a tunnel stream for one viewer request and tracks it.
func (s *Server) dialViewer(pol policy.Session) (net.Conn, error) {
	tgt := s.liveSession(pol.Machine)
	if tgt == nil {
		return nil, errNoSession
	}

	if err := s.checkNow(pol); err != nil {
		return nil, fmt.Errorf("hub: viewer no longer allowed: %w", err)
	}

	st, err := tgt.ymx.OpenStream()
	if err != nil {
		return nil, fmt.Errorf("hub: open stream: %w", err)
	}

	_ = st.SetWriteDeadline(time.Now().Add(headerReadTimeout))

	if err := proto.WriteLine(st, proto.StreamHeader{Svc: pol.Svc, Viewer: pol.Identity}); err != nil {
		_ = st.Close()

		return nil, fmt.Errorf("hub: write stream header: %w", err)
	}

	_ = st.SetWriteDeadline(time.Time{})

	t := &tracked{kind: "viewer", pol: pol, target: tgt}
	conn := &trackedConn{Conn: st, onClose: func() { s.untrack(t) }}
	t.closeFn = func() { _ = conn.Close() }

	s.track(t)

	// Close the window between the check above and tracking.
	if err := s.checkNow(pol); err != nil {
		_ = conn.Close()

		return nil, fmt.Errorf("hub: viewer no longer allowed: %w", err)
	}

	return conn, nil
}
