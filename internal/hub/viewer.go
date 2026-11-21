package hub

import (
	"context"
	"fmt"
	"html"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"github.com/zekihan/t3-mesh/internal/policy"
	"github.com/zekihan/t3-mesh/internal/proto"
	"github.com/zekihan/t3-mesh/internal/viewerproxy"
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
func (server *Server) ViewerHandler() http.Handler {
	return http.HandlerFunc(server.serveViewer)
}

func (server *Server) serveViewer(w http.ResponseWriter, r *http.Request) {
	// The API host is matched first: HostTarget only splits
	// <svc>.<machine>.<domain> and would answer 404.
	if server.cfg.Current().IsAPIHost(r.Host) {
		server.serveAPI(w, r)

		return
	}

	viewer, fp, notAfter, ok := viewerIdentity(r)
	if !ok {
		server.log.InfoContext(
			r.Context(),
			"Reject",
			slog.String("kind", "viewer"),
			slog.String("reason", "missing or invalid viewer headers"),
			slog.Any("host", r.Host),
		)
		http.Error(w, "forbidden", http.StatusForbidden)

		return
	}

	snap := server.cfg.Current()

	machine, svc, ok := snap.HostTarget(r.Host)
	if !ok {
		http.NotFound(w, r)

		return
	}

	pol := policy.Session{
		Identity:    viewer,
		Fingerprint: fp,
		NotAfter:    notAfter,
		Svc:         svc,
		Machine:     machine,
	}

	err := server.checkRules(&pol)
	if err == nil {
		// An enrolled device is admitted only with its newest leaf.
		err = server.admitDevice(r.Context(), snap, viewer, fp)
	}

	if err != nil {
		server.log.InfoContext(
			r.Context(),
			"Reject",
			slog.String("kind", "viewer"),
			slog.Any("viewer", viewer),
			slog.String("target", policy.Target(svc, machine)),
			slog.String("reason", err.Error()),
		)
		refuse(w, err)

		return
	}

	if server.liveSession(machine) == nil {
		server.writeOffline(w, machine)

		return
	}

	server.logViewerStream(r, &pol)

	// Revocation cancels the request and aborts the viewer's connection, so a
	// pending request or an upgraded WebSocket ends even if the machine's
	// service never hangs up.
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	r = r.WithContext(ctx)

	var revoked atomic.Bool

	rc := http.NewResponseController(w)

	onRevoke := func() {
		revoked.Store(true)
		// Unblocks a pending read of the request body, which the upstream
		// round trip waits for. Fails harmlessly once the connection is hijacked.
		_ = rc.SetReadDeadline(time.Now()) //nolint:errcheck // fails once hijacked; nothing to do

		cancel()
	}

	tr := &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			return server.dialViewer(&pol, onRevoke)
		},
	}

	rp := &httputil.ReverseProxy{
		Transport:     tr,
		FlushInterval: -1,
		Rewrite:       viewerproxy.Rewrite,
		ErrorHandler: func(w http.ResponseWriter, req *http.Request, err error) {
			if revoked.Load() {
				// Closing the hijacked connection ends the request at once; an
				// aborted handler would first drain the rest of the request body.
				conn, _, herr := rc.Hijack()
				if herr == nil {
					_ = conn.Close()

					return
				}

				panic(http.ErrAbortHandler)
			}

			server.log.DebugContext(
				req.Context(),
				"Viewer upstream error",
				slog.Any("viewer", viewer),
				slog.String("target", policy.Target(svc, machine)),
				slog.String("error", err.Error()),
			)
			http.Error(w, "bad gateway", http.StatusBadGateway)
		},
	}

	rp.ServeHTTP(w, r)
}

// logViewerStream records an admitted viewer stream with the identity URI it was
// opened under. Every WebSocket upgrade and every stream of an enrolled device is
// logged at info, so a device's chat socket and streams can be told from the log;
// the many plain requests of other viewers stay at debug.
func (server *Server) logViewerStream(r *http.Request, pol *policy.Session) {
	upgrade := strings.EqualFold(r.Header.Get("Upgrade"), "websocket")

	level := slog.LevelDebug
	if upgrade || policy.IsDevice(pol.Identity) {
		level = slog.LevelInfo
	}

	server.log.Log(
		r.Context(),
		level,
		"Viewer stream",
		slog.String("kind", "viewer"),
		slog.String("viewer", pol.Identity),
		slog.String("uri", policy.IdentityURI(pol.Identity)),
		slog.String("fingerprint", pol.Fingerprint),
		slog.String("target", policy.Target(pol.Svc, pol.Machine)),
		slog.Bool("upgrade", upgrade),
	)
}

func viewerIdentity(r *http.Request) (string, string, time.Time, bool) {
	get := func(name string) (string, bool) {
		v := r.Header.Values(name)
		if len(v) != 1 || strings.TrimSpace(v[0]) == "" {
			return "", false
		}

		return strings.TrimSpace(v[0]), true
	}

	uri, ok1 := get(HeaderViewer)
	fpRaw, ok2 := get(HeaderFingerprint)
	naRaw, ok3 := get(HeaderNotAfter)

	if !ok1 || !ok2 || !ok3 || !fingerprintRe.MatchString(fpRaw) {
		return "", "", time.Time{}, false
	}

	// The traefik-mtls-authz plugin forwards the full URI SAN of the verified leaf.
	viewer, err := policy.IdentityFromURI(uri)
	if err != nil || policy.IsAgent(viewer) {
		return "", "", time.Time{}, false
	}

	notAfter, err := time.Parse(time.RFC3339, naRaw)
	if err != nil {
		return "", "", time.Time{}, false
	}

	return viewer, strings.ToLower(fpRaw), notAfter, true
}

func (server *Server) writeOffline(w http.ResponseWriter, machine string) {
	server.mu.Lock()

	var last time.Time
	if m := server.machines[machine]; m != nil {
		last = m.lastSeen
	}
	server.mu.Unlock()

	seen := "not seen since the hub started"
	if !last.IsZero() {
		seen = "last seen " + last.UTC().Format(time.RFC3339)
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusBadGateway)
	_, _ = fmt.Fprintf(
		w,
		"<!doctype html><html><head><title>%[1]s is offline</title></head>"+
			"<body><h1>%[1]s is offline</h1>"+
			"<p>The machine is not connected to the mesh (%[2]s).</p></body></html>\n",
		html.EscapeString(machine),
		html.EscapeString(seen),
	)
}

// dialViewer opens a tunnel stream for one viewer request and tracks it.
func (server *Server) dialViewer(pol *policy.Session, onRevoke func()) (net.Conn, error) {
	tgt := server.liveSession(pol.Machine)
	if tgt == nil {
		return nil, errNoSession
	}

	err := server.checkNow(pol)
	if err != nil {
		return nil, fmt.Errorf("hub: viewer no longer allowed: %w", err)
	}

	st, err := tgt.ymx.OpenStream()
	if err != nil {
		return nil, fmt.Errorf("hub: open stream: %w", err)
	}

	//nolint:errcheck // best-effort deadline; a dead connection fails the next read or write
	_ = st.SetWriteDeadline(time.Now().Add(headerReadTimeout))

	err = proto.WriteLine(
		st,
		proto.StreamHeader{Svc: pol.Svc, Viewer: pol.Identity},
	)
	if err != nil {
		_ = st.Close()

		return nil, fmt.Errorf("hub: write stream header: %w", err)
	}

	//nolint:errcheck // best-effort deadline; a dead connection fails the next read or write
	_ = st.SetWriteDeadline(time.Time{})

	entry := &tracked{kind: "viewer", pol: *pol, target: tgt}
	conn := &trackedConn{Conn: st, onClose: func() { server.untrack(entry) }}
	entry.closeFn = func() {
		onRevoke()
		abortConn(conn)
	}

	server.track(entry)

	// Close the window between the check above and tracking.
	err = server.checkStream(server.cfg.Current(), entry, server.now())
	if err != nil {
		_ = conn.Close()

		return nil, fmt.Errorf("hub: viewer no longer allowed: %w", err)
	}

	return conn, nil
}
