package direct

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/zekihan/t3-mesh/internal/pki"
	"github.com/zekihan/t3-mesh/internal/policy"
	"github.com/zekihan/t3-mesh/internal/proto"
	"github.com/zekihan/t3-mesh/internal/viewerproxy"
)

// The device listener lets an enrolled device (the Android app) reach this
// machine's T3 over the LAN with TLS 1.3 and a client certificate, without the
// hub. It is not the agent-to-agent listener: it speaks HTTP/1.1 to the caller and
// proxies to the machine's own T3, and it admits only enrolled-device identities.
// It binds the same addresses as that listener under the same home gate, and its
// sessions are re-checked with the same view, so revocations, rule changes, newer
// leaves, expiry and the end of the cache window close them at once.

// Device listener constants.
const (
	// DeviceSvc is the service the device listener proxies to.
	DeviceSvc = "t3"
	// ProbePath is answered by the listener itself, and never reaches T3.
	ProbePath = "/.well-known/t3-mesh/direct"

	alpnHTTP            = "http/1.1"
	hostPortSuffix      = ":443"
	maxDeviceHandshakes = 64
	deviceHeaderTimeout = 10 * time.Second
	deviceIdleTimeout   = 3 * time.Minute
)

var (
	errNotDevice = errors.New("direct: caller is not an enrolled-device identity")
	errDeviceSAN = errors.New(
		"direct: device certificate carries more than its identity URI",
	)
	errDeviceSuperseded = errors.New("direct: not the newest leaf this agent knows for the device")
	errDeviceClosed     = errors.New("direct: device session closed")
)

type deviceSessionKey struct{}

// deviceProbe is the body of the probe answer.
type deviceProbe struct {
	Machine  string `json:"machine"`
	Identity string `json:"identity"`
}

// connQueue is the net.Listener the HTTP server accepts admitted connections
// from: a connection reaches it only after the TLS handshake and admission.
type connQueue struct {
	conns chan net.Conn
	done  chan struct{}
	once  sync.Once
}

func newConnQueue() *connQueue {
	return &connQueue{conns: make(chan net.Conn), done: make(chan struct{})}
}

func (q *connQueue) Accept() (net.Conn, error) {
	select {
	case conn := <-q.conns:
		return conn, nil
	case <-q.done:
		return nil, net.ErrClosed
	}
}

func (q *connQueue) Close() error {
	q.once.Do(func() { close(q.done) })

	return nil
}

func (q *connQueue) Addr() net.Addr { return &net.TCPAddr{} }

// offer hands conn to the server, and reports false when the queue is closed or
// ctx ends first.
func (q *connQueue) offer(ctx context.Context, conn net.Conn) bool {
	select {
	case q.conns <- conn:
		return true
	case <-q.done:
		return false
	case <-ctx.Done():
		return false
	}
}

// deviceSession is one admitted TLS connection from an enrolled device. It lives
// from the handshake until the connection closes, however many requests, WebSocket
// upgrades or keep-alive gaps that spans.
type deviceSession struct {
	local    netip.Addr
	err      error
	raw      net.Conn
	m        *Manager
	backends map[*backendConn]struct{}
	proxy    *httputil.ReverseProxy
	tc       *tls.Conn
	rule     policy.Session
	identity string
	fp       string
	once     sync.Once
	closed   bool
}

// deviceConn is the connection the HTTP server holds. Closing it, as the server
// and a finished WebSocket do, ends the session.
type deviceConn struct {
	*tls.Conn

	sess *deviceSession
}

func (c *deviceConn) Close() error { return c.sess.close() }

// backendConn is a connection to T3 opened for one request of a session.
type backendConn struct {
	net.Conn

	sess *deviceSession
}

func (c *backendConn) Close() error {
	c.sess.m.mu.Lock()
	delete(c.sess.backends, c)
	c.sess.m.mu.Unlock()

	return c.Conn.Close() //nolint:wrapcheck // passthrough
}

func (sess *deviceSession) close() error {
	sess.finish(false)

	return sess.err
}

// abort ends the session at once and reports whether this call ended it. It
// closes the TCP connection before the TLS one: a TLS close first sends an alert
// and waits on a write that a stalled peer never accepts.
func (sess *deviceSession) abort() bool { return sess.finish(true) }

func (sess *deviceSession) finish(abort bool) bool {
	first := false

	sess.once.Do(func() {
		first = true

		sess.m.mu.Lock()
		sess.closed = true
		delete(sess.m.devSessions, sess)

		backends := make([]*backendConn, 0, len(sess.backends))
		for b := range sess.backends {
			backends = append(backends, b)
		}

		clear(sess.backends)
		sess.m.mu.Unlock()

		if abort {
			_ = sess.raw.Close()
		}

		sess.err = sess.tc.Close()

		for _, b := range backends {
			_ = b.Conn.Close()
		}
	})

	return first
}

// dialBackend opens a connection to T3 for one request and ties it to the session.
func (sess *deviceSession) dialBackend(ctx context.Context) (net.Conn, error) {
	mgr := sess.m

	conn, err := mgr.opts.Dial(ctx, "tcp", mgr.opts.Serve[DeviceSvc])
	if err != nil {
		return nil, fmt.Errorf("direct: dial %s: %w", DeviceSvc, err)
	}

	back := &backendConn{Conn: conn, sess: sess}

	mgr.mu.Lock()
	if sess.closed {
		mgr.mu.Unlock()

		_ = conn.Close()

		return nil, errDeviceClosed
	}

	sess.backends[back] = struct{}{}
	mgr.mu.Unlock()

	return back, nil
}

// newDeviceSession returns the session for an admitted connection, with the proxy
// that carries its requests to T3. Like the hub's viewer proxy, it opens a
// connection to T3 for each request and never reuses one, so a T3 connection is
// never shared between requests of different callers, and every connection is
// known to the session that opened it.
func (mgr *Manager) newDeviceSession(
	raw net.Conn,
	tc *tls.Conn,
	leaf *x509.Certificate,
	identity, self string,
) *deviceSession {
	sess := &deviceSession{
		m:        mgr,
		raw:      raw,
		tc:       tc,
		local:    localAddrOf(raw),
		identity: identity,
		fp:       pki.Fingerprint(leaf),
		backends: make(map[*backendConn]struct{}),
	}
	sess.rule = policy.Session{
		Identity: identity, Fingerprint: sess.fp, NotAfter: leaf.NotAfter,
		Svc: DeviceSvc, Machine: self,
	}

	transport := &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return sess.dialBackend(ctx)
		},
	}

	sess.proxy = &httputil.ReverseProxy{
		Transport:     transport,
		FlushInterval: -1,
		Rewrite: func(pr *httputil.ProxyRequest) {
			// There is no proxy in front of this listener, so every forwarding
			// header is the caller's.
			viewerproxy.StripClientForwarding(pr.Out.Header)
			viewerproxy.Rewrite(pr)
		},
		ErrorLog: slog.NewLogLogger(mgr.log.Handler(), slog.LevelDebug),
		ErrorHandler: func(w http.ResponseWriter, req *http.Request, err error) {
			mgr.log.DebugContext(
				req.Context(),
				"Device upstream error",
				slog.String("peer", identity),
				slog.Any("err", err),
			)
			http.Error(w, "bad gateway", http.StatusBadGateway)
		},
	}

	return sess
}

// startDevices prepares the device listener, when it is configured and the
// machine serves T3.
func (mgr *Manager) startDevices() {
	if mgr.opts.DevicePort <= 0 {
		return
	}

	if mgr.opts.Serve[DeviceSvc] == "" {
		mgr.log.Info("Device listener off", slog.String("reason", "no t3 service is served"))

		return
	}

	mgr.deviceLn = listenSet{
		name: "Device", port: mgr.opts.DevicePort, serve: mgr.serveDevice,
		byAddr: make(map[netip.Addr]net.Listener),
	}
	mgr.devQueue = newConnQueue()
	mgr.devSlots = make(chan struct{}, maxDeviceHandshakes)
	mgr.devSrv = &http.Server{
		Handler:           http.HandlerFunc(mgr.serveDeviceRequest),
		ReadHeaderTimeout: deviceHeaderTimeout,
		IdleTimeout:       deviceIdleTimeout,
		// HTTP/1.1 only: the viewer path reaches T3 as HTTP/1.1.
		TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){},
		BaseContext:  func(net.Listener) context.Context { return mgr.ctx },
		ConnContext: func(ctx context.Context, conn net.Conn) context.Context {
			if dc, ok := conn.(*deviceConn); ok {
				return context.WithValue(ctx, deviceSessionKey{}, dc.sess)
			}

			return ctx
		},
		ErrorLog: slog.NewLogLogger(mgr.log.Handler(), slog.LevelDebug),
	}

	mgr.wg.Go(func() {
		err := mgr.devSrv.Serve(mgr.devQueue)
		if err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
			mgr.log.Error("Device server stopped", slog.Any("err", err))
		}
	})
}

func (mgr *Manager) stopDevices() {
	if mgr.devSrv == nil {
		return
	}

	_ = mgr.devSrv.Close()
	_ = mgr.devQueue.Close()
}

// DeviceListener returns the port and the addresses the device listener is bound
// on, or zero and nil while it is not listening.
func (mgr *Manager) DeviceListener() (int, []string) {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()

	if len(mgr.deviceLn.byAddr) == 0 {
		return 0, nil
	}

	addrs := make([]netip.Addr, 0, len(mgr.deviceLn.byAddr))
	for a := range mgr.deviceLn.byAddr {
		addrs = append(addrs, a)
	}

	slices.SortFunc(addrs, netip.Addr.Compare)

	out := make([]string, len(addrs))
	for i, a := range addrs {
		out[i] = a.String()
	}

	return mgr.deviceLn.port, out
}

// DeviceSessions returns the number of live device connections.
func (mgr *Manager) DeviceSessions() int {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()

	return len(mgr.devSessions)
}

// admitDeviceLeaf checks what a certificate must be to belong to an enrolled
// device, whatever the rules say: exactly one URI SAN and no other name, of the
// enrolled-device kind, client auth only and not a CA. The KeyChain identities
// and agents fail here. It returns the identity name, also on failure when the
// certificate has one, for the log.
func admitDeviceLeaf(leaf *x509.Certificate) (string, error) {
	identity, err := pki.CertIdentity(leaf)
	if err != nil {
		return "", fmt.Errorf("device caller: %w", err)
	}

	if !policy.IsDevice(identity) {
		return identity, fmt.Errorf("%w: %s", errNotDevice, identity)
	}

	if len(leaf.DNSNames)+len(leaf.IPAddresses)+len(leaf.EmailAddresses) > 0 {
		return identity, fmt.Errorf("%w: %s", errDeviceSAN, identity)
	}

	err = pki.CheckDeviceLeaf(leaf)
	if err != nil {
		return identity, fmt.Errorf("device caller %s: %w", identity, err)
	}

	return identity, nil
}

// allowedDevice reports whether the device behind rule may use this machine now:
// its identity is not disabled, its leaf is not blocked or expired, the machine's
// rule lists it, and its leaf is the newest this agent knows for it.
func (mgr *Manager) allowedDevice(view *View, rule *policy.Session, now time.Time) error {
	checked := *rule
	checked.Machine = view.Self

	if view.Rules.ServiceKinds[policy.Target(checked.Svc, checked.Machine)] != proto.KindHTTP {
		return errServiceKind
	}

	err := policy.Check(view.Rules, view.Revocations, checked, now)
	if err != nil {
		return fmt.Errorf("device: %w", err)
	}

	if !view.allowDevice(rule.Identity, rule.Fingerprint) {
		return fmt.Errorf("%w: %s", errDeviceSuperseded, rule.Identity)
	}

	return nil
}

// verifyDevice is the TLS handshake's check of a caller: its certificate chains to
// the cached clients CA bundle, is an enrolled device's, and that device may use
// this machine now. A caller that fails gets a TLS alert instead of a connection,
// and the app sees the refusal as a certificate failure at the TLS layer.
func (mgr *Manager) verifyDevice(raw [][]byte) error {
	view := mgr.view()
	if view.Roots == nil {
		return errNoTrustBundle
	}

	now := mgr.now()

	leaf, err := pki.VerifyPeer(raw, view.Roots, x509.ExtKeyUsageClientAuth, now)
	if err != nil {
		return fmt.Errorf("verify caller: %w", err)
	}

	identity, err := admitDeviceLeaf(leaf)
	if err != nil {
		return err
	}

	rule := policy.Session{
		Identity: identity, Fingerprint: pki.Fingerprint(leaf), NotAfter: leaf.NotAfter,
		Svc: DeviceSvc, Machine: view.Self,
	}

	return mgr.allowedDevice(view, &rule, now)
}

// serveDevice takes one accepted TCP connection through the handshake and
// admission, and hands it to the HTTP server when it passes.
func (mgr *Manager) serveDevice(raw net.Conn) {
	defer mgr.wg.Done()

	defer func() {
		mgr.mu.Lock()
		delete(mgr.pending, raw)
		mgr.mu.Unlock()
	}()

	// A bounded number of connections may be between accept and admission, so
	// a host on the LAN cannot hold every descriptor with half-open handshakes.
	select {
	case mgr.devSlots <- struct{}{}:
		defer func() { <-mgr.devSlots }()
	default:
		mgr.log.Debug("Device connection refused", slog.String("reason", "too many handshakes"))

		_ = raw.Close()

		return
	}

	if ok, reason := mgr.Active(); !ok {
		mgr.log.Debug("Device connection refused", slog.String("reason", reason))

		_ = raw.Close()

		return
	}

	setDeadline(raw.SetDeadline, time.Now().Add(serverSetupLimit))

	sess, tc, ok := mgr.admitDevice(raw)
	if !ok {
		return
	}

	setDeadline(raw.SetDeadline, time.Time{})

	mgr.log.Info("Device session open",
		slog.String("peer", sess.identity),
		slog.String("uri", policy.IdentityURI(sess.identity)),
		slog.String("fingerprint", sess.fp),
	)

	if !mgr.devQueue.offer(mgr.ctx, &deviceConn{Conn: tc, sess: sess}) {
		sess.abort()
	}
}

// admitDevice completes the TLS handshake with a caller, applies the admission
// rules and registers its session. It closes the connection and returns false
// when the caller is not admitted.
func (mgr *Manager) admitDevice(raw net.Conn) (*deviceSession, *tls.Conn, bool) {
	tc := tls.Server(raw, mgr.serverTLS(alpnHTTP, mgr.verifyDevice))

	ctx, cancel := context.WithTimeout(mgr.ctx, serverSetupLimit)
	defer cancel()

	err := tc.HandshakeContext(ctx)
	if err != nil {
		mgr.log.Info("Device caller refused", slog.String("remote", raw.RemoteAddr().String()),
			slog.Any("err", err),
		)

		_ = raw.Close()

		return nil, nil, false
	}

	state := tc.ConnectionState()
	if state.NegotiatedProtocol != alpnHTTP || len(state.PeerCertificates) == 0 {
		mgr.log.Info("Device caller refused", slog.String("remote", raw.RemoteAddr().String()),
			slog.String("reason", "no http/1.1 or no certificate"),
		)

		_ = raw.Close()

		return nil, nil, false
	}

	leaf := state.PeerCertificates[0]

	identity, err := admitDeviceLeaf(leaf)
	if err != nil {
		mgr.log.Info("Device caller refused", slog.String("remote", raw.RemoteAddr().String()),
			slog.Any("err", err),
		)

		_ = raw.Close()

		return nil, nil, false
	}

	view := mgr.view()
	sess := mgr.newDeviceSession(raw, tc, leaf, identity, view.Self)

	// The handshake checked this too; what changed since then is what this catches,
	// first before the session exists and again once it is registered, so an update
	// that lands in between cannot leave an unallowed session open.
	err = mgr.allowedDevice(view, &sess.rule, mgr.now())
	if err == nil && !mgr.registerDevice(sess) {
		err = errClosed
	}

	if err == nil {
		if why := mgr.deviceVerdictNow(sess); why != "" {
			err = fmt.Errorf("%w: %s", errDeviceClosed, why)
		}
	}

	if err != nil {
		mgr.log.Info(
			"Device caller refused",
			slog.String("remote", raw.RemoteAddr().String()),
			slog.String("peer", identity),
			slog.Any("err", err),
		)
		sess.abort()

		return nil, nil, false
	}

	return sess, tc, true
}

func (mgr *Manager) registerDevice(sess *deviceSession) bool {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()

	if mgr.closed {
		return false
	}

	mgr.devSessions[sess] = struct{}{}

	return true
}

// deviceVerdict says why a session may no longer continue, or "" when it may: the
// home gate is closed (active is false, with why), or the device is no longer
// allowed.
func (mgr *Manager) deviceVerdict(
	sess *deviceSession,
	view *View,
	now time.Time,
	active bool,
	why string,
) string {
	if !active {
		return why
	}

	err := mgr.allowedDevice(view, &sess.rule, now)
	if err != nil {
		return err.Error()
	}

	return ""
}

// deviceVerdictNow is deviceVerdict against the current state. The gateway is not
// asked, as in the periodic sweep: the check on a network change does that.
func (mgr *Manager) deviceVerdictNow(sess *deviceSession) string {
	view := mgr.view()
	ok, reason := mgr.active(view, false)

	return mgr.deviceVerdict(sess, view, mgr.now(), ok, reason)
}

func (mgr *Manager) closeDeviceWhere(reason func(*deviceSession) string) {
	type victim struct {
		s      *deviceSession
		reason string
	}

	var victims []victim

	mgr.mu.Lock()

	for s := range mgr.devSessions {
		if r := reason(s); r != "" {
			victims = append(victims, victim{s, r})
		}
	}

	mgr.mu.Unlock()

	for _, victim := range victims {
		mgr.closeDevice(victim.s, victim.reason)
	}
}

// closeDevice ends a session at once, and logs it when this call did.
func (mgr *Manager) closeDevice(sess *deviceSession, reason string) {
	if sess.abort() {
		mgr.log.Info("Closing device session",
			slog.String("peer", sess.identity),
			slog.String("fingerprint", sess.fp),
			slog.String("reason", reason),
		)
	}
}

// hostAllowed reports whether host names this machine's T3 as viewers know it:
// t3.<machine>.<viewer domain>, in any case, with or without the port 443.
func (view *View) hostAllowed(host string) bool {
	if view.Self == "" || view.ViewerDomain == "" {
		return false
	}

	want := strings.ToLower(DeviceSvc + "." + view.Self + "." + view.ViewerDomain)

	return strings.TrimSuffix(strings.ToLower(host), hostPortSuffix) == want
}

// serveDeviceRequest serves one request of an admitted connection. The session is
// checked again first, so a request never runs on a connection whose caller was
// refused after the last sweep.
func (mgr *Manager) serveDeviceRequest(w http.ResponseWriter, r *http.Request) {
	sess, ok := r.Context().Value(deviceSessionKey{}).(*deviceSession)
	if !ok {
		http.Error(w, "forbidden", http.StatusForbidden)

		return
	}

	if why := mgr.deviceVerdictNow(sess); why != "" {
		mgr.closeDevice(sess, why)

		return
	}

	view := mgr.view()
	if !view.hostAllowed(r.Host) {
		http.Error(w, "misdirected request", http.StatusMisdirectedRequest)

		return
	}

	if r.URL.Path == ProbePath {
		mgr.serveProbe(w, r, sess, view.Self)

		return
	}

	upgrade := strings.EqualFold(r.Header.Get("Upgrade"), "websocket")

	level := slog.LevelDebug
	if upgrade {
		level = slog.LevelInfo
	}

	mgr.log.Log(r.Context(), level, "Device stream",
		slog.String("peer", sess.identity),
		slog.String("uri", policy.IdentityURI(sess.identity)),
		slog.String("fingerprint", sess.fp),
		slog.Bool("upgrade", upgrade),
	)

	sess.proxy.ServeHTTP(w, r)
}

// serveProbe answers the side-effect-free probe the app uses to choose a path:
// who the listener took the caller for, on which machine. It is never proxied.
func (mgr *Manager) serveProbe(
	w http.ResponseWriter,
	r *http.Request,
	sess *deviceSession,
	self string,
) {
	w.Header().Set("Cache-Control", "no-store")

	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)

		return
	}

	body, err := json.Marshal(deviceProbe{Machine: self, Identity: sess.identity})
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)

		return
	}

	w.Header().Set("Content-Type", "application/json")

	_, err = w.Write(body)
	if err != nil {
		mgr.log.DebugContext(r.Context(), "Device probe write failed", slog.Any("err", err))
	}
}
