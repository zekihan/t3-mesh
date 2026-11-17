// Package direct implements the agent's direct bypass: an mTLS listener on the
// home LAN and a dialer that reaches peers on their LAN addresses without the
// tunnel. It does not know about the tunnel; the agent core supplies the
// current state through Options.View and falls back to the tunnel whenever
// Dial returns an error.
package direct

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/zekihan/t3-mesh/internal/agent/state"
	"github.com/zekihan/t3-mesh/internal/netwatch"
	"github.com/zekihan/t3-mesh/internal/policy"
	"github.com/zekihan/t3-mesh/internal/proto"
)

// Timing from the design.
const (
	SetupTimeout     = time.Second
	FailureMemory    = 60 * time.Second
	SweepInterval    = time.Second
	DefaultCacheTTL  = 7 * 24 * time.Hour
	serverSetupLimit = 5 * time.Second
	keepIdle         = 15 * time.Second
	keepInterval     = 5 * time.Second
	keepCount        = 3
	acceptRetryDelay = 50 * time.Millisecond
)

// Errors returned by Dial. Any error means "use the tunnel".
var (
	ErrInactive   = errors.New("direct: not active")
	ErrNoPeer     = errors.New("direct: peer not reachable directly")
	ErrRecentFail = errors.New("direct: recent failure for peer")
	ErrRefused    = errors.New("direct: refused by peer")
)

var (
	errSetupDeadline    = errors.New("setup deadline exceeded")
	errNoTrustBundle    = errors.New("direct: no trust bundle")
	errIdentityMismatch = errors.New("direct: server identity mismatch")
	errBadALPN          = errors.New("direct: bad alpn")
	errClosed           = errors.New("direct: closed")
	errNoIdentityCert   = errors.New("direct: no identity certificate")
	errNoIdentity       = errors.New("direct: no identity")
)

// View is a snapshot of the agent's current state. The agent core supplies a
// fresh one on every call to Options.View; it may change at any time.
type View struct {
	Identity       tls.Certificate
	Rules          proto.Rules
	LastHubContact time.Time
	Roots          *x509.CertPool
	Self           string
	HomeGatewayMAC string
	Revocations    proto.Revocations
	Peers          []proto.Peer
	HomePrefixes   []netip.Prefix
	SelfHome       bool
	HubConnected   bool
}

// Options configures a Manager.
type Options struct {
	Serve      map[string]string
	View       func() View
	Log        *slog.Logger
	Now        func() time.Time
	GatewayMAC func() (string, error)
	LocalAddrs func() ([]netip.Addr, error)
	Dial       func(ctx context.Context, network, addr string) (net.Conn, error)
	Port       int
	CacheTTL   time.Duration
}

// Manager runs the direct listeners, dialer and live-session tracking.
type Manager struct {
	ctx       context.Context //nolint:containedctx // root context of the listeners
	log       *slog.Logger
	cancel    context.CancelFunc
	listeners map[netip.Addr]net.Listener
	sessions  map[*session]struct{}
	pending   map[net.Conn]struct{}
	failures  map[string]time.Time
	// The last logged listen decision; guarded by reconcileMu.
	lastDecision string
	opts         Options
	wg           sync.WaitGroup
	reconcileMu  sync.Mutex
	mu           sync.Mutex
	closed       bool
}

// New returns a started Manager. Call Reconcile to bind listeners.
func New(opts Options) *Manager {
	if opts.Log == nil {
		opts.Log = slog.Default()
	}

	if opts.Now == nil {
		opts.Now = time.Now
	}

	if opts.CacheTTL <= 0 {
		opts.CacheTTL = DefaultCacheTTL
	}

	if opts.GatewayMAC == nil {
		opts.GatewayMAC = defaultGatewayMAC
	}

	if opts.LocalAddrs == nil {
		opts.LocalAddrs = netwatch.LocalAddrs
	}

	if opts.Dial == nil {
		opts.Dial = defaultDial
	}

	ctx, cancel := context.WithCancel(context.Background())
	mgr := &Manager{
		opts:      opts,
		log:       opts.Log.With(slog.String("component", "direct")),
		ctx:       ctx,
		cancel:    cancel,
		listeners: make(map[netip.Addr]net.Listener),
		sessions:  make(map[*session]struct{}),
		pending:   make(map[net.Conn]struct{}),
		failures:  make(map[string]time.Time),
	}

	mgr.wg.Add(1)

	go mgr.sweepLoop()

	return mgr
}

func defaultGatewayMAC() (string, error) {
	_, mac, err := netwatch.DefaultGatewayMAC()
	if err != nil {
		return "", fmt.Errorf("default gateway MAC: %w", err)
	}

	return mac.String(), nil
}

func keepAlive() net.KeepAliveConfig {
	return net.KeepAliveConfig{
		Enable:   true,
		Idle:     keepIdle,
		Interval: keepInterval,
		Count:    keepCount,
	}
}

func defaultDial(ctx context.Context, network, addr string) (net.Conn, error) {
	d := net.Dialer{KeepAliveConfig: keepAlive()}

	c, err := d.DialContext(ctx, network, addr)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}

	return c, nil
}

// Active reports whether direct connections are currently allowed and, when
// not, why.
func (mgr *Manager) Active() (bool, string) {
	return mgr.active(mgr.view(), true)
}

func sameMAC(left, right string) bool {
	ha, errA := net.ParseMAC(left)
	hb, errB := net.ParseMAC(right)

	if errA == nil && errB == nil {
		return ha.String() == hb.String()
	}

	return strings.EqualFold(left, right)
}

// Sessions returns the number of live direct sessions in both directions.
func (mgr *Manager) Sessions() int {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()

	return len(mgr.sessions)
}

// Close stops listeners, closes every session and waits for goroutines.
func (mgr *Manager) Close() error {
	mgr.mu.Lock()
	if mgr.closed {
		mgr.mu.Unlock()

		return nil
	}

	mgr.closed = true
	lns := mgr.listeners
	mgr.listeners = make(map[netip.Addr]net.Listener)
	sess := make([]*session, 0, len(mgr.sessions))

	for s := range mgr.sessions {
		sess = append(sess, s)
	}

	pend := make([]net.Conn, 0, len(mgr.pending))
	for c := range mgr.pending {
		pend = append(pend, c)
	}

	mgr.mu.Unlock()

	mgr.cancel()

	for _, l := range lns {
		_ = l.Close()
	}

	for _, s := range sess {
		_ = s.close()
	}

	for _, c := range pend {
		_ = c.Close()
	}

	mgr.wg.Wait()

	return nil
}

// Reconcile aligns listeners and sessions with the current state. The agent
// core calls it on start, on every view change, on network events and on wake.
func (mgr *Manager) Reconcile(ctx context.Context) {
	mgr.reconcileMu.Lock()
	defer mgr.reconcileMu.Unlock()

	if ctx.Err() != nil {
		return
	}

	view := mgr.view()
	ok, reason := mgr.active(view, true)

	local, err := mgr.opts.LocalAddrs()
	if err != nil {
		mgr.log.WarnContext(ctx, "List local addresses", slog.Any("err", err))
	}

	want := make(map[netip.Addr]struct{})

	if ok && err == nil {
		want = listenAddrs(local, view.HomePrefixes)
	}

	mgr.syncListeners(ctx, want, view.Self)

	if ok && err == nil && len(want) == 0 {
		ok, reason = false, "no local address in the home prefixes"
	}

	mgr.logDecision(ctx, ok, reason)

	if err == nil {
		present := make(map[netip.Addr]struct{}, len(local))
		for _, a := range local {
			present[a.Unmap()] = struct{}{}
		}

		mgr.closeWhere(func(s *session) string {
			if _, there := present[s.local]; !there {
				return "local address gone"
			}

			return ""
		})
	}

	mgr.recheck(true)
}

// Listening returns the addresses currently bound.
func (mgr *Manager) Listening() []netip.AddrPort {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()

	out := make([]netip.AddrPort, 0, len(mgr.listeners))
	for _, l := range mgr.listeners {
		if ta, ok := l.Addr().(*net.TCPAddr); ok {
			out = append(out, ta.AddrPort())
		}
	}

	return out
}

// session is one live direct connection, either direction.
type session struct {
	local        netip.Addr
	peerNotAfter time.Time
	conn         net.Conn
	err          error
	m            *Manager
	rule         policy.Session
	dir          string
	peerID       string
	peerFP       string
	once         sync.Once
}

func (sess *session) close() error {
	sess.once.Do(func() {
		sess.m.mu.Lock()
		delete(sess.m.sessions, sess)
		sess.m.mu.Unlock()

		sess.err = sess.conn.Close()
	})

	return sess.err
}

func localAddrOf(c net.Conn) netip.Addr {
	if ta, ok := c.LocalAddr().(*net.TCPAddr); ok {
		return ta.AddrPort().Addr().Unmap()
	}

	return netip.Addr{}
}

// Recheck closes sessions that are no longer allowed: revoked, rule removed,
// expired, or beyond the cache window while the hub is unreachable.
func (mgr *Manager) Recheck() { mgr.recheck(true) }

func (mgr *Manager) view() *View {
	current := mgr.opts.View()

	return &current
}

func (mgr *Manager) now() time.Time { return mgr.opts.Now() }

func (mgr *Manager) active(view *View, checkGateway bool) (bool, string) {
	if view.HubConnected {
		if view.SelfHome {
			return true, ""
		}

		return false, "hub reports this machine is not home"
	}

	c := state.Cache{LastHubContact: view.LastHubContact}
	if !c.WithinWindow(mgr.now(), mgr.opts.CacheTTL) {
		return false, "hub unreachable and cache window over"
	}

	if view.HomeGatewayMAC == "" {
		return false, "hub unreachable and no cached home gateway"
	}

	if !checkGateway {
		return true, ""
	}

	mac, err := mgr.opts.GatewayMAC()
	if err != nil {
		return false, fmt.Sprintf("hub unreachable and gateway unknown: %v", err)
	}

	if !sameMAC(mac, view.HomeGatewayMAC) {
		return false, "hub unreachable and gateway differs from home"
	}

	return true, ""
}

// listenAddrs returns the local addresses inside the home prefixes that a
// direct listener may bind: no unspecified, zoned or link-local addresses.
func listenAddrs(local []netip.Addr, prefixes []netip.Prefix) map[netip.Addr]struct{} {
	want := make(map[netip.Addr]struct{})

	for _, a := range netwatch.AddrsIn(local, prefixes) {
		a = a.Unmap()
		if a.IsUnspecified() || a.Zone() != "" || (a.Is6() && a.IsLinkLocalUnicast()) {
			continue
		}

		want[a] = struct{}{}
	}

	return want
}

// logDecision logs whether direct is active, and why not, each time that
// changes, so outage-mode choices show up in the log without repeating every
// reconcile. Callers hold reconcileMu.
func (mgr *Manager) logDecision(ctx context.Context, ok bool, reason string) {
	decision := "active"
	if !ok {
		decision = "inactive: " + reason
	}

	if decision == mgr.lastDecision {
		return
	}

	mgr.lastDecision = decision

	if ok {
		mgr.log.InfoContext(ctx, "Direct active")

		return
	}

	mgr.log.InfoContext(ctx, "Direct inactive", slog.String("reason", reason))
}

func (mgr *Manager) syncListeners(ctx context.Context, want map[netip.Addr]struct{}, self string) {
	mgr.mu.Lock()
	if mgr.closed {
		mgr.mu.Unlock()

		return
	}

	var stale []net.Listener

	for a, l := range mgr.listeners {
		if _, ok := want[a]; !ok {
			stale = append(stale, l)

			delete(mgr.listeners, a)
		}
	}

	var add []netip.Addr

	for a := range want {
		if _, ok := mgr.listeners[a]; !ok {
			add = append(add, a)
		}
	}

	mgr.mu.Unlock()

	for _, l := range stale {
		mgr.log.InfoContext(ctx, "Direct listener closed", slog.String("addr", l.Addr().String()))

		_ = l.Close()
	}

	lc := net.ListenConfig{KeepAliveConfig: keepAlive()}

	for _, addr := range add {
		port := uint16(mgr.opts.Port) //nolint:gosec // port validated by config
		ap := netip.AddrPortFrom(addr, port)

		ln, err := lc.Listen(ctx, "tcp", ap.String())
		if err != nil {
			mgr.log.WarnContext(ctx, "Direct listen failed", slog.String("addr", ap.String()),
				slog.Any("err", err),
			)

			continue
		}

		mgr.mu.Lock()
		if mgr.closed {
			mgr.mu.Unlock()

			_ = ln.Close()

			return
		}

		mgr.listeners[addr] = ln
		mgr.wg.Add(1)
		mgr.mu.Unlock()

		mgr.log.InfoContext(ctx, "Direct listener open", slog.String("addr", ap.String()),
			slog.String("self", self),
		)

		go mgr.acceptLoop(ln) //nolint:contextcheck // listeners run on the manager ctx
	}
}

func (mgr *Manager) register(sess *session) bool {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()

	if mgr.closed {
		return false
	}

	mgr.sessions[sess] = struct{}{}

	return true
}

// allowed re-evaluates a session against v.
func (mgr *Manager) allowed(sess *session, view *View, now time.Time) error {
	err := policy.Revoked(view.Revocations, sess.peerID, sess.peerFP)
	if err != nil {
		return fmt.Errorf("peer: %w", err)
	}

	if !sess.peerNotAfter.IsZero() && !now.Before(sess.peerNotAfter) {
		return fmt.Errorf("%w: peer %s", policy.ErrExpired, sess.peerID)
	}

	err = policy.Check(view.Rules, view.Revocations, sess.rule, now)
	if err != nil {
		return fmt.Errorf("check: %w", err)
	}

	return nil
}

func (mgr *Manager) recheck(checkGateway bool) {
	view := mgr.view()
	now := mgr.now()
	ok, reason := mgr.active(view, checkGateway)

	mgr.closeWhere(func(s *session) string {
		if !ok {
			return reason
		}

		err := mgr.allowed(s, view, now)
		if err != nil {
			return err.Error()
		}

		return ""
	})
}

func (mgr *Manager) closeWhere(reason func(*session) string) {
	type victim struct {
		s      *session
		reason string
	}

	var victims []victim

	mgr.mu.Lock()

	for s := range mgr.sessions {
		if r := reason(s); r != "" {
			victims = append(victims, victim{s, r})
		}
	}

	mgr.mu.Unlock()

	for _, victim := range victims {
		mgr.log.Info(
			"Closing direct session",
			slog.String("dir", victim.s.dir),
			slog.String("peer", victim.s.peerID),
			slog.String("svc", victim.s.rule.Svc),
			slog.String("reason", victim.reason),
		)

		_ = victim.s.close()
	}
}

func (mgr *Manager) sweepLoop() {
	defer mgr.wg.Done()

	ticker := time.NewTicker(SweepInterval)
	defer ticker.Stop()

	for {
		select {
		case <-mgr.ctx.Done():
			return
		case <-ticker.C:
			mgr.recheck(false)
		}
	}
}

func leafOf(cert *tls.Certificate) (*x509.Certificate, error) {
	if cert.Leaf != nil {
		return cert.Leaf, nil
	}

	if len(cert.Certificate) == 0 {
		return nil, errNoIdentityCert
	}

	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("direct: parse identity: %w", err)
	}

	return leaf, nil
}
