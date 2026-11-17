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
)

// Errors returned by Dial. Any error means "use the tunnel".
var (
	ErrInactive   = errors.New("direct: not active")
	ErrNoPeer     = errors.New("direct: peer not reachable directly")
	ErrRecentFail = errors.New("direct: recent failure for peer")
	ErrRefused    = errors.New("direct: refused by peer")
)

// View is a snapshot of the agent's current state. The agent core supplies a
// fresh one on every call to Options.View; it may change at any time.
type View struct {
	// Self is this machine's name.
	Self string
	// Identity is the current identity certificate; Leaf must be set.
	Identity tls.Certificate
	// Roots is the clients CA trust bundle.
	Roots       *x509.CertPool
	Rules       proto.Rules
	Revocations proto.Revocations
	Peers       []proto.Peer
	// SelfHome is the hub's verdict that this machine is home.
	SelfHome       bool
	HubConnected   bool
	LastHubContact time.Time
	// HomeGatewayMAC is the default gateway MAC cached during the last
	// hub-confirmed home session.
	HomeGatewayMAC string
	// HomePrefixes are the hub's homeCIDRs. The hub knows them; the agent core
	// obtains them from its configuration or a future protocol field. The
	// listener binds only local addresses inside these prefixes.
	HomePrefixes []netip.Prefix
}

// Options configures a Manager.
type Options struct {
	Port     int
	CacheTTL time.Duration
	// Serve maps a service name to the local address direct callers reach.
	Serve map[string]string
	View  func() View
	Log   *slog.Logger
	Now   func() time.Time
	// GatewayMAC returns the default gateway MAC; defaults to netwatch.
	GatewayMAC func() (string, error)
	// LocalAddrs lists local unicast addresses; defaults to netwatch.
	LocalAddrs func() ([]netip.Addr, error)
	// Dial opens outbound TCP connections (peers and local serve targets).
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
}

// Manager runs the direct listeners, dialer and live-session tracking.
type Manager struct {
	opts Options
	log  *slog.Logger

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	reconcileMu sync.Mutex

	mu        sync.Mutex
	closed    bool
	listeners map[netip.Addr]net.Listener
	sessions  map[*session]struct{}
	pending   map[net.Conn]struct{}
	failures  map[string]time.Time
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
	m := &Manager{
		opts:      opts,
		log:       opts.Log.With("component", "direct"),
		ctx:       ctx,
		cancel:    cancel,
		listeners: make(map[netip.Addr]net.Listener),
		sessions:  make(map[*session]struct{}),
		pending:   make(map[net.Conn]struct{}),
		failures:  make(map[string]time.Time),
	}

	m.wg.Add(1)

	go m.sweepLoop()

	return m
}

func defaultGatewayMAC() (string, error) {
	_, mac, err := netwatch.DefaultGatewayMAC()
	if err != nil {
		return "", fmt.Errorf("default gateway MAC: %w", err)
	}

	return mac.String(), nil
}

func keepAlive() net.KeepAliveConfig {
	return net.KeepAliveConfig{Enable: true, Idle: keepIdle, Interval: keepInterval, Count: keepCount}
}

func defaultDial(ctx context.Context, network, addr string) (net.Conn, error) {
	d := net.Dialer{KeepAliveConfig: keepAlive()}

	c, err := d.DialContext(ctx, network, addr)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}

	return c, nil
}

func (m *Manager) view() View { return m.opts.View() }

func (m *Manager) now() time.Time { return m.opts.Now() }

// Active reports whether direct connections are currently allowed and, when
// not, why.
func (m *Manager) Active() (bool, string) {
	return m.active(m.view(), true)
}

func (m *Manager) active(v View, checkGateway bool) (bool, string) {
	if v.HubConnected {
		if v.SelfHome {
			return true, ""
		}

		return false, "hub reports this machine is not home"
	}

	c := state.Cache{LastHubContact: v.LastHubContact}
	if !c.WithinWindow(m.now(), m.opts.CacheTTL) {
		return false, "hub unreachable and cache window over"
	}

	if v.HomeGatewayMAC == "" {
		return false, "hub unreachable and no cached home gateway"
	}

	if !checkGateway {
		return true, ""
	}

	mac, err := m.opts.GatewayMAC()
	if err != nil {
		return false, fmt.Sprintf("hub unreachable and gateway unknown: %v", err)
	}

	if !sameMAC(mac, v.HomeGatewayMAC) {
		return false, "hub unreachable and gateway differs from home"
	}

	return true, ""
}

func sameMAC(a, b string) bool {
	ha, errA := net.ParseMAC(a)
	hb, errB := net.ParseMAC(b)

	if errA == nil && errB == nil {
		return ha.String() == hb.String()
	}

	return strings.EqualFold(a, b)
}

// Sessions returns the number of live direct sessions in both directions.
func (m *Manager) Sessions() int {
	m.mu.Lock()
	defer m.mu.Unlock()

	return len(m.sessions)
}

// Close stops listeners, closes every session and waits for goroutines.
func (m *Manager) Close() error {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()

		return nil
	}

	m.closed = true
	lns := m.listeners
	m.listeners = make(map[netip.Addr]net.Listener)
	sess := make([]*session, 0, len(m.sessions))

	for s := range m.sessions {
		sess = append(sess, s)
	}

	pend := make([]net.Conn, 0, len(m.pending))
	for c := range m.pending {
		pend = append(pend, c)
	}

	m.mu.Unlock()

	m.cancel()

	for _, l := range lns {
		_ = l.Close()
	}

	for _, s := range sess {
		_ = s.close()
	}

	for _, c := range pend {
		_ = c.Close()
	}

	m.wg.Wait()

	return nil
}

// Reconcile aligns listeners and sessions with the current state. The agent
// core calls it on start, on every view change, on network events and on wake.
func (m *Manager) Reconcile(ctx context.Context) {
	m.reconcileMu.Lock()
	defer m.reconcileMu.Unlock()

	if ctx.Err() != nil {
		return
	}

	v := m.view()
	ok, reason := m.active(v, true)

	local, err := m.opts.LocalAddrs()
	if err != nil {
		m.log.Warn("list local addresses", "err", err)
	}

	want := make(map[netip.Addr]struct{})

	if ok && err == nil {
		for _, a := range netwatch.AddrsIn(local, v.HomePrefixes) {
			a = a.Unmap()
			if a.IsUnspecified() || a.Zone() != "" || (a.Is6() && a.IsLinkLocalUnicast()) {
				continue
			}

			want[a] = struct{}{}
		}
	}

	m.syncListeners(ctx, want, v.Self)

	if !ok {
		m.log.Debug("direct inactive", "reason", reason)
	}

	if err == nil {
		present := make(map[netip.Addr]struct{}, len(local))
		for _, a := range local {
			present[a.Unmap()] = struct{}{}
		}

		m.closeWhere(func(s *session) string {
			if _, there := present[s.local]; !there {
				return "local address gone"
			}

			return ""
		})
	}

	m.recheck(true)
}

func (m *Manager) syncListeners(ctx context.Context, want map[netip.Addr]struct{}, self string) {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()

		return
	}

	var stale []net.Listener

	for a, l := range m.listeners {
		if _, ok := want[a]; !ok {
			stale = append(stale, l)

			delete(m.listeners, a)
		}
	}

	var add []netip.Addr

	for a := range want {
		if _, ok := m.listeners[a]; !ok {
			add = append(add, a)
		}
	}

	m.mu.Unlock()

	for _, l := range stale {
		m.log.Info("direct listener closed", "addr", l.Addr().String())

		_ = l.Close()
	}

	lc := net.ListenConfig{KeepAliveConfig: keepAlive()}

	for _, a := range add {
		ap := netip.AddrPortFrom(a, uint16(m.opts.Port)) //nolint:gosec // port validated by config
		ln, err := lc.Listen(ctx, "tcp", ap.String())

		if err != nil {
			m.log.Warn("direct listen failed", "addr", ap.String(), "err", err)

			continue
		}

		m.mu.Lock()
		if m.closed {
			m.mu.Unlock()

			_ = ln.Close()

			return
		}

		m.listeners[a] = ln
		m.wg.Add(1)
		m.mu.Unlock()

		m.log.Info("direct listener open", "addr", ap.String(), "self", self)

		go m.acceptLoop(ln)
	}
}

// Listening returns the addresses currently bound.
func (m *Manager) Listening() []netip.AddrPort {
	m.mu.Lock()
	defer m.mu.Unlock()

	out := make([]netip.AddrPort, 0, len(m.listeners))
	for _, l := range m.listeners {
		if ta, ok := l.Addr().(*net.TCPAddr); ok {
			out = append(out, ta.AddrPort())
		}
	}

	return out
}

// session is one live direct connection, either direction.
type session struct {
	m            *Manager
	dir          string
	conn         net.Conn
	local        netip.Addr
	peerID       string
	peerFP       string
	peerNotAfter time.Time
	// rule is what policy.Check evaluates: the caller's identity against the
	// service on the target machine.
	rule policy.Session

	once sync.Once
	err  error
}

func (s *session) close() error {
	s.once.Do(func() {
		s.m.mu.Lock()
		delete(s.m.sessions, s)
		s.m.mu.Unlock()

		s.err = s.conn.Close()
	})

	return s.err
}

func localAddrOf(c net.Conn) netip.Addr {
	if ta, ok := c.LocalAddr().(*net.TCPAddr); ok {
		return ta.AddrPort().Addr().Unmap()
	}

	return netip.Addr{}
}

func (m *Manager) register(s *session) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return false
	}

	m.sessions[s] = struct{}{}

	return true
}

// allowed re-evaluates a session against v.
func (m *Manager) allowed(s *session, v View, now time.Time) error {
	if err := policy.Revoked(v.Revocations, s.peerID, s.peerFP); err != nil {
		return fmt.Errorf("peer: %w", err)
	}

	if !s.peerNotAfter.IsZero() && !now.Before(s.peerNotAfter) {
		return fmt.Errorf("%w: peer %s", policy.ErrExpired, s.peerID)
	}

	if err := policy.Check(v.Rules, v.Revocations, s.rule, now); err != nil {
		return fmt.Errorf("check: %w", err)
	}

	return nil
}

// Recheck closes sessions that are no longer allowed: revoked, rule removed,
// expired, or beyond the cache window while the hub is unreachable.
func (m *Manager) Recheck() { m.recheck(true) }

func (m *Manager) recheck(checkGateway bool) {
	v := m.view()
	now := m.now()
	ok, reason := m.active(v, checkGateway)

	m.closeWhere(func(s *session) string {
		if !ok {
			return reason
		}

		if err := m.allowed(s, v, now); err != nil {
			return err.Error()
		}

		return ""
	})
}

func (m *Manager) closeWhere(reason func(*session) string) {
	type victim struct {
		s      *session
		reason string
	}

	var victims []victim

	m.mu.Lock()

	for s := range m.sessions {
		if r := reason(s); r != "" {
			victims = append(victims, victim{s, r})
		}
	}

	m.mu.Unlock()

	for _, v := range victims {
		m.log.Info("closing direct session", "dir", v.s.dir, "peer", v.s.peerID, "svc", v.s.rule.Svc, "reason", v.reason)

		_ = v.s.close()
	}
}

func (m *Manager) sweepLoop() {
	defer m.wg.Done()

	t := time.NewTicker(SweepInterval)
	defer t.Stop()

	for {
		select {
		case <-m.ctx.Done():
			return
		case <-t.C:
			m.recheck(false)
		}
	}
}

func leafOf(c tls.Certificate) (*x509.Certificate, error) {
	if c.Leaf != nil {
		return c.Leaf, nil
	}

	if len(c.Certificate) == 0 {
		return nil, errors.New("direct: no identity certificate")
	}

	leaf, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("direct: parse identity: %w", err)
	}

	return leaf, nil
}
