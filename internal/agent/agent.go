// Package agent is the t3-mesh agent core: it keeps the tunnel to the hub,
// serves hub-relayed streams to local services, runs the loopback link ports,
// drives the direct bypass and the updater, and renews the agent certificate.
package agent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zekihan/t3-mesh/internal/agent/agentconfig"
	"github.com/zekihan/t3-mesh/internal/agent/direct"
	"github.com/zekihan/t3-mesh/internal/agent/state"
	"github.com/zekihan/t3-mesh/internal/agent/updater"
	"github.com/zekihan/t3-mesh/internal/launcher"
	"github.com/zekihan/t3-mesh/internal/netwatch"
	"github.com/zekihan/t3-mesh/internal/pki"
	"github.com/zekihan/t3-mesh/internal/release"
)

// Timing defaults.
const (
	defaultBackoffBase  = time.Second
	defaultBackoffMax   = 30 * time.Second
	stableAfter         = 30 * time.Second
	defaultStatusEvery  = 60 * time.Second
	defaultRenewEvery   = time.Hour
	defaultRenewWindow  = 90 * 24 * time.Hour
	defaultRenewRetry   = time.Hour
	saveThrottle        = time.Minute
	maxWarnings         = 10
	healthAliveInterval = 10 * time.Second
	dnsRecheckInterval  = 30 * time.Second
	pingProbeTimeout    = 2 * time.Second
	lookupTimeout       = 5 * time.Second
	shutdownWait        = 5 * time.Second
	maxBackoffShift     = 30
)

var (
	errConfigRequired   = errors.New("agent: config is required")
	errTokenRequired    = errors.New("enroll: token is required")
	errIdentityMismatch = errors.New("identity mismatch")
	errEnrollRejected   = errors.New("enroll: hub rejected")
	errUnexpectedReply  = errors.New("unexpected reply")
	errRenewRefused     = errors.New("hub refused renewal")
	errRenewSessionDone = errors.New("session closed during renewal")
	errNoRenewReply     = errors.New("no renewal reply from hub")
	errNoHelloAck       = errors.New("no HelloAck from hub")
)

// Options configures an Agent.
type Options struct {
	Health     updater.HealthSink
	Config     *agentconfig.Config
	Log        *slog.Logger
	Now        func() time.Time
	HubTLS     *tls.Config
	LocalAddrs func() ([]netip.Addr, error)
	GatewayMAC func() (string, error)

	// NetEvents replaces netwatch.Watch as the source of network events.
	// Production leaves it nil.
	NetEvents <-chan netwatch.Event
	// LookupHost replaces the hub DNS lookup. Production leaves it nil.
	LookupHost func(ctx context.Context, host string) ([]string, error)
	// AddrPresent replaces the local-address check. Production leaves it nil.
	AddrPresent func(netip.Addr) bool
	Version     string
	// DNSRecheckInterval replaces the 30 s DNS backstop when positive.
	DNSRecheckInterval time.Duration
}

// Agent is the running agent.
type Agent struct {
	ident        tls.Certificate
	renewAfter   time.Time
	lastHelloAck time.Time
	lastSave     time.Time
	health       updater.HealthSink
	ctx          context.Context //nolint:containedctx // root context of the background goroutines
	localAddrs   func() ([]netip.Addr, error)
	now          func() time.Time
	addrPresent  func(netip.Addr) bool
	gatewayMAC   func() (string, error)
	cfg          *agentconfig.Config
	renewKick    chan struct{}
	statusNudge  chan struct{}
	curChanged   chan struct{}
	kick         chan struct{}
	log          *slog.Logger
	baseLog      *slog.Logger
	lookupHost   func(ctx context.Context, host string) ([]netip.Addr, error)
	netEvents    <-chan netwatch.Event
	hubTLS       *tls.Config
	live         map[*session]struct{}
	direct       *direct.Manager
	upd          *updater.Updater
	cur          *session
	roots        *x509.CertPool
	cache        *state.Cache
	version      string
	rootsPEM     string
	store        pki.Store
	prefixes     []netip.Prefix
	warnings     []string
	wg           sync.WaitGroup
	dnsEvery     time.Duration
	renewWindow  time.Duration
	renewRetry   time.Duration
	renewEvery   time.Duration
	statusEvery  time.Duration
	backoffMax   time.Duration
	backoffBase  time.Duration
	mu           sync.Mutex
	saveMu       sync.Mutex
	dialMu       sync.Mutex
	renewing     atomic.Bool
}

// New validates opts and returns an Agent. Identity and state are loaded by Run.
func New(
	opts Options, //nolint:gocritic // Options is passed by value in the public API
) (*Agent, error) {
	if opts.Config == nil {
		return nil, errConfigRequired
	}

	if opts.Log == nil {
		opts.Log = slog.Default()
	}

	if opts.Now == nil {
		opts.Now = time.Now
	}

	agent := &Agent{
		cfg:         opts.Config,
		log:         opts.Log.With(slog.String("component", "agent")),
		baseLog:     opts.Log,
		now:         opts.Now,
		version:     opts.Version,
		store:       pki.Store{Dir: opts.Config.Identity.Dir},
		hubTLS:      opts.HubTLS,
		health:      opts.Health,
		gatewayMAC:  defaultGatewayMAC,
		localAddrs:  netwatch.LocalAddrs,
		addrPresent: defaultAddrPresent,
		netEvents:   opts.NetEvents,
		dnsEvery:    dnsRecheckInterval,
		backoffBase: defaultBackoffBase,
		backoffMax:  defaultBackoffMax,
		statusEvery: defaultStatusEvery,
		renewEvery:  defaultRenewEvery,
		renewWindow: defaultRenewWindow,
		renewRetry:  defaultRenewRetry,
		live:        make(map[*session]struct{}),
		kick:        make(chan struct{}, 1),
		curChanged:  make(chan struct{}, 1),
		statusNudge: make(chan struct{}, 1),
		renewKick:   make(chan struct{}, 1),
	}
	agent.lookupHost = agent.defaultLookup

	if opts.LocalAddrs != nil {
		agent.localAddrs = opts.LocalAddrs
	}

	if opts.GatewayMAC != nil {
		agent.gatewayMAC = opts.GatewayMAC
	}

	if opts.LookupHost != nil {
		agent.lookupHost = stringLookup(opts.LookupHost)
	}

	if opts.AddrPresent != nil {
		agent.addrPresent = opts.AddrPresent
	}

	if opts.DNSRecheckInterval > 0 {
		agent.dnsEvery = opts.DNSRecheckInterval
	}

	return agent, nil
}

// stringLookup adapts a lookup that returns textual addresses. Entries that do
// not parse are dropped.
func stringLookup(
	lookup func(ctx context.Context, host string) ([]string, error),
) func(ctx context.Context, host string) ([]netip.Addr, error) {
	return func(ctx context.Context, host string) ([]netip.Addr, error) {
		raw, err := lookup(ctx, host)
		if err != nil {
			return nil, err
		}

		addrs := make([]netip.Addr, 0, len(raw))

		for _, text := range raw {
			ad, perr := netip.ParseAddr(text)
			if perr == nil {
				addrs = append(addrs, ad)
			}
		}

		return addrs, nil
	}
}

func defaultGatewayMAC() (string, error) {
	_, mac, err := netwatch.DefaultGatewayMAC()
	if err != nil {
		return "", fmt.Errorf("default gateway MAC: %w", err)
	}

	return mac.String(), nil
}

// defaultAddrPresent treats loopback as always present: LocalAddrs excludes it.
func defaultAddrPresent(a netip.Addr) bool {
	return a.IsLoopback() || netwatch.AddrPresent(a)
}

// Run starts the agent and blocks until ctx ends or startup fails. Startup
// loads the identity and cached state, binds every link port and reconciles the
// direct listener from cached state; only then does it report the local
// startup check to the launcher, so a hub outage never fails it.
func (agent *Agent) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	agent.ctx = ctx

	err := agent.loadLocal()
	if err != nil {
		return err
	}

	if agent.cfg.Direct.Enabled {
		agent.direct = direct.New(direct.Options{
			Port:     agent.cfg.Direct.Port,
			CacheTTL: agent.cfg.Direct.CacheTTL,
			Serve:    agent.cfg.Serve,
			View:     agent.view,
			Log:      agent.baseLog, // direct adds its own component

			Now:        agent.now,
			GatewayMAC: agent.gatewayMAC,
			LocalAddrs: agent.localAddrs,
		})

		defer func() { _ = agent.direct.Close() }()
	}

	links, err := agent.bindLinks(ctx)
	if err != nil {
		return err
	}

	defer func() {
		for _, l := range links {
			l.close()
		}
	}()

	if agent.direct != nil {
		agent.direct.Reconcile(ctx)
	}

	agent.setupUpdater()
	agent.startupOK()

	for _, l := range links {
		agent.wg.Go(l.serve)
	}

	agent.wg.Go(func() { agent.tunnelLoop(ctx) })
	agent.wg.Go(func() { agent.netLoop(ctx) })
	agent.wg.Go(func() { agent.statusLoop(ctx) })
	agent.wg.Go(func() { agent.renewLoop(ctx) })

	if agent.upd != nil {
		agent.wg.Go(func() {
			uerr := agent.upd.Run(ctx)
			if uerr != nil && !errors.Is(uerr, context.Canceled) {
				agent.log.ErrorContext(ctx, "Updater stopped", slog.Any("err", uerr))
			}
		})
	}

	<-ctx.Done()
	agent.closeLinks(links)
	agent.shutdown()

	return nil
}

func (agent *Agent) defaultLookup(ctx context.Context, host string) ([]netip.Addr, error) {
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("lookup %s: %w", host, err)
	}

	return addrs, nil
}

func (agent *Agent) shutdown() {
	agent.mu.Lock()

	sessions := make([]*session, 0, len(agent.live))
	for s := range agent.live {
		sessions = append(sessions, s)
	}
	agent.mu.Unlock()

	for _, s := range sessions {
		s.close()
	}

	done := make(chan struct{})

	go func() {
		agent.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(shutdownWait):
		agent.log.Warn("Shutdown timed out waiting for goroutines")
	}

	agent.saveCache()
}

func (agent *Agent) loadLocal() error {
	tc, _, err := agent.store.Load()
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf(
				"agent: no identity in %s, run `t3-mesh-agent enroll --token <token>` first: %w",
				agent.cfg.Identity.Dir,
				err,
			)
		}

		return fmt.Errorf("agent: load identity: %w", err)
	}

	cache, err := state.Load(agent.cfg.StateDir)
	if err != nil {
		return fmt.Errorf("agent: load state: %w", err)
	}

	agent.mu.Lock()
	agent.ident = tc
	agent.cache = cache
	agent.deriveLocked()
	agent.mu.Unlock()

	if tc.Leaf != nil && !agent.now().Before(tc.Leaf.NotAfter) {
		agent.log.Warn(
			"Identity certificate expired, re-enroll",
			slog.String("notAfter", tc.Leaf.NotAfter.Format(time.RFC3339)),
		)
	}

	return nil
}

// deriveLocked rebuilds the trust pool and home prefixes from the cache. Direct
// stays inactive until a trust bundle is cached: without roots there are no
// prefixes, so no listener binds, and dials fail fast in the direct package.
func (agent *Agent) deriveLocked() {
	if pem := agent.cache.TrustBundle.PEM; pem != agent.rootsPEM {
		agent.rootsPEM = pem
		agent.roots = nil

		if pem != "" {
			pool, err := pki.PoolFromPEM([]byte(pem))
			if err != nil {
				agent.log.Warn("Trust bundle unusable", slog.Any("err", err))
			} else {
				agent.roots = pool
			}
		}
	}

	agent.prefixes = agent.prefixes[:0:0]

	for _, c := range agent.cache.HomeCIDRs {
		prefix, err := netip.ParsePrefix(c)
		if err != nil {
			agent.log.Warn("Bad home cidr", slog.String("cidr", c),
				slog.Any("err", err),
			)

			continue
		}

		agent.prefixes = append(agent.prefixes, prefix.Masked())
	}
}

func (agent *Agent) view() direct.View {
	agent.mu.Lock()
	defer agent.mu.Unlock()

	self := agent.cache.Machine
	if self == "" {
		self = strings.TrimPrefix(agent.cfg.Identity.Name, "agent-")
	}

	var prefixes []netip.Prefix
	if agent.roots != nil {
		prefixes = agent.prefixes
	}

	return direct.View{
		Self:           self,
		Identity:       agent.ident,
		Roots:          agent.roots,
		Rules:          agent.cache.Rules,
		Revocations:    agent.cache.Revocations,
		Peers:          agent.cache.Peers.Peers,
		SelfHome:       agent.cache.Home,
		HubConnected:   agent.cur != nil,
		LastHubContact: agent.cache.LastHubContact,
		HomeGatewayMAC: agent.cache.HomeGatewayMAC,
		HomePrefixes:   prefixes,
	}
}

func (agent *Agent) identity() tls.Certificate {
	agent.mu.Lock()
	defer agent.mu.Unlock()

	return agent.ident
}

func (agent *Agent) current() *session {
	agent.mu.Lock()
	defer agent.mu.Unlock()

	return agent.cur
}

func (agent *Agent) warn(msg string) {
	agent.mu.Lock()
	defer agent.mu.Unlock()

	if len(agent.warnings) > 0 && agent.warnings[len(agent.warnings)-1] == msg {
		return
	}

	agent.warnings = append(agent.warnings, msg)
	if len(agent.warnings) > maxWarnings {
		agent.warnings = slices.Clone(agent.warnings[len(agent.warnings)-maxWarnings:])
	}
}

func (agent *Agent) saveCache() {
	agent.mu.Lock()
	if agent.cache == nil {
		agent.mu.Unlock()

		return
	}

	cache := *agent.cache
	agent.lastSave = agent.now()
	agent.mu.Unlock()

	agent.saveMu.Lock()
	defer agent.saveMu.Unlock()

	err := state.Save(agent.cfg.StateDir, &cache)
	if err != nil {
		agent.log.Error("State save failed", slog.Any("err", err))
	}
}

// touchHub records a successful hub contact, saving at most once a minute.
func (agent *Agent) touchHub() {
	agent.mu.Lock()
	now := agent.now()
	agent.cache.LastHubContact = now
	save := now.Sub(agent.lastSave) >= saveThrottle || agent.lastSave.IsZero()
	agent.mu.Unlock()

	if save {
		agent.saveCache()
	}
}

func (agent *Agent) reconcileDirect() {
	if agent.direct == nil {
		return
	}

	agent.direct.Recheck()
	agent.direct.Reconcile(agent.ctx)
}

func signal(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}

// setupUpdater enables self-update only for release builds running under the
// launcher; otherwise Restart would silently do nothing.
func (agent *Agent) setupUpdater() {
	_, verr := release.ParseVersion(agent.version)
	underLauncher := agent.health != nil || os.Getenv(launcher.HealthFDEnv) != ""

	if agent.health == nil {
		health, err := launcher.OpenHealth()
		if err != nil {
			agent.log.Error("Open health pipe", slog.Any("err", err))

			health = &launcher.Health{}
		}

		agent.health = health
	}

	switch {
	case verr != nil:
		agent.log.Info(
			"Self-update disabled",
			slog.String("reason", "not a release version"),
			slog.String("version", agent.version),
		)

		return
	case !underLauncher:
		agent.log.Info(
			"Self-update disabled",
			slog.String("reason", "not running under the launcher"),
		)

		return
	}

	exe, err := os.Executable()
	if err != nil {
		agent.log.Warn("Executable path unknown", slog.Any("err", err))
	}

	targets := make([]string, 0, len(agent.cfg.Serve))
	for _, t := range agent.cfg.Serve {
		targets = append(targets, t)
	}

	slices.Sort(targets)

	upd, err := updater.New(updater.Options{
		Version:  agent.version,
		Platform: runtime.GOOS + "-" + runtime.GOARCH,
		StateDir: agent.cfg.StateDir,
		Layout:   launcher.Layout{Dir: agent.cfg.InstallDir},
		Health:   agent.health,
		Binary:   exe,
		Hooks: updater.Hooks{
			LastHelloAck:   agent.lastHelloAckTime,
			HubHandshakeOK: agent.hubHandshakeOK,
			NetworkUp:      agent.networkUp,
			ServeTargets:   targets,
		},
		Log: agent.baseLog, // the updater adds its own component
		Now: agent.now,
	})
	if err != nil {
		agent.log.Error("Self-update disabled", slog.String("reason", "updater setup failed"),
			slog.Any("err", err),
		)

		return
	}

	agent.upd = upd
}

// startupOK reports the local startup check. It runs after the link ports are
// bound and the direct listener is reconciled, and never waits for the hub.
func (agent *Agent) startupOK() {
	if agent.upd != nil {
		agent.upd.StartupOK()

		return
	}

	if agent.health == nil {
		return
	}

	err := agent.health.Ready()
	if err != nil {
		agent.log.Error("Send ready", slog.Any("err", err))
	}

	agent.wg.Go(func() {
		ticker := time.NewTicker(healthAliveInterval)
		defer ticker.Stop()

		for {
			select {
			case <-agent.ctx.Done():
				return
			case <-ticker.C:
				err := agent.health.Alive()
				if err != nil {
					agent.log.Warn("Send alive", slog.Any("err", err))
				}
			}
		}
	})
}

// lastHelloAckTime is the updater's "hub is healthy" signal: the later of the
// last HelloAck and the last ping reply on the current session. A HelloAck
// alone arrives only when a session starts, so a long-lived healthy session
// would otherwise look stale and defer every update.
func (agent *Agent) lastHelloAckTime() time.Time {
	agent.mu.Lock()
	last, cur := agent.lastHelloAck, agent.cur
	agent.mu.Unlock()

	if cur != nil && !last.IsZero() {
		if pong := cur.ctrl.LastPong(); pong.After(last) {
			last = pong
		}
	}

	return last
}

func (agent *Agent) networkUp() bool {
	addrs, err := agent.localAddrs()

	return err == nil && len(addrs) > 0
}

func (agent *Agent) hubHandshakeOK(ctx context.Context) bool {
	ctx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	defer cancel()

	d := net.Dialer{}

	raw, err := d.DialContext(ctx, "tcp", agent.cfg.HubAddr())
	if err != nil {
		return false
	}

	defer func() { _ = raw.Close() }()

	ident := agent.identity()
	tc := tls.Client(raw, agent.tunnelTLS(&ident))

	return tc.HandshakeContext(ctx) == nil
}
