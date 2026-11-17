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
)

// Options configures an Agent.
type Options struct {
	Config *agentconfig.Config
	// Version is the build version, "dev" for non-release builds.
	Version string
	Log     *slog.Logger
	Now     func() time.Time
	// HubTLS overrides trust for the hub in tests: RootCAs and ServerName.
	// Production leaves it nil and uses system roots and the exact hub host.
	HubTLS *tls.Config
	// Health is the launcher health pipe; nil opens it from the environment.
	Health updater.HealthSink
	// LocalAddrs and GatewayMAC override host network lookups in tests, which
	// need loopback addresses that the real lookup excludes.
	LocalAddrs func() ([]netip.Addr, error)
	GatewayMAC func() (string, error)
}

// Agent is the running agent.
type Agent struct {
	cfg     *agentconfig.Config
	log     *slog.Logger
	now     func() time.Time
	version string
	store   pki.Store
	hubTLS  *tls.Config
	health  updater.HealthSink

	// Seams for tests and tuning.
	lookupHost  func(ctx context.Context, host string) ([]netip.Addr, error)
	addrPresent func(netip.Addr) bool
	gatewayMAC  func() (string, error)
	localAddrs  func() ([]netip.Addr, error)
	backoffBase time.Duration
	backoffMax  time.Duration
	statusEvery time.Duration
	renewEvery  time.Duration
	renewWindow time.Duration
	renewRetry  time.Duration

	ctx context.Context //nolint:containedctx // run context shared by session goroutines
	wg  sync.WaitGroup

	direct *direct.Manager
	upd    *updater.Updater

	mu           sync.Mutex
	ident        tls.Certificate
	cache        *state.Cache
	roots        *x509.CertPool
	rootsPEM     string
	prefixes     []netip.Prefix
	cur          *session
	live         map[*session]struct{}
	warnings     []string
	lastSave     time.Time
	lastHelloAck time.Time
	renewAfter   time.Time

	saveMu sync.Mutex
	dialMu sync.Mutex

	kick        chan struct{}
	curChanged  chan struct{}
	statusNudge chan struct{}
	renewKick   chan struct{}

	renewing atomic.Bool
}

// New validates opts and returns an Agent. Identity and state are loaded by Run.
func New(opts Options) (*Agent, error) {
	if opts.Config == nil {
		return nil, errors.New("agent: config is required")
	}

	if opts.Log == nil {
		opts.Log = slog.Default()
	}

	if opts.Now == nil {
		opts.Now = time.Now
	}

	a := &Agent{
		cfg:         opts.Config,
		log:         opts.Log.With("component", "agent"),
		now:         opts.Now,
		version:     opts.Version,
		store:       pki.Store{Dir: opts.Config.Identity.Dir},
		hubTLS:      opts.HubTLS,
		health:      opts.Health,
		gatewayMAC:  defaultGatewayMAC,
		localAddrs:  netwatch.LocalAddrs,
		addrPresent: defaultAddrPresent,
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
	a.lookupHost = a.defaultLookup

	if opts.LocalAddrs != nil {
		a.localAddrs = opts.LocalAddrs
	}

	if opts.GatewayMAC != nil {
		a.gatewayMAC = opts.GatewayMAC
	}

	return a, nil
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

func (a *Agent) defaultLookup(ctx context.Context, host string) ([]netip.Addr, error) {
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("lookup %s: %w", host, err)
	}

	return addrs, nil
}

// Run starts the agent and blocks until ctx ends or startup fails. Startup
// loads the identity and cached state, binds every link port and reconciles the
// direct listener from cached state; only then does it report the local
// startup check to the launcher, so a hub outage never fails it.
func (a *Agent) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	a.ctx = ctx

	if err := a.loadLocal(); err != nil {
		return err
	}

	if a.cfg.Direct.Enabled {
		a.direct = direct.New(direct.Options{
			Port:       a.cfg.Direct.Port,
			CacheTTL:   a.cfg.Direct.CacheTTL,
			Serve:      a.cfg.Serve,
			View:       a.view,
			Log:        a.log,
			Now:        a.now,
			GatewayMAC: a.gatewayMAC,
			LocalAddrs: a.localAddrs,
		})

		defer func() { _ = a.direct.Close() }()
	}

	links, err := a.bindLinks()
	if err != nil {
		return err
	}

	defer func() {
		for _, l := range links {
			l.close()
		}
	}()

	if a.direct != nil {
		a.direct.Reconcile(ctx)
	}

	a.setupUpdater()
	a.startupOK()

	for _, l := range links {
		a.wg.Go(l.serve)
	}

	a.wg.Go(func() { a.tunnelLoop(ctx) })
	a.wg.Go(func() { a.netLoop(ctx) })
	a.wg.Go(func() { a.statusLoop(ctx) })
	a.wg.Go(func() { a.renewLoop(ctx) })

	if a.upd != nil {
		a.wg.Go(func() {
			if uerr := a.upd.Run(ctx); uerr != nil && !errors.Is(uerr, context.Canceled) {
				a.log.Error("updater stopped", "err", uerr)
			}
		})
	}

	<-ctx.Done()
	a.closeLinks(links)
	a.shutdown()

	return nil
}

func (a *Agent) shutdown() {
	a.mu.Lock()
	sessions := make([]*session, 0, len(a.live))
	for s := range a.live {
		sessions = append(sessions, s)
	}
	a.mu.Unlock()

	for _, s := range sessions {
		s.close()
	}

	done := make(chan struct{})

	go func() {
		a.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(shutdownWait):
		a.log.Warn("shutdown timed out waiting for goroutines")
	}

	a.saveCache()
}

func (a *Agent) loadLocal() error {
	tc, _, err := a.store.Load()
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("agent: no identity in %s, run `t3-mesh-agent enroll --token <token>` first: %w",
				a.cfg.Identity.Dir, err)
		}

		return fmt.Errorf("agent: load identity: %w", err)
	}

	cache, err := state.Load(a.cfg.StateDir)
	if err != nil {
		return fmt.Errorf("agent: load state: %w", err)
	}

	a.mu.Lock()
	a.ident = tc
	a.cache = cache
	a.deriveLocked()
	a.mu.Unlock()

	if tc.Leaf != nil && !a.now().Before(tc.Leaf.NotAfter) {
		a.log.Warn("identity certificate expired, re-enroll", "not_after", tc.Leaf.NotAfter.Format(time.RFC3339))
	}

	return nil
}

// deriveLocked rebuilds the trust pool and home prefixes from the cache. Direct
// stays inactive until a trust bundle is cached: without roots there are no
// prefixes, so no listener binds, and dials fail fast in the direct package.
func (a *Agent) deriveLocked() {
	if pem := a.cache.TrustBundle.PEM; pem != a.rootsPEM {
		a.rootsPEM = pem
		a.roots = nil

		if pem != "" {
			pool, err := pki.PoolFromPEM([]byte(pem))
			if err != nil {
				a.log.Warn("trust bundle unusable", "err", err)
			} else {
				a.roots = pool
			}
		}
	}

	a.prefixes = a.prefixes[:0:0]

	for _, c := range a.cache.HomeCIDRs {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			a.log.Warn("bad home cidr", "cidr", c, "err", err)

			continue
		}

		a.prefixes = append(a.prefixes, p.Masked())
	}
}

func (a *Agent) view() direct.View {
	a.mu.Lock()
	defer a.mu.Unlock()

	self := a.cache.Machine
	if self == "" {
		self = strings.TrimPrefix(a.cfg.Identity.Name, "agent-")
	}

	var prefixes []netip.Prefix
	if a.roots != nil {
		prefixes = a.prefixes
	}

	return direct.View{
		Self:           self,
		Identity:       a.ident,
		Roots:          a.roots,
		Rules:          a.cache.Rules,
		Revocations:    a.cache.Revocations,
		Peers:          a.cache.Peers.Peers,
		SelfHome:       a.cache.Home,
		HubConnected:   a.cur != nil,
		LastHubContact: a.cache.LastHubContact,
		HomeGatewayMAC: a.cache.HomeGatewayMAC,
		HomePrefixes:   prefixes,
	}
}

func (a *Agent) identity() tls.Certificate {
	a.mu.Lock()
	defer a.mu.Unlock()

	return a.ident
}

func (a *Agent) current() *session {
	a.mu.Lock()
	defer a.mu.Unlock()

	return a.cur
}

func (a *Agent) warn(msg string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if len(a.warnings) > 0 && a.warnings[len(a.warnings)-1] == msg {
		return
	}

	a.warnings = append(a.warnings, msg)
	if len(a.warnings) > maxWarnings {
		a.warnings = slices.Clone(a.warnings[len(a.warnings)-maxWarnings:])
	}
}

func (a *Agent) saveCache() {
	a.mu.Lock()
	if a.cache == nil {
		a.mu.Unlock()

		return
	}

	c := *a.cache
	a.lastSave = a.now()
	a.mu.Unlock()

	a.saveMu.Lock()
	defer a.saveMu.Unlock()

	if err := state.Save(a.cfg.StateDir, &c); err != nil {
		a.log.Error("state save failed", "err", err)
	}
}

// touchHub records a successful hub contact, saving at most once a minute.
func (a *Agent) touchHub() {
	a.mu.Lock()
	now := a.now()
	a.cache.LastHubContact = now
	save := now.Sub(a.lastSave) >= saveThrottle || a.lastSave.IsZero()
	a.mu.Unlock()

	if save {
		a.saveCache()
	}
}

func (a *Agent) reconcileDirect() {
	if a.direct == nil {
		return
	}

	a.direct.Recheck()
	a.direct.Reconcile(a.ctx)
}

func signal(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}

// setupUpdater enables self-update only for release builds running under the
// launcher; otherwise Restart would silently do nothing.
func (a *Agent) setupUpdater() {
	_, verr := release.ParseVersion(a.version)
	underLauncher := a.health != nil || os.Getenv(launcher.HealthFDEnv) != ""

	if a.health == nil {
		h, err := launcher.OpenHealth()
		if err != nil {
			a.log.Error("open health pipe", "err", err)

			h = &launcher.Health{}
		}

		a.health = h
	}

	switch {
	case verr != nil:
		a.log.Info("self-update disabled", "reason", "not a release version", "version", a.version)

		return
	case !underLauncher:
		a.log.Info("self-update disabled", "reason", "not running under the launcher")

		return
	}

	exe, err := os.Executable()
	if err != nil {
		a.log.Warn("executable path unknown", "err", err)
	}

	targets := make([]string, 0, len(a.cfg.Serve))
	for _, t := range a.cfg.Serve {
		targets = append(targets, t)
	}

	slices.Sort(targets)

	upd, err := updater.New(updater.Options{
		Version:  a.version,
		Platform: runtime.GOOS + "-" + runtime.GOARCH,
		StateDir: a.cfg.StateDir,
		Layout:   launcher.Layout{Dir: a.cfg.InstallDir},
		Health:   a.health,
		Binary:   exe,
		Hooks: updater.Hooks{
			LastHelloAck:   a.lastHelloAckTime,
			HubHandshakeOK: a.hubHandshakeOK,
			NetworkUp:      a.networkUp,
			ServeTargets:   targets,
		},
		Log: a.log,
		Now: a.now,
	})
	if err != nil {
		a.log.Error("self-update disabled", "reason", "updater setup failed", "err", err)

		return
	}

	a.upd = upd
}

// startupOK reports the local startup check. It runs after the link ports are
// bound and the direct listener is reconciled, and never waits for the hub.
func (a *Agent) startupOK() {
	if a.upd != nil {
		a.upd.StartupOK()

		return
	}

	if a.health == nil {
		return
	}

	if err := a.health.Ready(); err != nil {
		a.log.Error("send ready", "err", err)
	}

	a.wg.Go(func() {
		t := time.NewTicker(healthAliveInterval)
		defer t.Stop()

		for {
			select {
			case <-a.ctx.Done():
				return
			case <-t.C:
				if err := a.health.Alive(); err != nil {
					a.log.Warn("send alive", "err", err)
				}
			}
		}
	})
}

func (a *Agent) lastHelloAckTime() time.Time {
	a.mu.Lock()
	defer a.mu.Unlock()

	return a.lastHelloAck
}

func (a *Agent) networkUp() bool {
	addrs, err := a.localAddrs()

	return err == nil && len(addrs) > 0
}

func (a *Agent) hubHandshakeOK(ctx context.Context) bool {
	ctx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	defer cancel()

	d := net.Dialer{}

	raw, err := d.DialContext(ctx, "tcp", a.cfg.HubAddr())
	if err != nil {
		return false
	}

	defer func() { _ = raw.Close() }()

	tc := tls.Client(raw, a.tunnelTLS(a.identity()))

	return tc.HandshakeContext(ctx) == nil
}
