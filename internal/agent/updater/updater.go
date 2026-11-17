// Package updater orchestrates the agent's self-update: probation of a freshly
// installed binary and the periodic check that installs the hub's advertised
// release.
package updater

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zekihan/t3-mesh/internal/launcher"
	"github.com/zekihan/t3-mesh/internal/proto"
	"github.com/zekihan/t3-mesh/internal/release"
)

// Timing defaults.
const (
	DefaultCheckInterval    = 10 * time.Minute
	DefaultProbationTimeout = 2 * time.Minute
	aliveInterval           = 10 * time.Second
	probationTick           = time.Second
	maxTickGap              = 5 * time.Second
	probeInterval           = 5 * time.Second
	probeTimeout            = 3 * time.Second
	keepVersions            = 1
)

// HealthSink is the part of *launcher.Health the updater uses.
type HealthSink interface {
	Ready() error
	Alive() error
	Promote() error
	Fail(reason, kind string) error
	Restart() error
}

// Hooks are supplied by the agent core.
type Hooks struct {
	// LastHelloAck is when the running binary last received a HelloAck.
	LastHelloAck func() time.Time
	// HubHandshakeOK reports whether a TLS handshake to the hub succeeds now.
	HubHandshakeOK func(ctx context.Context) bool
	// NetworkUp reports whether the machine has a network.
	NetworkUp func() bool
	// ServeTargets are the local serve addresses.
	ServeTargets []string
}

// Options configure an Updater.
type Options struct {
	Version    string
	Platform   string
	StateDir   string
	Layout     launcher.Layout
	Health     HealthSink
	Downloader *release.Downloader
	Binary     string
	Hooks      Hooks
	Log        *slog.Logger
	Now        func() time.Time

	// Optional overrides, mainly for tests.
	SelfTest         func(ctx context.Context, binary string) error
	CheckInterval    time.Duration
	ProbationTimeout time.Duration
}

// Updater drives probation and update checks.
type Updater struct {
	o       Options
	running release.Version
	log     *slog.Logger

	onProbation atomic.Bool
	nudge       chan struct{}
	installMu   sync.Mutex
	stopOnce    sync.Once
	stop        chan struct{}
	aliveOnce   sync.Once

	mu          sync.Mutex
	rel         *proto.Release
	applied     string
	helloAck    bool
	rejected    string
	outcomeSent bool
	restarting  bool
}

// New ingests the launcher outcome file and determines whether this process is
// on probation.
func New(opts Options) (*Updater, error) {
	running, err := release.ParseVersion(opts.Version)
	if err != nil {
		return nil, fmt.Errorf("updater: running version: %w", err)
	}
	if opts.Log == nil {
		opts.Log = slog.Default()
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Health == nil {
		opts.Health = &launcher.Health{}
	}
	if opts.SelfTest == nil {
		opts.SelfTest = launcher.SelfTest
	}
	if opts.CheckInterval <= 0 {
		opts.CheckInterval = DefaultCheckInterval
	}
	if opts.ProbationTimeout <= 0 {
		opts.ProbationTimeout = DefaultProbationTimeout
	}
	if opts.Downloader == nil {
		opts.Downloader = &release.Downloader{}
	}
	u := &Updater{
		o:       opts,
		running: running,
		log:     opts.Log.With("component", "updater"),
		nudge:   make(chan struct{}, 1),
		stop:    make(chan struct{}),
	}
	if ierr := release.IngestLauncherOutcome(opts.StateDir); ierr != nil {
		u.log.Error("ingest launcher outcome", "err", ierr)
	}
	cur, err := opts.Layout.Current()
	if err == nil {
		kg, kerr := opts.Layout.KnownGood()
		if kerr != nil || kg != cur {
			u.onProbation.Store(cur == opts.Version)
		}
	}
	if u.onProbation.Load() {
		u.log.Info("running on probation", "version", opts.Version)
	}
	return u, nil
}

// OnProbation reports whether the running binary is on probation. The agent
// core must not renew certificates or write new state formats while true.
func (u *Updater) OnProbation() bool { return u.onProbation.Load() }

// Close stops the liveness goroutine.
func (u *Updater) Close() { u.stopOnce.Do(func() { close(u.stop) }) }

// StartupOK is called once the local startup check passes. It sends Ready and
// then Alive every 10 seconds.
func (u *Updater) StartupOK() {
	u.aliveOnce.Do(func() {
		if err := u.o.Health.Ready(); err != nil {
			u.log.Error("send ready", "err", err)
		}
		go func() {
			t := time.NewTicker(aliveInterval)
			defer t.Stop()
			for {
				select {
				case <-u.stop:
					return
				case <-t.C:
					if err := u.o.Health.Alive(); err != nil {
						u.log.Warn("send alive", "err", err)
					}
				}
			}
		}()
	})
}

// HelloAckReceived records probation progress.
func (u *Updater) HelloAckReceived() {
	u.mu.Lock()
	u.helloAck = true
	u.mu.Unlock()
}

// OnRelease is called with every Release message.
func (u *Updater) OnRelease(rel proto.Release) {
	u.mu.Lock()
	u.rel = &rel
	if rel.Version == u.o.Version {
		u.applied = rel.Revision
	}
	u.mu.Unlock()
	select {
	case u.nudge <- struct{}{}:
	default:
	}
}

// OnReject handles a hub Reject. One naming the version on probation is a
// release failure.
func (u *Updater) OnReject(r proto.Reject) {
	if r.Version == "" || r.Version != u.o.Version || !u.onProbation.Load() {
		return
	}
	u.mu.Lock()
	u.rejected = fmt.Sprintf("hub rejected version %s: %s", r.Version, r.Reason)
	u.mu.Unlock()
	u.log.Warn("hub rejected the version on probation", "reason", r.Reason, "detail", r.Detail)
	u.failProbation(u.rejected, launcher.KindRelease)
}

// FailedUpdates returns the recorded failures for Status.
func (u *Updater) FailedUpdates() []proto.FailedUpdate {
	st, err := release.LoadState(u.o.StateDir)
	if err != nil {
		u.log.Error("load update state", "err", err)
		return nil
	}
	return st.FailedUpdates()
}

// LastAppliedRelease returns the revision of the last Release naming the
// running version.
func (u *Updater) LastAppliedRelease() string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.applied
}

// Run drives probation (if on probation) and update checks until ctx ends.
func (u *Updater) Run(ctx context.Context) error {
	defer u.Close()
	if u.onProbation.Load() {
		if err := u.runProbation(ctx); err != nil {
			return err
		}
	}
	if !u.onProbation.Load() {
		return u.runChecks(ctx)
	}
	<-ctx.Done()
	return ctx.Err()
}

func (u *Updater) failProbation(reason, kind string) {
	u.mu.Lock()
	if u.outcomeSent {
		u.mu.Unlock()
		return
	}
	u.outcomeSent = true
	u.mu.Unlock()
	u.log.Error("probation failed", "kind", kind, "reason", reason)
	if err := u.o.Health.Fail(reason, kind); err != nil {
		u.log.Error("send fail", "err", err)
	}
}

func (u *Updater) promote() {
	u.mu.Lock()
	if u.outcomeSent {
		u.mu.Unlock()
		return
	}
	u.outcomeSent = true
	u.mu.Unlock()
	if err := u.o.Health.Promote(); err != nil {
		u.log.Error("send promote", "err", err)
		return
	}
	u.onProbation.Store(false)
	u.log.Info("probation passed, promoted", "version", u.o.Version)
	if err := u.o.Layout.Prune(keepVersions); err != nil {
		u.log.Warn("prune old versions", "err", err)
	}
}

// probation tracks the eligible-time budget and the completion checklist.
type probation struct {
	u        *Updater
	last     time.Time
	eligible time.Duration

	lastProbe  time.Time
	handshake  bool
	haveProbe  bool
	serveDone  bool
	serveErr   error
	manifestOK bool
	manifestEr error
	selfTestOK bool
	selfTestEr error
}

func (u *Updater) runProbation(ctx context.Context) error {
	p := &probation{u: u, last: u.o.Now().Round(0)}
	t := time.NewTicker(probationTick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
		}
		if p.step(ctx, u.o.Now()) {
			return nil
		}
	}
}

func (u *Updater) helloDone() bool {
	u.mu.Lock()
	ok := u.helloAck
	u.mu.Unlock()
	if ok {
		return true
	}
	if f := u.o.Hooks.LastHelloAck; f != nil && !f().IsZero() {
		return true
	}
	return false
}

// step advances probation to now and reports whether it concluded.
func (p *probation) step(ctx context.Context, now time.Time) bool {
	u := p.u
	now = now.Round(0) // compare wall clocks so that suspended time shows up as a gap
	dt := now.Sub(p.last)
	p.last = now
	u.mu.Lock()
	rejected := u.rejected
	done := u.outcomeSent
	u.mu.Unlock()
	if done || rejected != "" {
		return true
	}
	if dt <= 0 || dt > maxTickGap {
		if dt > maxTickGap {
			u.log.Info("ignoring probation clock gap (sleep?)", "gap", dt)
		}
		return false
	}
	if !p.haveProbe || now.Sub(p.lastProbe) >= probeInterval {
		p.haveProbe, p.lastProbe = true, now
		p.handshake = false
		if h := u.o.Hooks.HubHandshakeOK; h != nil {
			pctx, cancel := context.WithTimeout(ctx, probeTimeout)
			p.handshake = h(pctx)
			cancel()
		}
	}
	netUp := u.o.Hooks.NetworkUp != nil && u.o.Hooks.NetworkUp()
	if netUp && p.handshake {
		p.eligible += dt
		p.work(ctx)
		if p.complete() {
			u.promote()
			return true
		}
	}
	if p.eligible >= u.o.ProbationTimeout {
		kind, reason := p.classify()
		u.failProbation(reason, kind)
		return true
	}
	return false
}

func (p *probation) complete() bool {
	return p.u.helloDone() && p.serveDone && p.manifestOK && p.selfTestOK
}

// work runs the undone checklist items; failures are retried on later steps.
func (p *probation) work(ctx context.Context) {
	u := p.u
	if !p.serveDone {
		p.serveErr = dialAll(ctx, u.o.Hooks.ServeTargets)
		p.serveDone = p.serveErr == nil
	}
	if !p.manifestOK {
		_, err := u.o.Downloader.Fetch(ctx, u.o.Version)
		p.manifestEr, p.manifestOK = err, err == nil
	}
	if !p.selfTestOK && p.manifestOK && p.serveDone && u.helloDone() {
		err := u.o.SelfTest(ctx, u.o.Binary)
		p.selfTestEr, p.selfTestOK = err, err == nil
	}
}

func (p *probation) classify() (kind, reason string) {
	switch {
	case p.manifestEr != nil && !p.manifestOK:
		return launcher.KindRelease, fmt.Sprintf("manifest re-fetch failed: %v", p.manifestEr)
	case p.selfTestEr != nil && !p.selfTestOK:
		return launcher.KindRelease, fmt.Sprintf("launcher self-test failed: %v", p.selfTestEr)
	case !p.u.helloDone():
		return launcher.KindDependency, "no HelloAck within probation time"
	case !p.serveDone:
		return launcher.KindDependency, fmt.Sprintf("serve target check failed: %v", p.serveErr)
	}
	return launcher.KindRelease, "probation timed out"
}

func dialAll(ctx context.Context, targets []string) error {
	d := net.Dialer{Timeout: release.DialTimeout}
	for _, t := range targets {
		c, err := d.DialContext(ctx, "tcp", t)
		if err != nil {
			return fmt.Errorf("serve target %s: %w", t, err)
		}
		_ = c.Close()
	}
	return nil
}

func (u *Updater) runChecks(ctx context.Context) error {
	t := time.NewTicker(u.o.CheckInterval)
	defer t.Stop()
	u.check(ctx)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-u.nudge:
		case <-t.C:
		}
		u.check(ctx)
	}
}

// check evaluates the latest Release once. It never installs concurrently.
func (u *Updater) check(ctx context.Context) {
	if !u.installMu.TryLock() {
		return
	}
	defer u.installMu.Unlock()
	u.mu.Lock()
	rel, restarting := u.rel, u.restarting
	u.mu.Unlock()
	if rel == nil || restarting || u.onProbation.Load() {
		return
	}
	st, err := release.LoadState(u.o.StateDir)
	if err != nil {
		u.log.Error("load update state", "err", err)
		return
	}
	now := u.o.Now()
	dec, why := release.Decide(u.running, *rel, st, now)
	if dec != release.Install {
		u.log.Debug("no update", "reason", why)
		return
	}
	u.log.Info("update available", "version", rel.Version, "reason", why)
	var last time.Time
	if f := u.o.Hooks.LastHelloAck; f != nil {
		last = f()
	}
	if err := release.Preconditions(ctx, u.o.Hooks.ServeTargets, last, now); err != nil {
		u.log.Info("update deferred", "version", rel.Version, "err", err)
		return
	}
	if err := u.install(ctx, rel.Version); err != nil {
		u.log.Warn("update failed, will retry at next check", "version", rel.Version, "err", err)
	}
}

func (u *Updater) install(ctx context.Context, version string) error {
	u.log.Info("fetching manifest", "version", version)
	m, err := u.o.Downloader.Fetch(ctx, version)
	if err != nil {
		return fmt.Errorf("fetch manifest: %w", err)
	}
	if err := os.MkdirAll(u.o.Layout.Dir, 0o755); err != nil {
		return fmt.Errorf("create install dir: %w", err)
	}
	tmp := filepath.Join(u.o.Layout.Dir, ".staging-"+version)
	u.log.Info("downloading binary", "version", version, "platform", u.o.Platform)
	if err := u.o.Downloader.Download(ctx, m, u.o.Platform, tmp); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("download: %w", err)
	}
	u.log.Info("staging", "version", version)
	if err := u.o.Layout.Stage(version, tmp); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("stage: %w", err)
	}
	u.log.Info("switching current", "version", version)
	if err := u.o.Layout.SetCurrent(version); err != nil {
		return fmt.Errorf("set current: %w", err)
	}
	u.log.Info("requesting restart", "version", version)
	if err := u.o.Health.Restart(); err != nil {
		if rerr := u.o.Layout.Rollback(); rerr != nil {
			err = errors.Join(err, fmt.Errorf("rollback current: %w", rerr))
		}
		return fmt.Errorf("request restart: %w", err)
	}
	u.mu.Lock()
	u.restarting = true
	u.mu.Unlock()
	return nil
}
