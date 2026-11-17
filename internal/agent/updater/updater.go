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
	installDirMode          = 0o755
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
	// LastHelloAck is when the running binary last heard from the hub: a HelloAck
	// or a ping reply on its current session.
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
	Health           HealthSink
	Downloader       *release.Downloader
	SelfTest         func(ctx context.Context, binary string) error
	Now              func() time.Time
	Log              *slog.Logger
	Layout           launcher.Layout
	Binary           string
	Version          string
	StateDir         string
	Platform         string
	Hooks            Hooks
	CheckInterval    time.Duration
	ProbationTimeout time.Duration
}

// Updater drives probation and update checks.
type Updater struct {
	log         *slog.Logger
	nudge       chan struct{}
	rel         *proto.Release
	stop        chan struct{}
	running     release.Version
	rejected    string
	applied     string
	o           Options
	aliveOnce   sync.Once
	stopOnce    sync.Once
	mu          sync.Mutex
	installMu   sync.Mutex
	onProbation atomic.Bool
	helloAck    bool
	outcomeSent bool
	restarting  bool
}

// New ingests the launcher outcome file and determines whether this process is
// on probation.
func New(
	opts Options, //nolint:gocritic // Options is passed by value in the public API
) (*Updater, error) {
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

	updater := &Updater{
		o:       opts,
		running: running,
		log:     opts.Log.With(slog.String("component", "updater")),
		nudge:   make(chan struct{}, 1),
		stop:    make(chan struct{}),
	}

	ierr := release.IngestLauncherOutcome(opts.StateDir)
	if ierr != nil {
		updater.log.Error("Ingest launcher outcome", slog.Any("err", ierr))
	}

	cur, err := opts.Layout.Current()
	if err == nil {
		kg, kerr := opts.Layout.KnownGood()
		if kerr != nil || kg != cur {
			updater.onProbation.Store(cur == opts.Version)
		}
	}

	if updater.onProbation.Load() {
		updater.log.Info("Running on probation", slog.String("version", opts.Version))
	}

	return updater, nil
}

// OnProbation reports whether the running binary is on probation. The agent
// core must not renew certificates or write new state formats while true.
func (updater *Updater) OnProbation() bool { return updater.onProbation.Load() }

// Close stops the liveness goroutine.
func (updater *Updater) Close() { updater.stopOnce.Do(func() { close(updater.stop) }) }

// StartupOK is called once the local startup check passes. It sends Ready and
// then Alive every 10 seconds.
func (updater *Updater) StartupOK() {
	updater.aliveOnce.Do(func() {
		err := updater.o.Health.Ready()
		if err != nil {
			updater.log.Error("Send ready", slog.Any("err", err))
		}

		go func() {
			ticker := time.NewTicker(aliveInterval)
			defer ticker.Stop()

			for {
				select {
				case <-updater.stop:
					return
				case <-ticker.C:
					err := updater.o.Health.Alive()
					if err != nil {
						updater.log.Warn("Send alive", slog.Any("err", err))
					}
				}
			}
		}()
	})
}

// HelloAckReceived records probation progress.
func (updater *Updater) HelloAckReceived() {
	updater.mu.Lock()
	updater.helloAck = true
	updater.mu.Unlock()
}

// OnRelease is called with every Release message.
func (updater *Updater) OnRelease(rel proto.Release) {
	updater.mu.Lock()

	updater.rel = &rel
	if rel.Version == updater.o.Version {
		updater.applied = rel.Revision
	}
	updater.mu.Unlock()

	select {
	case updater.nudge <- struct{}{}:
	default:
	}
}

// OnReject handles a hub Reject. One naming the version on probation is a
// release failure.
func (updater *Updater) OnReject(reject proto.Reject) {
	if reject.Version == "" || reject.Version != updater.o.Version || !updater.onProbation.Load() {
		return
	}

	updater.mu.Lock()
	updater.rejected = fmt.Sprintf("hub rejected version %s: %s", reject.Version, reject.Reason)
	updater.mu.Unlock()
	updater.log.Warn(
		"Hub rejected the version on probation",
		slog.String("reason", reject.Reason),
		slog.String("detail", reject.Detail),
	)
	updater.failProbation(updater.rejected, launcher.KindRelease)
}

// FailedUpdates returns the recorded failures for Status.
func (updater *Updater) FailedUpdates() []proto.FailedUpdate {
	st, err := release.LoadState(updater.o.StateDir)
	if err != nil {
		updater.log.Error("Load update state", slog.Any("err", err))

		return nil
	}

	return st.FailedUpdates()
}

// LastAppliedRelease returns the revision of the last Release naming the
// running version.
func (updater *Updater) LastAppliedRelease() string {
	updater.mu.Lock()
	defer updater.mu.Unlock()

	return updater.applied
}

// Run drives probation (if on probation) and update checks until ctx ends.
func (updater *Updater) Run(ctx context.Context) error {
	defer updater.Close()

	if updater.onProbation.Load() {
		err := updater.runProbation(ctx)
		if err != nil {
			return err
		}
	}

	if !updater.onProbation.Load() {
		return updater.runChecks(ctx)
	}

	<-ctx.Done()

	return fmt.Errorf("updater: %w", ctx.Err())
}

func (updater *Updater) failProbation(reason, kind string) {
	updater.mu.Lock()
	if updater.outcomeSent {
		updater.mu.Unlock()

		return
	}

	updater.outcomeSent = true
	updater.mu.Unlock()
	updater.log.Error("Probation failed", slog.String("kind", kind),
		slog.String("reason", reason),
	)

	err := updater.o.Health.Fail(reason, kind)
	if err != nil {
		updater.log.Error("Send fail", slog.Any("err", err))
	}
}

func (updater *Updater) promote() {
	updater.mu.Lock()
	if updater.outcomeSent {
		updater.mu.Unlock()

		return
	}

	updater.outcomeSent = true
	updater.mu.Unlock()

	err := updater.o.Health.Promote()
	if err != nil {
		updater.log.Error("Send promote", slog.Any("err", err))

		return
	}

	updater.onProbation.Store(false)
	updater.log.Info("Probation passed, promoted", slog.String("version", updater.o.Version))

	err = updater.o.Layout.Prune(keepVersions)
	if err != nil {
		updater.log.Warn("Prune old versions", slog.Any("err", err))
	}
}

// probation tracks the eligible-time budget and the completion checklist.
type probation struct {
	last       time.Time
	lastProbe  time.Time
	serveErr   error
	manifestEr error
	selfTestEr error
	u          *Updater
	eligible   time.Duration
	handshake  bool
	haveProbe  bool
	serveDone  bool
	manifestOK bool
	selfTestOK bool
}

func (updater *Updater) runProbation(ctx context.Context) error {
	prob := &probation{u: updater, last: updater.o.Now().Round(0)}

	ticker := time.NewTicker(probationTick)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("updater: %w", ctx.Err())
		case <-ticker.C:
		}

		if prob.step(ctx, updater.o.Now()) {
			return nil
		}
	}
}

func (updater *Updater) helloDone() bool {
	updater.mu.Lock()
	ok := updater.helloAck
	updater.mu.Unlock()

	if ok {
		return true
	}

	if f := updater.o.Hooks.LastHelloAck; f != nil && !f().IsZero() {
		return true
	}

	return false
}

// step advances probation to now and reports whether it concluded.
func (prob *probation) step(ctx context.Context, now time.Time) bool {
	updater := prob.u
	now = now.Round(0) // compare wall clocks so that suspended time shows up as a gap
	dt := now.Sub(prob.last)
	prob.last = now

	updater.mu.Lock()
	rejected := updater.rejected
	done := updater.outcomeSent
	updater.mu.Unlock()

	if done || rejected != "" {
		return true
	}

	if dt <= 0 || dt > maxTickGap {
		if dt > maxTickGap {
			updater.log.InfoContext(
				ctx,
				"Ignoring probation clock gap (sleep?)",
				slog.Duration("gap", dt),
			)
		}

		return false
	}

	if !prob.haveProbe || now.Sub(prob.lastProbe) >= probeInterval {
		prob.haveProbe, prob.lastProbe = true, now
		prob.handshake = false

		if h := updater.o.Hooks.HubHandshakeOK; h != nil {
			pctx, cancel := context.WithTimeout(ctx, probeTimeout)
			prob.handshake = h(pctx)

			cancel()
		}
	}

	netUp := updater.o.Hooks.NetworkUp != nil && updater.o.Hooks.NetworkUp()
	if netUp && prob.handshake {
		prob.eligible += dt
		prob.work(ctx)

		if prob.complete() {
			updater.promote()

			return true
		}
	}

	if prob.eligible >= updater.o.ProbationTimeout {
		kind, reason := prob.classify()
		updater.failProbation(reason, kind)

		return true
	}

	return false
}

func (prob *probation) complete() bool {
	return prob.u.helloDone() && prob.serveDone && prob.manifestOK && prob.selfTestOK
}

// work runs the undone checklist items; failures are retried on later steps.
func (prob *probation) work(ctx context.Context) {
	updater := prob.u
	if !prob.serveDone {
		prob.serveErr = dialAll(ctx, updater.o.Hooks.ServeTargets)
		prob.serveDone = prob.serveErr == nil
	}

	if !prob.manifestOK {
		_, err := updater.o.Downloader.Fetch(ctx, updater.o.Version)
		prob.manifestEr, prob.manifestOK = err, err == nil
	}

	if !prob.selfTestOK && prob.manifestOK && prob.serveDone && updater.helloDone() {
		err := updater.o.SelfTest(ctx, updater.o.Binary)
		prob.selfTestEr, prob.selfTestOK = err, err == nil
	}
}

func (prob *probation) classify() (string, string) {
	switch {
	case prob.manifestEr != nil && !prob.manifestOK:
		return launcher.KindRelease, fmt.Sprintf("manifest re-fetch failed: %v", prob.manifestEr)
	case prob.selfTestEr != nil && !prob.selfTestOK:
		return launcher.KindRelease, fmt.Sprintf("launcher self-test failed: %v", prob.selfTestEr)
	case !prob.u.helloDone():
		return launcher.KindDependency, "no HelloAck within probation time"
	case !prob.serveDone:
		return launcher.KindDependency, fmt.Sprintf("serve target check failed: %v", prob.serveErr)
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

func (updater *Updater) runChecks(ctx context.Context) error {
	ticker := time.NewTicker(updater.o.CheckInterval)
	defer ticker.Stop()

	updater.check(ctx)

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("updater: %w", ctx.Err())
		case <-updater.nudge:
		case <-ticker.C:
		}

		updater.check(ctx)
	}
}

// check evaluates the latest Release once. It never installs concurrently.
func (updater *Updater) check(ctx context.Context) {
	if !updater.installMu.TryLock() {
		return
	}
	defer updater.installMu.Unlock()

	updater.mu.Lock()
	rel, restarting := updater.rel, updater.restarting
	updater.mu.Unlock()

	if rel == nil || restarting || updater.onProbation.Load() {
		return
	}

	st, err := release.LoadState(updater.o.StateDir)
	if err != nil {
		updater.log.ErrorContext(ctx, "Load update state", slog.Any("err", err))

		return
	}

	now := updater.o.Now()

	dec, why := release.Decide(updater.running, *rel, st, now)
	if dec != release.Install {
		updater.log.DebugContext(ctx, "No update", slog.Any("reason", why))

		return
	}

	updater.log.InfoContext(ctx, "Update available", slog.String("version", rel.Version),
		slog.Any("reason", why),
	)

	var last time.Time
	if f := updater.o.Hooks.LastHelloAck; f != nil {
		last = f()
	}

	err = release.Preconditions(ctx, updater.o.Hooks.ServeTargets, last, now)
	if err != nil {
		updater.log.InfoContext(ctx, "Update deferred", slog.String("version", rel.Version),
			slog.Any("err", err),
		)

		return
	}

	err = updater.install(ctx, rel.Version)
	if err != nil {
		updater.log.WarnContext(
			ctx,
			"Update failed, will retry at next check",
			slog.String("version", rel.Version),
			slog.Any("err", err),
		)
	}
}

func (updater *Updater) install(ctx context.Context, version string) error {
	updater.log.InfoContext(ctx, "Fetching manifest", slog.String("version", version))

	manifest, err := updater.o.Downloader.Fetch(ctx, version)
	if err != nil {
		return fmt.Errorf("fetch manifest: %w", err)
	}

	err = os.MkdirAll(updater.o.Layout.Dir, installDirMode)
	if err != nil {
		return fmt.Errorf("create install dir: %w", err)
	}

	tmp := filepath.Join(updater.o.Layout.Dir, ".staging-"+version)
	updater.log.InfoContext(
		ctx,
		"Downloading binary",
		slog.String("version", version),
		slog.String("platform", updater.o.Platform),
	)

	err = updater.o.Downloader.Download(ctx, manifest, updater.o.Platform, tmp)
	if err != nil {
		_ = os.Remove(tmp)

		return fmt.Errorf("download: %w", err)
	}

	updater.log.InfoContext(ctx, "Staging", slog.String("version", version))

	err = updater.o.Layout.Stage(version, tmp)
	if err != nil {
		_ = os.Remove(tmp)

		return fmt.Errorf("stage: %w", err)
	}

	updater.log.InfoContext(ctx, "Switching current", slog.String("version", version))

	err = updater.o.Layout.SetCurrent(version)
	if err != nil {
		return fmt.Errorf("set current: %w", err)
	}

	updater.log.InfoContext(ctx, "Requesting restart", slog.String("version", version))

	err = updater.o.Health.Restart()
	if err != nil {
		rerr := updater.o.Layout.Rollback()
		if rerr != nil {
			err = errors.Join(err, fmt.Errorf("rollback current: %w", rerr))
		}

		return fmt.Errorf("request restart: %w", err)
	}

	updater.mu.Lock()
	updater.restarting = true
	updater.mu.Unlock()

	return nil
}
