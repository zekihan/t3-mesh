package launcher

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const (
	defaultStartupTimeout = 30 * time.Second
	defaultAliveTimeout   = 30 * time.Second
	defaultStopTimeout    = 10 * time.Second
	backoffFactor         = 2
	messageBuffer         = 16
	healthReadTimeout     = 500 * time.Millisecond
	scanInitialBuffer     = 4096
	scanMaxBuffer         = 64 * 1024
)

// File names inside Config.StateDir.
const (
	OutcomeFile   = "launcher-outcome.json"
	HeartbeatFile = "launcher-heartbeat"
)

// Outcome is the content of launcher-outcome.json, written after a rollback.
type Outcome struct {
	Version string `json:"version"`
	Reason  string `json:"reason"`
	Kind    string `json:"kind"`
	At      string `json:"at"`
}

// Config configures Run.
type Config struct {
	Log *slog.Logger
	// ArgsFor, when set, overrides Args per version.
	ArgsFor func(version string) []string
	events  func(ev string)
	// Exec replaces the process image; default syscall.Exec. If it returns,
	// Run returns its error (nil when a test hook returns nil).
	Exec func(path string, argv, env []string) error
	// Command builds the child command; default exec.Command.
	Command  func(binary string, args []string) *exec.Cmd
	StateDir string
	Layout   Layout
	// Args are the arguments passed to the child.
	Args []string
	// ReexecArgs is the launcher's own argument list (without argv[0]) used
	// when re-executing after promotion; default os.Args[1:].
	ReexecArgs []string
	// StopTimeout is the SIGTERM grace before SIGKILL (10 s).
	StopTimeout time.Duration
	// MinBackoff and MaxBackoff bound restarts of the known-good (1 s, 1 min).
	MaxBackoff time.Duration
	MinBackoff time.Duration
	// HeartbeatInterval is how often the heartbeat file is touched (1 min).
	HeartbeatInterval time.Duration
	// AliveTimeout is the longest silence tolerated after ready (30 s).
	AliveTimeout time.Duration
	// StartupTimeout is how long a child on probation has to send ready (30 s).
	StartupTimeout time.Duration
}

func (cfg *Config) defaults() {
	if cfg.StartupTimeout <= 0 {
		cfg.StartupTimeout = defaultStartupTimeout
	}

	if cfg.AliveTimeout <= 0 {
		cfg.AliveTimeout = defaultAliveTimeout
	}

	if cfg.StopTimeout <= 0 {
		cfg.StopTimeout = defaultStopTimeout
	}

	if cfg.HeartbeatInterval <= 0 {
		cfg.HeartbeatInterval = time.Minute
	}

	if cfg.MinBackoff <= 0 {
		cfg.MinBackoff = time.Second
	}

	if cfg.MaxBackoff < cfg.MinBackoff {
		cfg.MaxBackoff = max(time.Minute, cfg.MinBackoff)
	}

	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}

	if cfg.Command == nil {
		cfg.Command = func(binary string, args []string) *exec.Cmd {
			// Not tied to ctx: stop() gives the child a SIGTERM grace before killing it.
			return exec.CommandContext(context.Background(), binary, args...)
		}
	}

	if cfg.Exec == nil {
		cfg.Exec = syscall.Exec
	}

	if cfg.ReexecArgs == nil && len(os.Args) > 1 {
		cfg.ReexecArgs = os.Args[1:]
	}
}

func (cfg *Config) event(ev string) {
	if cfg.events != nil {
		cfg.events(ev)
	}
}

type resultKind int

const (
	resExited resultKind = iota
	resFailed
	resPromoted
	resCtx
	resRestart
)

type result struct {
	reason  string
	failure string
	kind    resultKind
	ran     time.Duration
}

// Run supervises the current binary until ctx is canceled.
//
//nolint:gocritic // exported API takes Config by value
func Run(ctx context.Context, cfg Config) error {
	cfg.defaults()
	backoff := cfg.MinBackoff

	for !canceled(ctx) {
		cur, knownGood, err := resolveVersions(cfg.Layout)
		if err != nil {
			return err
		}

		probation := cur != knownGood
		logStart(ctx, &cfg, cur, knownGood, probation)

		res := superviseOnce(ctx, &cfg, cur, probation)
		// A child exit can race with shutdown. Leave probation for the next start.
		if canceled(ctx) {
			return nil
		}

		switch res.kind {
		case resCtx:
			return nil
		case resRestart:
			cfg.Log.InfoContext(
				ctx,
				"Child requested restart into current",
				slog.String("version", cur),
			)

			backoff = cfg.MinBackoff
		case resPromoted:
			return promoteAndReexec(ctx, &cfg, cur)
		case resFailed, resExited:
			if probation {
				err := rollback(&cfg, cur, res)
				if err != nil {
					return err
				}

				backoff = cfg.MinBackoff

				continue
			}

			cfg.Log.ErrorContext(
				ctx,
				"Known-good version stopped, nothing to roll back to",
				slog.String("version", cur),
				slog.String("reason", res.reason),
				slog.Duration("backoff", backoff),
			)

			if res.ran > cfg.MaxBackoff {
				backoff = cfg.MinBackoff
			}

			if !sleepCtx(ctx, backoff) {
				return nil
			}

			backoff = min(backoff*backoffFactor, cfg.MaxBackoff)
		default:
			// Every result kind is handled above.
		}
	}

	return nil
}

func canceled(ctx context.Context) bool { return ctx.Err() != nil }

// sleepCtx waits for d and reports false when ctx ends first.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()

	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func resolveVersions(l Layout) (string, string, error) {
	cur, err := l.Current()
	if err != nil {
		return "", "", fmt.Errorf("launcher: resolve current: %w", err)
	}

	knownGood, err := l.KnownGood()
	if err != nil {
		return "", "", fmt.Errorf("launcher: resolve known-good: %w", err)
	}

	return cur, knownGood, nil
}

func logStart(ctx context.Context, cfg *Config, cur, knownGood string, probation bool) {
	if probation {
		cfg.Log.InfoContext(
			ctx,
			"Starting version on probation",
			slog.String("version", cur),
			slog.String("knownGood", knownGood),
		)

		return
	}

	cfg.Log.InfoContext(ctx, "Starting known-good version", slog.String("version", cur))
}

// promoteAndReexec repoints known-good at cur and re-executes the launcher.
func promoteAndReexec(ctx context.Context, cfg *Config, cur string) error {
	err := cfg.Layout.Promote()
	if err != nil {
		return fmt.Errorf("launcher: promote %s: %w", cur, err)
	}

	cfg.event("promoted")
	cfg.Log.InfoContext(ctx, "Promoted, re-executing launcher", slog.String("version", cur))

	path := cfg.Layout.Dir + "/" + linkKnownGood + "/" + BinaryName
	argv := append([]string{path}, cfg.ReexecArgs...)

	err = cfg.Exec(path, argv, os.Environ())
	if err != nil {
		return fmt.Errorf("launcher: re-exec %s: %w", path, err)
	}

	return nil
}

func rollback(cfg *Config, failed string, res result) error {
	reason, kind := res.reason, res.failure
	if reason == "" {
		reason = "crash"
	}

	if kind != KindDependency {
		kind = KindRelease
	}

	cfg.Log.Error(
		"Rolling back failed version",
		slog.String("version", failed),
		slog.String("reason", reason),
		slog.String("kind", kind),
	)

	err := cfg.Layout.Rollback()
	if err != nil {
		return fmt.Errorf("launcher: rollback from %s: %w", failed, err)
	}

	cfg.event("rollback")

	if cfg.StateDir != "" {
		out := Outcome{
			Version: failed,
			Reason:  reason,
			Kind:    kind,
			At:      time.Now().UTC().Format(time.RFC3339),
		}

		err := writeJSONAtomic(filepath.Join(cfg.StateDir, OutcomeFile), out)
		if err != nil {
			cfg.Log.Error("Write launcher outcome", slog.Any("err", err))
		}
	}

	return nil
}

func writeJSONAtomic(path string, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("launcher: encode %s: %w", path, err)
	}

	err = os.MkdirAll(filepath.Dir(path), dirMode)
	if err != nil {
		return fmt.Errorf("launcher: create state dir: %w", err)
	}

	tmp := path + ".tmp"

	err = os.WriteFile(tmp, data, fileMode)
	if err != nil {
		return fmt.Errorf("launcher: write %s: %w", tmp, err)
	}

	err = os.Rename(tmp, path)
	if err != nil {
		_ = os.Remove(tmp)

		return fmt.Errorf("launcher: rename %s: %w", tmp, err)
	}

	return nil
}

func touch(path string) error {
	return touchAt(path, time.Now())
}

func touchAt(path string, now time.Time) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, fileMode)
	if err != nil {
		return fmt.Errorf("launcher: touch %s: %w", path, err)
	}

	err = f.Close()
	if err != nil {
		return fmt.Errorf("launcher: touch %s: %w", path, err)
	}

	err = os.Chtimes(path, now, now)
	if err != nil {
		return fmt.Errorf("launcher: touch %s: %w", path, err)
	}

	return nil
}

func envWithHealth() []string {
	var env []string

	for _, e := range os.Environ() {
		if !strings.HasPrefix(e, HealthFDEnv+"=") {
			env = append(env, e)
		}
	}

	return append(env, HealthFDEnv+"=3")
}

// childWatch is the state of one supervised child process.
type childWatch struct {
	cfg       *Config
	cmd       *exec.Cmd
	exitCh    chan error
	msgs      chan Message
	deadline  <-chan time.Time
	timer     *time.Timer
	start     time.Time
	version   string
	probation bool
	ready     bool
	exited    bool
}

func failed(start time.Time, reason string) result {
	return result{kind: resFailed, reason: reason, failure: KindRelease, ran: time.Since(start)}
}

// childCommand builds the child command with the health pipe as fd 3.
func childCommand(cfg *Config, version string, pipe *os.File) *exec.Cmd {
	args := cfg.Args
	if cfg.ArgsFor != nil {
		args = cfg.ArgsFor(version)
	}

	cmd := cfg.Command(cfg.Layout.Binary(version), args)

	cmd.ExtraFiles = []*os.File{pipe}
	if cmd.Env == nil {
		cmd.Env = envWithHealth()
	} else {
		cmd.Env = append(cmd.Env, HealthFDEnv+"=3")
	}

	if cmd.Stdout == nil {
		cmd.Stdout = os.Stdout
	}

	if cmd.Stderr == nil {
		cmd.Stderr = os.Stderr
	}

	return cmd
}

// superviseOnce starts the child and watches it until it ends, fails, is
// promoted or ctx is canceled. The child has stopped when it returns.
func superviseOnce(ctx context.Context, cfg *Config, version string, probation bool) result {
	start := time.Now()

	rd, wr, err := os.Pipe()
	if err != nil {
		cfg.Log.ErrorContext(ctx, "Create health pipe", slog.Any("err", err))

		return failed(start, "crash")
	}
	defer rd.Close()

	cmd := childCommand(cfg, version, wr)

	err = cmd.Start()
	_ = wr.Close()

	if err != nil {
		cfg.Log.ErrorContext(
			ctx,
			"Start child",
			slog.String("version", version),
			slog.Any("err", err),
		)

		return failed(start, "crash")
	}

	cw := &childWatch{
		cfg:       cfg,
		cmd:       cmd,
		exitCh:    make(chan error, 1),
		msgs:      make(chan Message, messageBuffer),
		start:     start,
		version:   version,
		probation: probation,
	}
	go func() { cw.exitCh <- cmd.Wait() }()

	done := make(chan struct{})
	defer close(done)

	go readMessages(rd, cw.msgs, done, cfg.Log)

	defer func() {
		if cw.timer != nil {
			cw.timer.Stop()
		}
	}()

	if probation {
		cw.setDeadline(cfg.StartupTimeout)
	}

	hb := time.NewTicker(cfg.HeartbeatInterval)
	defer hb.Stop()

	return cw.loop(ctx, hb.C)
}

func (cw *childWatch) loop(ctx context.Context, hb <-chan time.Time) result {
	for {
		select {
		case <-ctx.Done():
			cw.stop(ctx)

			return result{kind: resCtx}
		case err := <-cw.exitCh:
			return cw.onExit(ctx, err)
		case hmsg, ok := <-cw.msgs:
			if !ok {
				cw.msgs = nil

				continue
			}

			res, finished := cw.onMessage(ctx, hmsg)
			if finished {
				return res
			}
		case <-cw.deadline:
			return cw.onDeadline(ctx)
		case <-hb:
			if cw.ready {
				cw.heartbeat(ctx)
			}
		}
	}
}

func (cw *childWatch) setDeadline(d time.Duration) {
	if cw.timer == nil {
		cw.timer = time.NewTimer(d)
	} else {
		cw.timer.Reset(d)
	}

	cw.deadline = cw.timer.C
}

// stop asks the child to terminate and kills it after the grace period.
func (cw *childWatch) stop(ctx context.Context) {
	if cw.exited {
		return
	}

	_ = cw.cmd.Process.Signal(syscall.SIGTERM) //nolint:errcheck // child may have exited

	t := time.NewTimer(cw.cfg.StopTimeout)
	select {
	case <-cw.exitCh: //nolint:errcheck // only the exit, not its status, matters here
		t.Stop()
	case <-t.C:
		cw.cfg.Log.WarnContext(
			ctx,
			"Child ignored SIGTERM, killing",
			slog.String("version", cw.version),
		)

		_ = cw.cmd.Process.Kill() //nolint:errcheck // child may have exited

		<-cw.exitCh //nolint:errcheck // only the exit, not its status, matters here
	}

	cw.exited = true
}

func (cw *childWatch) heartbeat(ctx context.Context) {
	if cw.cfg.StateDir == "" {
		return
	}

	err := os.MkdirAll(cw.cfg.StateDir, dirMode)
	if err == nil {
		err = touch(filepath.Join(cw.cfg.StateDir, HeartbeatFile))
		if err != nil {
			cw.cfg.Log.WarnContext(ctx, "Heartbeat", slog.Any("err", err))
		}
	}
}

// onExit builds the result for a child that exited by itself.
func (cw *childWatch) onExit(ctx context.Context, err error) result {
	cw.exited = true

	failMsg, ok := drainFail(cw.msgs)
	if ok {
		cw.cfg.Log.WarnContext(
			ctx,
			"Child reported failure before exiting",
			slog.String("reason", failMsg.Reason),
		)

		return result{
			kind:    resFailed,
			reason:  failMsg.Reason,
			failure: normKind(failMsg.Kind),
			ran:     time.Since(cw.start),
		}
	}

	cw.cfg.Log.WarnContext(
		ctx,
		"Child exited",
		slog.String("version", cw.version),
		slog.Any("err", err),
	)

	return result{
		kind:    resExited,
		reason:  "crash",
		failure: KindRelease,
		ran:     time.Since(cw.start),
	}
}

// onMessage handles one health message; finished reports that res is final.
func (cw *childWatch) onMessage(ctx context.Context, hmsg Message) (result, bool) {
	switch hmsg.Type {
	case msgReady:
		cw.ready = true

		cw.cfg.event(msgReady)
		cw.heartbeat(ctx)
		cw.setDeadline(cw.cfg.AliveTimeout)
	case "alive":
		cw.cfg.event("alive")

		if cw.ready {
			cw.setDeadline(cw.cfg.AliveTimeout)
		}
	case msgPromote:
		if !cw.probation {
			cw.cfg.Log.DebugContext(ctx, "Ignoring promote from known-good")

			return result{}, false
		}

		cw.stop(ctx)

		return result{kind: resPromoted, ran: time.Since(cw.start)}, true
	case msgRestart:
		cw.stop(ctx)

		return result{kind: resRestart, ran: time.Since(cw.start)}, true
	case msgFail:
		cw.cfg.Log.ErrorContext(
			ctx,
			"Child requested rollback",
			slog.String("version", cw.version),
			slog.String("reason", hmsg.Reason),
			slog.String("kind", hmsg.Kind),
		)
		cw.stop(ctx)

		reason := hmsg.Reason
		if reason == "" {
			reason = "fail"
		}

		return result{
			kind:    resFailed,
			reason:  reason,
			failure: normKind(hmsg.Kind),
			ran:     time.Since(cw.start),
		}, true
	}

	return result{}, false
}

// onDeadline builds the result for a child that missed its health deadline.
func (cw *childWatch) onDeadline(ctx context.Context) result {
	reason := "liveness"
	if !cw.ready {
		reason = "startup-check"
	}

	cw.cfg.Log.ErrorContext(
		ctx,
		"Child health deadline missed",
		slog.String("version", cw.version),
		slog.String("reason", reason),
	)
	cw.stop(ctx)

	return failed(cw.start, reason)
}

func normKind(k string) string {
	if k == KindDependency {
		return KindDependency
	}

	return KindRelease
}

// drainFail waits briefly for the reader to finish and returns a fail message
// if one was sent before the child exited.
func drainFail(msgs <-chan Message) (Message, bool) {
	if msgs == nil {
		return Message{}, false
	}

	timer := time.NewTimer(healthReadTimeout)
	defer timer.Stop()

	for {
		select {
		case m, ok := <-msgs:
			if !ok {
				return Message{}, false
			}

			if m.Type == msgFail {
				return m, true
			}
		case <-timer.C:
			return Message{}, false
		}
	}
}

func readMessages(r io.Reader, out chan<- Message, done <-chan struct{}, log *slog.Logger) {
	defer close(out)

	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, scanInitialBuffer), scanMaxBuffer)

	for sc.Scan() {
		var hmsg Message

		err := json.Unmarshal(sc.Bytes(), &hmsg)
		if err != nil {
			log.Warn("Bad health message", slog.Any("err", err))

			continue
		}

		select {
		case out <- hmsg:
		case <-done:
			return
		}
	}

	err := sc.Err()
	if err != nil && !errors.Is(err, os.ErrClosed) {
		log.Debug("Health pipe read", slog.Any("err", err))
	}
}
