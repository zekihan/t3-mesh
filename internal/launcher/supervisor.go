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
	Layout   Layout
	StateDir string
	// Args are the arguments passed to the child.
	Args []string
	// ArgsFor, when set, overrides Args per version.
	ArgsFor func(version string) []string
	// StartupTimeout is how long a child on probation has to send ready (30 s).
	StartupTimeout time.Duration
	// AliveTimeout is the longest silence tolerated after ready (30 s).
	AliveTimeout time.Duration
	// StopTimeout is the SIGTERM grace before SIGKILL (10 s).
	StopTimeout time.Duration
	// HeartbeatInterval is how often the heartbeat file is touched (1 min).
	HeartbeatInterval time.Duration
	// MinBackoff and MaxBackoff bound restarts of the known-good (1 s, 1 min).
	MinBackoff, MaxBackoff time.Duration
	Log                    *slog.Logger

	// Command builds the child command; default exec.Command.
	Command func(binary string, args []string) *exec.Cmd
	// ReexecArgs is the launcher's own argument list (without argv[0]) used
	// when re-executing after promotion; default os.Args[1:].
	ReexecArgs []string
	// Exec replaces the process image; default syscall.Exec. If it returns,
	// Run returns its error (nil when a test hook returns nil).
	Exec func(path string, argv []string, env []string) error

	events func(ev string)
}

func (c *Config) defaults() {
	if c.StartupTimeout <= 0 {
		c.StartupTimeout = 30 * time.Second
	}
	if c.AliveTimeout <= 0 {
		c.AliveTimeout = 30 * time.Second
	}
	if c.StopTimeout <= 0 {
		c.StopTimeout = 10 * time.Second
	}
	if c.HeartbeatInterval <= 0 {
		c.HeartbeatInterval = time.Minute
	}
	if c.MinBackoff <= 0 {
		c.MinBackoff = time.Second
	}
	if c.MaxBackoff < c.MinBackoff {
		c.MaxBackoff = time.Minute
		if c.MaxBackoff < c.MinBackoff {
			c.MaxBackoff = c.MinBackoff
		}
	}
	if c.Log == nil {
		c.Log = slog.Default()
	}
	if c.Command == nil {
		c.Command = func(binary string, args []string) *exec.Cmd { return exec.Command(binary, args...) }
	}
	if c.Exec == nil {
		c.Exec = syscall.Exec
	}
	if c.ReexecArgs == nil && len(os.Args) > 1 {
		c.ReexecArgs = os.Args[1:]
	}
}

func (c *Config) event(ev string) {
	if c.events != nil {
		c.events(ev)
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
	kind    resultKind
	reason  string // outcome reason for failures on probation
	failure string // outcome kind
	ran     time.Duration
}

// Run supervises the current binary until ctx is cancelled.
func Run(ctx context.Context, cfg Config) error {
	cfg.defaults()
	backoff := cfg.MinBackoff
	for {
		if ctx.Err() != nil {
			return nil
		}
		cur, err := cfg.Layout.Current()
		if err != nil {
			return fmt.Errorf("launcher: resolve current: %w", err)
		}
		kg, err := cfg.Layout.KnownGood()
		if err != nil {
			return fmt.Errorf("launcher: resolve known-good: %w", err)
		}
		probation := cur != kg
		if probation {
			cfg.Log.Info("starting version on probation", "version", cur, "known_good", kg)
		} else {
			cfg.Log.Info("starting known-good version", "version", cur)
		}
		res := superviseOnce(ctx, &cfg, cur, probation)
		switch res.kind {
		case resCtx:
			return nil
		case resRestart:
			cfg.Log.Info("child requested restart into current", "version", cur)
			backoff = cfg.MinBackoff

			continue
		case resPromoted:
			if err := cfg.Layout.Promote(); err != nil {
				return fmt.Errorf("launcher: promote %s: %w", cur, err)
			}
			cfg.event("promoted")
			cfg.Log.Info("promoted, re-executing launcher", "version", cur)
			path := cfg.Layout.Dir + "/" + linkKnownGood + "/" + BinaryName
			argv := append([]string{path}, cfg.ReexecArgs...)
			if err := cfg.Exec(path, argv, os.Environ()); err != nil {
				return fmt.Errorf("launcher: re-exec %s: %w", path, err)
			}
			return nil
		case resFailed, resExited:
			if probation {
				if err := rollback(&cfg, cur, res); err != nil {
					return err
				}
				backoff = cfg.MinBackoff
				continue
			}
			cfg.Log.Error("known-good version stopped, nothing to roll back to",
				"version", cur, "reason", res.reason, "backoff", backoff)
			if res.ran > cfg.MaxBackoff {
				backoff = cfg.MinBackoff
			}
			t := time.NewTimer(backoff)
			select {
			case <-ctx.Done():
				t.Stop()
				return nil
			case <-t.C:
			}
			backoff = min(backoff*2, cfg.MaxBackoff)
		}
	}
}

func rollback(cfg *Config, failed string, res result) error {
	reason, kind := res.reason, res.failure
	if reason == "" {
		reason = "crash"
	}
	if kind != KindDependency {
		kind = KindRelease
	}
	cfg.Log.Error("rolling back failed version", "version", failed, "reason", reason, "kind", kind)
	if err := cfg.Layout.Rollback(); err != nil {
		return fmt.Errorf("launcher: rollback from %s: %w", failed, err)
	}
	cfg.event("rollback")
	if cfg.StateDir != "" {
		out := Outcome{Version: failed, Reason: reason, Kind: kind, At: time.Now().UTC().Format(time.RFC3339)}
		if err := writeJSONAtomic(filepath.Join(cfg.StateDir, OutcomeFile), out); err != nil {
			cfg.Log.Error("write launcher outcome", "err", err)
		}
	}
	return nil
}

func writeJSONAtomic(path string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("launcher: encode %s: %w", path, err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("launcher: create state dir: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return fmt.Errorf("launcher: write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("launcher: rename %s: %w", tmp, err)
	}
	return nil
}

func touch(path string) error {
	return touchAt(path, time.Now())
}

func touchAt(path string, now time.Time) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("launcher: touch %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("launcher: touch %s: %w", path, err)
	}
	if err := os.Chtimes(path, now, now); err != nil {
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

// superviseOnce starts the child and watches it until it ends, fails, is
// promoted or ctx is cancelled. The child has stopped when it returns.
func superviseOnce(ctx context.Context, cfg *Config, version string, probation bool) result {
	start := time.Now()
	fail := func(reason string) result {
		return result{kind: resFailed, reason: reason, failure: KindRelease, ran: time.Since(start)}
	}
	r, w, err := os.Pipe()
	if err != nil {
		cfg.Log.Error("create health pipe", "err", err)
		return fail("crash")
	}
	defer r.Close()
	args := cfg.Args
	if cfg.ArgsFor != nil {
		args = cfg.ArgsFor(version)
	}
	cmd := cfg.Command(cfg.Layout.Binary(version), args)
	cmd.ExtraFiles = []*os.File{w}
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
	err = cmd.Start()
	_ = w.Close()
	if err != nil {
		cfg.Log.Error("start child", "version", version, "err", err)
		return fail("crash")
	}

	exitCh := make(chan error, 1)
	go func() { exitCh <- cmd.Wait() }()
	done := make(chan struct{})
	defer close(done)
	msgs := make(chan Message, 16)
	go readMessages(r, msgs, done, cfg.Log)

	exited := false
	stop := func() {
		if exited {
			return
		}
		_ = cmd.Process.Signal(syscall.SIGTERM)
		t := time.NewTimer(cfg.StopTimeout)
		select {
		case <-exitCh:
			t.Stop()
		case <-t.C:
			cfg.Log.Warn("child ignored SIGTERM, killing", "version", version)
			_ = cmd.Process.Kill()
			<-exitCh
		}
		exited = true
	}

	ready := false
	var deadline <-chan time.Time
	var dt *time.Timer
	setDeadline := func(d time.Duration) {
		if dt == nil {
			dt = time.NewTimer(d)
		} else {
			dt.Reset(d)
		}
		deadline = dt.C
	}
	defer func() {
		if dt != nil {
			dt.Stop()
		}
	}()
	if probation {
		setDeadline(cfg.StartupTimeout)
	}
	hb := time.NewTicker(cfg.HeartbeatInterval)
	defer hb.Stop()
	heartbeat := func() {
		if cfg.StateDir == "" {
			return
		}
		if err := os.MkdirAll(cfg.StateDir, 0o755); err == nil {
			err = touch(filepath.Join(cfg.StateDir, HeartbeatFile))
			if err != nil {
				cfg.Log.Warn("heartbeat", "err", err)
			}
		}
	}

	for {
		select {
		case <-ctx.Done():
			stop()
			return result{kind: resCtx}
		case err := <-exitCh:
			exited = true
			reason := "crash"
			if m, ok := drainFail(msgs); ok {
				cfg.Log.Warn("child reported failure before exiting", "reason", m.Reason)
				return result{kind: resFailed, reason: m.Reason, failure: normKind(m.Kind), ran: time.Since(start)}
			}
			cfg.Log.Warn("child exited", "version", version, "err", err)
			return result{kind: resExited, reason: reason, failure: KindRelease, ran: time.Since(start)}
		case m, ok := <-msgs:
			if !ok {
				msgs = nil
				continue
			}
			switch m.Type {
			case "ready":
				ready = true
				cfg.event("ready")
				heartbeat()
				setDeadline(cfg.AliveTimeout)
			case "alive":
				cfg.event("alive")
				if ready {
					setDeadline(cfg.AliveTimeout)
				}
			case "promote":
				if !probation {
					cfg.Log.Debug("ignoring promote from known-good")
					continue
				}
				stop()
				return result{kind: resPromoted, ran: time.Since(start)}
			case "restart":
				stop()
				return result{kind: resRestart, ran: time.Since(start)}
			case "fail":
				cfg.Log.Error("child requested rollback", "version", version, "reason", m.Reason, "kind", m.Kind)
				stop()
				reason := m.Reason
				if reason == "" {
					reason = "fail"
				}
				return result{kind: resFailed, reason: reason, failure: normKind(m.Kind), ran: time.Since(start)}
			}
		case <-deadline:
			reason := "liveness"
			if !ready {
				reason = "startup-check"
			}
			cfg.Log.Error("child health deadline missed", "version", version, "reason", reason)
			stop()
			return result{kind: resFailed, reason: reason, failure: KindRelease, ran: time.Since(start)}
		case <-hb.C:
			if ready {
				heartbeat()
			}
		}
	}
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
	t := time.NewTimer(500 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case m, ok := <-msgs:
			if !ok {
				return Message{}, false
			}
			if m.Type == "fail" {
				return m, true
			}
		case <-t.C:
			return Message{}, false
		}
	}
}

func readMessages(r io.Reader, out chan<- Message, done <-chan struct{}, log *slog.Logger) {
	defer close(out)
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 4096), 64*1024)
	for sc.Scan() {
		var m Message
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			log.Warn("bad health message", "err", err)
			continue
		}
		select {
		case out <- m:
		case <-done:
			return
		}
	}
	if err := sc.Err(); err != nil && !errors.Is(err, os.ErrClosed) {
		log.Debug("health pipe read", "err", err)
	}
}
