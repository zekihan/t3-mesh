package launcher

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

// SelfTestChildArg is the hidden mode the main package dispatches to
// SelfTestChild: `<binary> launcher-selftest-child <behaviour>`.
const SelfTestChildArg = "launcher-selftest-child"

// Behaviours understood by SelfTestChild.
const (
	BehaviourOK       = "ok"       // ready, then alive until SIGTERM
	BehaviourPromote  = "promote"  // ready, alive, promote, alive until SIGTERM
	BehaviourCrash    = "crash"    // exit 1 immediately
	BehaviourHang     = "hang"     // ready, then silent
	BehaviourSilent   = "silent"   // never ready
	BehaviourFail     = "fail"     // fail message (dependency), then wait
	BehaviourStubborn = "stubborn" // ready, ignore SIGTERM
	BehaviourHandover = "handover" // ready, then ask for a restart into current
)

// SelfTestChild is the dummy child; args are the arguments after
// launcher-selftest-child.
func SelfTestChild(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("launcher: selftest child: missing behaviour")
	}
	h, err := OpenHealth()
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	alive := func() error {
		t := time.NewTicker(100 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return nil
			case <-t.C:
				if err := h.Alive(); err != nil {
					return err
				}
			}
		}
	}
	switch args[0] {
	case BehaviourOK:
		if err := h.Ready(); err != nil {
			return err
		}
		return alive()
	case BehaviourPromote:
		if err := h.Ready(); err != nil {
			return err
		}
		if err := h.Alive(); err != nil {
			return err
		}
		if err := h.Promote(); err != nil {
			return err
		}
		return alive()
	case BehaviourCrash:
		os.Exit(1)
	case BehaviourHang:
		if err := h.Ready(); err != nil {
			return err
		}
		<-ctx.Done()
	case BehaviourSilent:
		<-ctx.Done()
	case BehaviourFail:
		if err := h.Fail("selftest failure", KindDependency); err != nil {
			return err
		}
		<-ctx.Done()
	case BehaviourHandover:
		if err := h.Ready(); err != nil {
			return err
		}
		t := time.NewTimer(200 * time.Millisecond)
		defer t.Stop()
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
		if err := h.Restart(); err != nil {
			return err
		}
		<-ctx.Done()
	case BehaviourStubborn:
		signal.Ignore(syscall.SIGTERM)
		if err := h.Ready(); err != nil {
			return err
		}
		select {}
	default:
		return fmt.Errorf("launcher: selftest child: unknown behaviour %q", args[0])
	}
	return nil
}

// SelfTest supervises dummy children, re-invoking binary, through start with
// ready and alive, a crash and a rollback, then a promotion, all in a
// temporary layout.
func SelfTest(ctx context.Context, binary string) error {
	ctx, cancel := context.WithTimeout(ctx, 9*time.Second)
	defer cancel()
	tmp, err := os.MkdirTemp("", "t3-mesh-selftest-")
	if err != nil {
		return fmt.Errorf("launcher: selftest temp dir: %w", err)
	}
	defer os.RemoveAll(tmp)

	l := Layout{Dir: filepath.Join(tmp, "install")}
	state := filepath.Join(tmp, "state")
	for _, v := range []string{"v1", "v2"} {
		cp := filepath.Join(tmp, "stage-"+v)
		if err := copyFile(binary, cp); err != nil {
			return err
		}
		if err := l.Stage(v, cp); err != nil {
			return err
		}
	}
	behaviours := map[string]string{"v1": BehaviourOK, "v2": BehaviourOK}
	setup := func(cur string) error {
		if err := l.setLink(linkKnownGood, "v1"); err != nil {
			return err
		}
		return l.SetCurrent(cur)
	}

	// Scenario runner: run until pred(event) returns true, then cancel.
	run := func(name string, pred func(ev string) bool, reexec *bool) error {
		rctx, rcancel := context.WithCancel(ctx)
		defer rcancel()
		evCh := make(chan string, 64)
		cfg := Config{
			Layout:         l,
			StateDir:       state,
			ArgsFor:        func(v string) []string { return []string{SelfTestChildArg, behaviours[v]} },
			StartupTimeout: 2 * time.Second,
			AliveTimeout:   2 * time.Second,
			StopTimeout:    2 * time.Second,
			MinBackoff:     50 * time.Millisecond,
			Log:            slog.New(slog.NewTextHandler(io.Discard, nil)),
			ReexecArgs:     []string{"launcher"},
			Exec: func(string, []string, []string) error {
				*reexec = true
				return nil
			},
			events: func(ev string) {
				select {
				case evCh <- ev:
				default:
				}
			},
		}
		errCh := make(chan error, 1)
		go func() { errCh <- Run(rctx, cfg) }()
		ok := false
		for !ok {
			select {
			case ev := <-evCh:
				ok = pred(ev)
			case err := <-errCh:
				if err != nil {
					return fmt.Errorf("launcher selftest %s: %w", name, err)
				}
				return nil
			case <-ctx.Done():
				return fmt.Errorf("launcher selftest %s: timed out", name)
			}
		}
		rcancel()
		if err := <-errCh; err != nil {
			return fmt.Errorf("launcher selftest %s: %w", name, err)
		}
		return nil
	}

	// 1. known-good starts, becomes ready and stays alive.
	seenReady := false
	var reexec bool
	if err := setup("v1"); err != nil {
		return err
	}
	if err := run("start", func(ev string) bool {
		if ev == "ready" {
			seenReady = true
		}
		return seenReady && ev == "alive"
	}, &reexec); err != nil {
		return err
	}

	// 2. crash on probation rolls back to known-good, which then runs.
	behaviours["v2"] = BehaviourCrash
	if err := setup("v2"); err != nil {
		return err
	}
	rolled := false
	if err := run("rollback", func(ev string) bool {
		if ev == "rollback" {
			rolled = true
		}
		return rolled && ev == "ready"
	}, &reexec); err != nil {
		return err
	}
	if cur, err := l.Current(); err != nil || cur != "v1" {
		return fmt.Errorf("launcher selftest rollback: current is %q (%v), want v1", cur, err)
	}
	b, err := os.ReadFile(filepath.Join(state, OutcomeFile))
	if err != nil {
		return fmt.Errorf("launcher selftest rollback: read outcome: %w", err)
	}
	var out Outcome
	if err := json.Unmarshal(b, &out); err != nil {
		return fmt.Errorf("launcher selftest rollback: decode outcome: %w", err)
	}
	if out.Version != "v2" || out.Reason != "crash" || out.Kind != KindRelease {
		return fmt.Errorf("launcher selftest rollback: unexpected outcome %+v", out)
	}

	// 3. promotion repoints known-good and re-execs.
	behaviours["v2"] = BehaviourPromote
	if err := setup("v2"); err != nil {
		return err
	}
	reexec = false
	if err := run("promote", func(string) bool { return false }, &reexec); err != nil {
		return err
	}
	if kg, err := l.KnownGood(); err != nil || kg != "v2" || !reexec {
		return fmt.Errorf(
			"launcher selftest promote: known-good %q (%v), reexec %v",
			kg,
			err,
			reexec,
		)
	}
	return nil
}
