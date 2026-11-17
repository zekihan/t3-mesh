package launcher

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

const (
	selfTestAlivePoll     = 100 * time.Millisecond
	selfTestReadyInterval = 200 * time.Millisecond
	selfTestTimeout       = 9 * time.Second
	selfTestEventBuffer   = 64
	selfTestChildTimeout  = 2 * time.Second
	selfTestMinBackoff    = 50 * time.Millisecond
)

var (
	errMissingBehavior   = errors.New("launcher: selftest child: missing behavior")
	errUnknownBehavior   = errors.New("unknown behavior")
	errTimedOut          = errors.New("timed out")
	errUnexpectedOutcome = errors.New("unexpected outcome")
)

// SelfTestChildArg is the hidden mode the main package dispatches to
// SelfTestChild: `<binary> launcher-selftest-child <behavior>`.
const SelfTestChildArg = "launcher-selftest-child"

// Behaviors understood by SelfTestChild.
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
		return errMissingBehavior
	}

	health, err := OpenHealth()
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()

	return runBehavior(ctx, health, args[0])
}

// runBehavior plays one scripted child behavior until ctx ends.
func runBehavior(ctx context.Context, health *Health, behavior string) error {
	switch behavior {
	case BehaviourOK:
		return childOK(ctx, health)
	case BehaviourPromote:
		return childPromote(ctx, health)
	case BehaviourCrash:
		os.Exit(1) //nolint:forbidigo // simulates a crashing child
	case BehaviourHang:
		err := health.Ready()
		if err != nil {
			return err
		}

		<-ctx.Done()
	case BehaviourSilent:
		<-ctx.Done()
	case BehaviourFail:
		err := health.Fail("selftest failure", KindDependency)
		if err != nil {
			return err
		}

		<-ctx.Done()
	case BehaviourHandover:
		return childHandover(ctx, health)
	case BehaviourStubborn:
		return childStubborn(health)
	default:
		return fmt.Errorf("launcher: selftest child: %w %q", errUnknownBehavior, behavior)
	}

	return nil
}

// childAlive sends alive messages until ctx ends.
func childAlive(ctx context.Context, health *Health) error {
	ticker := time.NewTicker(selfTestAlivePoll)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			err := health.Alive()
			if err != nil {
				return err
			}
		}
	}
}

func childOK(ctx context.Context, h *Health) error {
	err := h.Ready()
	if err != nil {
		return err
	}

	return childAlive(ctx, h)
}

func childPromote(ctx context.Context, health *Health) error {
	err := health.Ready()
	if err != nil {
		return err
	}

	err = health.Alive()
	if err != nil {
		return err
	}

	err = health.Promote()
	if err != nil {
		return err
	}

	return childAlive(ctx, health)
}

func childHandover(ctx context.Context, health *Health) error {
	err := health.Ready()
	if err != nil {
		return err
	}

	t := time.NewTimer(selfTestReadyInterval)
	defer t.Stop()

	select {
	case <-ctx.Done():
		return nil
	case <-t.C:
	}

	err = health.Restart()
	if err != nil {
		return err
	}

	<-ctx.Done()

	return nil
}

func childStubborn(h *Health) error {
	signal.Ignore(syscall.SIGTERM)

	err := h.Ready()
	if err != nil {
		return err
	}

	select {}
}

// selfTestRun is one SelfTest installation: a temporary layout whose
// versions run scripted behaviors.
type selfTestRun struct {
	behaviors map[string]string
	layout    Layout
	state     string
}

// SelfTest supervises dummy children, re-invoking binary, through start with
// ready and alive, a crash and a rollback, then a promotion, all in a
// temporary layout.
func SelfTest(ctx context.Context, binary string) error {
	ctx, cancel := context.WithTimeout(ctx, selfTestTimeout)
	defer cancel()

	tmp, err := os.MkdirTemp("", "t3-mesh-selftest-")
	if err != nil {
		return fmt.Errorf("launcher: selftest temp dir: %w", err)
	}
	defer os.RemoveAll(tmp)

	st := &selfTestRun{
		behaviors: map[string]string{"v1": BehaviourOK, "v2": BehaviourOK},
		layout:    Layout{Dir: filepath.Join(tmp, "install")},
		state:     filepath.Join(tmp, "state"),
	}

	for _, ver := range []string{"v1", "v2"} {
		cp := filepath.Join(tmp, "stage-"+ver)

		err = copyFile(binary, cp)
		if err != nil {
			return err
		}

		err = st.layout.Stage(ver, cp)
		if err != nil {
			return err
		}
	}

	var reexec bool

	err = st.scenarioStart(ctx, &reexec)
	if err != nil {
		return err
	}

	err = st.scenarioRollback(ctx, &reexec)
	if err != nil {
		return err
	}

	return st.scenarioPromote(ctx, &reexec)
}

func (st *selfTestRun) setup(cur string) error {
	err := st.layout.setLink(linkKnownGood, "v1")
	if err != nil {
		return err
	}

	return st.layout.SetCurrent(cur)
}

// run runs the supervisor until pred(event) returns true, then cancels it.
func (st *selfTestRun) run(
	ctx context.Context,
	name string,
	pred func(ev string) bool,
	reexec *bool,
) error {
	rctx, rcancel := context.WithCancel(ctx)
	defer rcancel()

	evCh := make(chan string, selfTestEventBuffer)
	cfg := Config{
		Layout:   st.layout,
		StateDir: st.state,
		ArgsFor: func(v string) []string {
			return []string{SelfTestChildArg, st.behaviors[v]}
		},
		StartupTimeout: selfTestChildTimeout,
		AliveTimeout:   selfTestChildTimeout,
		StopTimeout:    selfTestChildTimeout,
		MinBackoff:     selfTestMinBackoff,
		Log:            slog.New(slog.DiscardHandler),
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

	matched := false
	for !matched {
		select {
		case ev := <-evCh:
			matched = pred(ev)
		case err := <-errCh:
			if err != nil {
				return fmt.Errorf("launcher selftest %s: %w", name, err)
			}

			return nil
		case <-ctx.Done():
			return fmt.Errorf("launcher selftest %s: %w", name, errTimedOut)
		}
	}

	rcancel()

	err := <-errCh
	if err != nil {
		return fmt.Errorf("launcher selftest %s: %w", name, err)
	}

	return nil
}

// scenarioStart: 1. Known-good starts, becomes ready and stays alive.
func (st *selfTestRun) scenarioStart(ctx context.Context, reexec *bool) error {
	seenReady := false

	err := st.setup("v1")
	if err != nil {
		return err
	}

	return st.run(ctx, "start", func(ev string) bool {
		if ev == msgReady {
			seenReady = true
		}

		return seenReady && ev == "alive"
	}, reexec)
}

// scenarioRollback: 2. Crash on probation rolls back to known-good, which
// then runs.
func (st *selfTestRun) scenarioRollback(ctx context.Context, reexec *bool) error {
	st.behaviors["v2"] = BehaviourCrash

	err := st.setup("v2")
	if err != nil {
		return err
	}

	rolled := false

	err = st.run(ctx, "rollback", func(ev string) bool {
		if ev == "rollback" {
			rolled = true
		}

		return rolled && ev == msgReady
	}, reexec)
	if err != nil {
		return err
	}

	cur, err := st.layout.Current()
	if err != nil || cur != "v1" {
		return fmt.Errorf("launcher selftest rollback: current is %q (%w), want v1", cur, err)
	}

	data, err := os.ReadFile(filepath.Join(st.state, OutcomeFile))
	if err != nil {
		return fmt.Errorf("launcher selftest rollback: read outcome: %w", err)
	}

	var out Outcome

	err = json.Unmarshal(data, &out)
	if err != nil {
		return fmt.Errorf("launcher selftest rollback: decode outcome: %w", err)
	}

	if out.Version != "v2" || out.Reason != "crash" || out.Kind != KindRelease {
		return fmt.Errorf("launcher selftest rollback: %w %+v", errUnexpectedOutcome, out)
	}

	return nil
}

// scenarioPromote: 3. Promotion repoints known-good and re-execs.
func (st *selfTestRun) scenarioPromote(ctx context.Context, reexec *bool) error {
	st.behaviors["v2"] = BehaviourPromote

	err := st.setup("v2")
	if err != nil {
		return err
	}

	*reexec = false

	err = st.run(ctx, "promote", func(string) bool { return false }, reexec)
	if err != nil {
		return err
	}

	knownGood, err := st.layout.KnownGood()
	if err != nil || knownGood != "v2" || !*reexec {
		return fmt.Errorf(
			"launcher selftest promote: known-good %q (%w), reexec %v",
			knownGood,
			err,
			*reexec,
		)
	}

	return nil
}
