package launcher

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	if len(os.Args) > 2 && os.Args[1] == SelfTestChildArg {
		err := SelfTestChild(os.Args[2:])
		if err != nil {
			_, _ = os.Stderr.WriteString(err.Error() + "\n")

			os.Exit(2) //nolint:forbidigo // the child must exit non-zero without running tests
		}

		return
	}

	m.Run()
}

func newLayout(t *testing.T, versions ...string) Layout {
	t.Helper()

	lay := Layout{Dir: filepath.Join(t.TempDir(), "install")}
	for _, ver := range versions {
		src := filepath.Join(t.TempDir(), "bin")

		err := copyFile(os.Args[0], src)
		if err != nil {
			t.Fatal(err)
		}

		err = lay.Stage(ver, src)
		if err != nil {
			t.Fatal(err)
		}
	}

	return lay
}

func mustNoErr(t *testing.T, err error) {
	t.Helper()

	if err != nil {
		t.Fatal(err)
	}
}

func wantLink(t *testing.T, what, got, want string) {
	t.Helper()

	if got != want {
		t.Fatalf("%s=%s, want %s", what, got, want)
	}
}

func TestLayout(t *testing.T) {
	lay := newLayout(t, "1", "2", "3")

	info, err := os.Stat(lay.Binary("1"))
	if err != nil || info.Mode().Perm() != 0o755 {
		t.Fatalf("stage: %v %v", err, info)
	}

	_, err = lay.Current()
	if err == nil {
		t.Fatal("expected error without link")
	}

	mustNoErr(t, lay.SetCurrent("1"))
	mustNoErr(t, lay.Promote())

	kg, _ := lay.KnownGood()
	wantLink(t, "kg", kg, "1")

	mustNoErr(t, lay.SetCurrent("2"))
	mustNoErr(t, lay.Promote())

	kg, _ = lay.KnownGood()
	pg, _ := lay.PreviousGood()

	wantLink(t, "kg", kg, "2")
	wantLink(t, "pg", pg, "1")

	mustNoErr(t, lay.SetCurrent("3"))
	mustNoErr(t, lay.Rollback())

	c, _ := lay.Current()
	wantLink(t, "rollback current", c, "2")

	target, _ := os.Readlink(filepath.Join(lay.Dir, "current"))
	wantLink(t, "target", target, filepath.Join("versions", "2"))

	checkPruneAndFallback(t, lay)
}

func checkPruneAndFallback(t *testing.T, lay Layout) {
	t.Helper()

	mustNoErr(t, lay.Prune(0))

	_, err := os.Stat(lay.Binary("3"))
	if err == nil {
		t.Fatal("3 should be pruned")
	}

	_, err = os.Stat(lay.Binary("1"))
	if err != nil {
		t.Fatal("1 is previous-good, must stay")
	}

	mustNoErr(t, lay.FallbackToPrevious())

	kg, _ := lay.KnownGood()
	c, _ := lay.Current()

	wantLink(t, "fallback kg", kg, "1")
	wantLink(t, "fallback cur", c, "1")

	err = lay.SetCurrent("nope")
	if err == nil {
		t.Fatal("unstaged version accepted")
	}

	err = lay.Stage("../x", "/dev/null")
	if err == nil {
		t.Fatal("bad version accepted")
	}
}

func TestFallback(t *testing.T) {
	lay := newLayout(t, "1", "2")
	_ = lay.SetCurrent("1")
	_ = lay.Promote()
	_ = lay.SetCurrent("2")
	_ = lay.Promote()
	hb := filepath.Join(t.TempDir(), "hb")
	stateDir := t.TempDir()
	now := time.Now()

	err := touch(hb)
	if err != nil {
		t.Fatal(err)
	}

	step := func(name string, at time.Duration, want bool) {
		t.Helper()

		ok, ferr := Fallback(lay, stateDir, hb, 5*time.Minute, now.Add(at))
		if ok != want || ferr != nil {
			t.Fatalf("%s: %v %v", name, ok, ferr)
		}
	}

	step("fresh heartbeat", 0, false)
	// First stale reading (e.g. right after wake) only records suspicion.
	step("first stale reading", 6*time.Minute, false)
	// A heartbeat after the suspicion clears it.
	mustNoErr(t, touchAt(hb, now.Add(7*time.Minute)))
	step("recovered heartbeat", 8*time.Minute, false)
	step("new suspicion", 13*time.Minute, false)
	step("stale twice", 18*time.Minute, true)

	if kg, _ := lay.KnownGood(); kg != "1" {
		t.Fatalf("kg=%s", kg)
	}

	// The abandoned version is recorded as a failed release for the agent.
	data, err := os.ReadFile(filepath.Join(stateDir, OutcomeFile))
	if err != nil || !strings.Contains(string(data), `"version":"2"`) ||
		!strings.Contains(string(data), `"kind":"`+KindRelease+`"`) {
		t.Fatalf("fallback outcome = %s, %v", data, err)
	}

	step("re-suspect after fallback", time.Hour, false)
	step("second fallback", 2*time.Hour, false)
}

type env struct {
	events chan string
	reexec chan []string
	l      Layout
	state  string
	cfg    Config
}

func newEnv(t *testing.T, behaviors map[string]string, cur, kg string) *env {
	t.Helper()

	versions := make([]string, 0, len(behaviors))
	for v := range behaviors {
		versions = append(versions, v)
	}

	lay := newLayout(t, versions...)

	err := lay.setLink(linkKnownGood, kg)
	if err != nil {
		t.Fatal(err)
	}

	err = lay.SetCurrent(cur)
	if err != nil {
		t.Fatal(err)
	}

	en := &env{
		l:      lay,
		state:  t.TempDir(),
		events: make(chan string, 256),
		reexec: make(chan []string, 1),
	}
	en.cfg = Config{
		Layout:            lay,
		StateDir:          en.state,
		ArgsFor:           func(v string) []string { return []string{SelfTestChildArg, behaviors[v]} },
		StartupTimeout:    time.Second,
		AliveTimeout:      time.Second,
		StopTimeout:       300 * time.Millisecond,
		HeartbeatInterval: 50 * time.Millisecond,
		MinBackoff:        20 * time.Millisecond,
		MaxBackoff:        100 * time.Millisecond,
		Log:               slog.New(slog.DiscardHandler),
		Command:           nil,
		ReexecArgs:        []string{"launcher", "--x"},
		Exec: func(p string, argv, _ []string) error {
			en.reexec <- append([]string{p}, argv...)

			return nil
		},
		events: func(ev string) {
			select {
			case en.events <- ev:
			default:
			}
		},
	}

	t.Cleanup(func() {})

	return en
}

func (en *env) start(t *testing.T) (func(), <-chan error) {
	t.Helper()

	ctx, cancel := context.WithCancel(t.Context())

	ch := make(chan error, 1)
	go func() { ch <- Run(ctx, en.cfg) }()

	t.Cleanup(cancel)

	return cancel, ch
}

func (en *env) waitEvent(t *testing.T, want string) {
	t.Helper()

	to := time.After(8 * time.Second)

	for {
		select {
		case ev := <-en.events:
			if ev == want {
				return
			}
		case <-to:
			t.Fatalf("timeout waiting for %s", want)
		}
	}
}

func (en *env) outcome(t *testing.T) Outcome {
	t.Helper()

	data, err := os.ReadFile(filepath.Join(en.state, OutcomeFile))
	if err != nil {
		t.Fatal(err)
	}

	var out Outcome

	err = json.Unmarshal(data, &out)
	if err != nil {
		t.Fatal(err)
	}

	_, err = time.Parse(time.RFC3339, out.At)
	if err != nil {
		t.Fatal(err)
	}

	return out
}

func (en *env) finish(t *testing.T, cancel func(), done <-chan error) {
	t.Helper()
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return")
	}
}

func TestRollbackScenarios(t *testing.T) {
	cases := []struct { //nolint:govet // positional table rows read better in this order
		name, behavior, reason, kind string
		tweak                        func(*Config)
	}{
		{"crash", BehaviourCrash, "crash", KindRelease, nil},
		{
			"startup",
			BehaviourSilent,
			"startup-check",
			KindRelease,
			func(c *Config) { c.StartupTimeout = 200 * time.Millisecond },
		},
		{
			"liveness",
			BehaviourHang,
			"liveness",
			KindRelease,
			func(c *Config) { c.AliveTimeout = 200 * time.Millisecond },
		},
		{
			"liveness-stubborn",
			BehaviourStubborn,
			"liveness",
			KindRelease,
			func(c *Config) { c.AliveTimeout = 200 * time.Millisecond },
		},
		{"fail", BehaviourFail, "selftest failure", KindDependency, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			en := newEnv(
				t,
				map[string]string{"good": BehaviourOK, "bad": tc.behavior},
				"bad",
				"good",
			)
			if tc.tweak != nil {
				tc.tweak(&en.cfg)
			}

			cancel, done := en.start(t)
			en.waitEvent(t, "rollback")
			en.waitEvent(t, "ready")

			o := en.outcome(t)
			if o.Version != "bad" || o.Reason != tc.reason || o.Kind != tc.kind {
				t.Fatalf("outcome %+v", o)
			}

			if c, _ := en.l.Current(); c != "good" {
				t.Fatalf("current %s", c)
			}

			en.finish(t, cancel, done)
		})
	}
}

func TestPromoteReexec(t *testing.T) {
	en := newEnv(t, map[string]string{"good": BehaviourOK, "new": BehaviourPromote}, "new", "good")

	_, done := en.start(t)
	select {
	case argv := <-en.reexec:
		want := filepath.Join(en.l.Dir, "known-good", BinaryName)
		if argv[0] != want || argv[1] != want || argv[2] != "launcher" || argv[3] != "--x" {
			t.Fatalf("argv %v", argv)
		}
	case <-time.After(8 * time.Second):
		t.Fatal("no reexec")
	}

	err := <-done
	if err != nil {
		t.Fatal(err)
	}

	kg, _ := en.l.KnownGood()

	pg, _ := en.l.PreviousGood()
	if kg != "new" || pg != "good" {
		t.Fatalf("kg=%s pg=%s", kg, pg)
	}
}

func TestHandoverToStagedVersion(t *testing.T) {
	en := newEnv(
		t,
		map[string]string{"good": BehaviourHandover, "new": BehaviourPromote},
		"good",
		"good",
	)
	_, done := en.start(t)
	en.waitEvent(t, "ready")

	err := en.l.SetCurrent("new")
	if err != nil {
		t.Fatal(err)
	}

	select {
	case <-en.reexec:
	case <-time.After(8 * time.Second):
		t.Fatal("staged version was not started and promoted")
	}

	err = <-done
	if err != nil {
		t.Fatal(err)
	}

	if kg, _ := en.l.KnownGood(); kg != "new" {
		t.Fatalf("known-good = %s", kg)
	}

	_, err = os.Stat(filepath.Join(en.state, OutcomeFile))
	if err == nil {
		t.Fatal("handover must not record a failure")
	}
}

func TestKnownGoodCrashRestarts(t *testing.T) {
	en := newEnv(t, map[string]string{"good": BehaviourCrash}, "good", "good")
	cancel, done := en.start(t)

	<-time.After(400 * time.Millisecond)
	en.finish(t, cancel, done)

	_, err := os.Stat(filepath.Join(en.state, OutcomeFile))
	if err == nil {
		t.Fatal("no outcome expected for known-good")
	}

	if c, _ := en.l.Current(); c != "good" {
		t.Fatal(c)
	}
}

func TestShutdownDuringChildStartKeepsProbation(t *testing.T) {
	en := newEnv(t, map[string]string{"good": BehaviourOK, "new": BehaviourOK}, "new", "good")

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	en.cfg.Command = func(path string, args []string) *exec.Cmd {
		cmd := exec.CommandContext(ctx, path, args...)

		cancel()

		return cmd
	}

	mustNoErr(t, Run(ctx, en.cfg))

	cur, err := en.l.Current()
	mustNoErr(t, err)

	if cur != "new" {
		t.Errorf("current on shutdown = %q, want new", cur)
	}

	kg, err := en.l.KnownGood()
	mustNoErr(t, err)
	wantLink(t, "known-good on shutdown", kg, "good")

	_, err = os.Stat(filepath.Join(en.state, OutcomeFile))
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("shutdown wrote a failure outcome: stat error = %v", err)
	}
}

func TestHeartbeatAndShutdown(t *testing.T) {
	en := newEnv(t, map[string]string{"good": BehaviourOK}, "good", "good")
	cancel, done := en.start(t)
	en.waitEvent(t, "ready")
	hb := filepath.Join(en.state, HeartbeatFile)

	deadline := time.Now().Add(5 * time.Second)

	for {
		info, err := os.Stat(hb)
		if err == nil && time.Since(info.ModTime()) < time.Second {
			break
		}

		if time.Now().After(deadline) {
			t.Fatal("no heartbeat")
		}

		<-time.After(10 * time.Millisecond)
	}

	en.finish(t, cancel, done)
}

func TestHealthNoop(t *testing.T) {
	t.Setenv(HealthFDEnv, "")

	h, err := OpenHealth()
	if err != nil {
		t.Fatal(err)
	}

	if h.Ready() != nil || h.Alive() != nil || h.Promote() != nil ||
		h.Fail("x", KindRelease) != nil {
		t.Fatal("noop health errored")
	}

	t.Setenv(HealthFDEnv, "abc")

	_, err = OpenHealth()
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestSelfTest(t *testing.T) {
	start := time.Now()

	err := SelfTest(t.Context(), os.Args[0])
	if err != nil {
		t.Fatal(err)
	}

	if d := time.Since(start); d > 10*time.Second {
		t.Fatalf("self test took %s", d)
	}
}
