package launcher

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	if len(os.Args) > 2 && os.Args[1] == SelfTestChildArg {
		if err := SelfTestChild(os.Args[2:]); err != nil {
			os.Stderr.WriteString(err.Error() + "\n")
			os.Exit(2)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func newLayout(t *testing.T, versions ...string) Layout {
	t.Helper()
	l := Layout{Dir: filepath.Join(t.TempDir(), "install")}
	for _, v := range versions {
		src := filepath.Join(t.TempDir(), "bin")
		if err := copyFile(os.Args[0], src); err != nil {
			t.Fatal(err)
		}
		if err := l.Stage(v, src); err != nil {
			t.Fatal(err)
		}
	}
	return l
}

func TestLayout(t *testing.T) {
	l := newLayout(t, "1", "2", "3")
	info, err := os.Stat(l.Binary("1"))
	if err != nil || info.Mode().Perm() != 0o755 {
		t.Fatalf("stage: %v %v", err, info)
	}
	if _, err := l.Current(); err == nil {
		t.Fatal("expected error without link")
	}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(l.SetCurrent("1"))
	must(l.Promote())
	kg, _ := l.KnownGood()
	if kg != "1" {
		t.Fatalf("kg=%s", kg)
	}
	must(l.SetCurrent("2"))
	must(l.Promote())
	kg, _ = l.KnownGood()
	pg, _ := l.PreviousGood()
	if kg != "2" || pg != "1" {
		t.Fatalf("kg=%s pg=%s", kg, pg)
	}
	must(l.SetCurrent("3"))
	must(l.Rollback())
	if c, _ := l.Current(); c != "2" {
		t.Fatalf("rollback: %s", c)
	}
	target, _ := os.Readlink(filepath.Join(l.Dir, "current"))
	if target != filepath.Join("versions", "2") {
		t.Fatalf("target %s", target)
	}
	must(l.Prune(0))
	if _, err := os.Stat(l.Binary("3")); err == nil {
		t.Fatal("3 should be pruned")
	}
	if _, err := os.Stat(l.Binary("1")); err != nil {
		t.Fatal("1 is previous-good, must stay")
	}
	must(l.FallbackToPrevious())
	kg, _ = l.KnownGood()
	c, _ := l.Current()
	if kg != "1" || c != "1" {
		t.Fatalf("fallback kg=%s cur=%s", kg, c)
	}
	if err := l.SetCurrent("nope"); err == nil {
		t.Fatal("unstaged version accepted")
	}
	if err := l.Stage("../x", "/dev/null"); err == nil {
		t.Fatal("bad version accepted")
	}
}

func TestFallback(t *testing.T) {
	l := newLayout(t, "1", "2")
	_ = l.SetCurrent("1")
	_ = l.Promote()
	_ = l.SetCurrent("2")
	_ = l.Promote()
	hb := filepath.Join(t.TempDir(), "hb")
	now := time.Now()
	if err := touch(hb); err != nil {
		t.Fatal(err)
	}
	if ok, err := Fallback(l, hb, 5*time.Minute, now); ok || err != nil {
		t.Fatalf("fresh heartbeat: %v %v", ok, err)
	}
	// First stale reading (e.g. right after wake) only records suspicion.
	if ok, err := Fallback(l, hb, 5*time.Minute, now.Add(6*time.Minute)); ok || err != nil {
		t.Fatalf("first stale reading: %v %v", ok, err)
	}
	// A heartbeat after the suspicion clears it.
	if err := touchAt(hb, now.Add(7*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if ok, err := Fallback(l, hb, 5*time.Minute, now.Add(8*time.Minute)); ok || err != nil {
		t.Fatalf("recovered heartbeat: %v %v", ok, err)
	}
	if ok, err := Fallback(l, hb, 5*time.Minute, now.Add(13*time.Minute)); ok || err != nil {
		t.Fatalf("new suspicion: %v %v", ok, err)
	}
	if ok, err := Fallback(l, hb, 5*time.Minute, now.Add(18*time.Minute)); !ok || err != nil {
		t.Fatalf("stale twice: %v %v", ok, err)
	}
	if kg, _ := l.KnownGood(); kg != "1" {
		t.Fatalf("kg=%s", kg)
	}
	if ok, err := Fallback(l, hb, 5*time.Minute, now.Add(time.Hour)); ok || err != nil {
		t.Fatalf("re-suspect after fallback: %v %v", ok, err)
	}
	if ok, err := Fallback(l, hb, 5*time.Minute, now.Add(2*time.Hour)); ok || err != nil {
		t.Fatalf("second fallback: %v %v", ok, err)
	}
}

type env struct {
	l      Layout
	state  string
	cfg    Config
	events chan string
	reexec chan []string
}

func newEnv(t *testing.T, behaviours map[string]string, cur, kg string) *env {
	t.Helper()
	versions := make([]string, 0, len(behaviours))
	for v := range behaviours {
		versions = append(versions, v)
	}
	l := newLayout(t, versions...)
	if err := l.setLink(linkKnownGood, kg); err != nil {
		t.Fatal(err)
	}
	if err := l.SetCurrent(cur); err != nil {
		t.Fatal(err)
	}
	e := &env{
		l:      l,
		state:  t.TempDir(),
		events: make(chan string, 256),
		reexec: make(chan []string, 1),
	}
	e.cfg = Config{
		Layout:            l,
		StateDir:          e.state,
		ArgsFor:           func(v string) []string { return []string{SelfTestChildArg, behaviours[v]} },
		StartupTimeout:    time.Second,
		AliveTimeout:      time.Second,
		StopTimeout:       300 * time.Millisecond,
		HeartbeatInterval: 50 * time.Millisecond,
		MinBackoff:        20 * time.Millisecond,
		MaxBackoff:        100 * time.Millisecond,
		Log:               slog.New(slog.NewTextHandler(io.Discard, nil)),
		Command:           nil,
		ReexecArgs:        []string{"launcher", "--x"},
		Exec: func(p string, argv, _ []string) error {
			e.reexec <- append([]string{p}, argv...)
			return nil
		},
		events: func(ev string) {
			select {
			case e.events <- ev:
			default:
			}
		},
	}
	t.Cleanup(func() {})
	return e
}

func (e *env) start(t *testing.T) (cancel func(), done <-chan error) {
	ctx, c := context.WithCancel(context.Background())
	ch := make(chan error, 1)
	go func() { ch <- Run(ctx, e.cfg) }()
	t.Cleanup(c)
	return c, ch
}

func (e *env) waitEvent(t *testing.T, want string) {
	t.Helper()
	to := time.After(8 * time.Second)
	for {
		select {
		case ev := <-e.events:
			if ev == want {
				return
			}
		case <-to:
			t.Fatalf("timeout waiting for %s", want)
		}
	}
}

func (e *env) outcome(t *testing.T) Outcome {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(e.state, OutcomeFile))
	if err != nil {
		t.Fatal(err)
	}
	var o Outcome
	if err := json.Unmarshal(b, &o); err != nil {
		t.Fatal(err)
	}
	if _, err := time.Parse(time.RFC3339, o.At); err != nil {
		t.Fatal(err)
	}
	return o
}

func (e *env) finish(t *testing.T, cancel func(), done <-chan error) {
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
	cases := []struct {
		name, behaviour, reason, kind string
		tweak                         func(*Config)
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
			e := newEnv(
				t,
				map[string]string{"good": BehaviourOK, "bad": tc.behaviour},
				"bad",
				"good",
			)
			if tc.tweak != nil {
				tc.tweak(&e.cfg)
			}
			cancel, done := e.start(t)
			e.waitEvent(t, "rollback")
			e.waitEvent(t, "ready")
			o := e.outcome(t)
			if o.Version != "bad" || o.Reason != tc.reason || o.Kind != tc.kind {
				t.Fatalf("outcome %+v", o)
			}
			if c, _ := e.l.Current(); c != "good" {
				t.Fatalf("current %s", c)
			}
			e.finish(t, cancel, done)
		})
	}
}

func TestPromoteReexec(t *testing.T) {
	e := newEnv(t, map[string]string{"good": BehaviourOK, "new": BehaviourPromote}, "new", "good")
	_, done := e.start(t)
	select {
	case argv := <-e.reexec:
		want := filepath.Join(e.l.Dir, "known-good", BinaryName)
		if argv[0] != want || argv[1] != want || argv[2] != "launcher" || argv[3] != "--x" {
			t.Fatalf("argv %v", argv)
		}
	case <-time.After(8 * time.Second):
		t.Fatal("no reexec")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	kg, _ := e.l.KnownGood()
	pg, _ := e.l.PreviousGood()
	if kg != "new" || pg != "good" {
		t.Fatalf("kg=%s pg=%s", kg, pg)
	}
}

func TestHandoverToStagedVersion(t *testing.T) {
	e := newEnv(
		t,
		map[string]string{"good": BehaviourHandover, "new": BehaviourPromote},
		"good",
		"good",
	)
	_, done := e.start(t)
	e.waitEvent(t, "ready")
	if err := e.l.SetCurrent("new"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-e.reexec:
	case <-time.After(8 * time.Second):
		t.Fatal("staged version was not started and promoted")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if kg, _ := e.l.KnownGood(); kg != "new" {
		t.Fatalf("known-good = %s", kg)
	}
	if _, err := os.Stat(filepath.Join(e.state, OutcomeFile)); err == nil {
		t.Fatal("handover must not record a failure")
	}
}

func TestKnownGoodCrashRestarts(t *testing.T) {
	e := newEnv(t, map[string]string{"good": BehaviourCrash}, "good", "good")
	cancel, done := e.start(t)
	time.Sleep(400 * time.Millisecond)
	e.finish(t, cancel, done)
	if _, err := os.Stat(filepath.Join(e.state, OutcomeFile)); err == nil {
		t.Fatal("no outcome expected for known-good")
	}
	if c, _ := e.l.Current(); c != "good" {
		t.Fatal(c)
	}
}

func TestHeartbeatAndShutdown(t *testing.T) {
	e := newEnv(t, map[string]string{"good": BehaviourOK}, "good", "good")
	cancel, done := e.start(t)
	e.waitEvent(t, "ready")
	hb := filepath.Join(e.state, HeartbeatFile)
	deadline := time.Now().Add(5 * time.Second)
	for {
		if info, err := os.Stat(hb); err == nil && time.Since(info.ModTime()) < time.Second {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no heartbeat")
		}
		time.Sleep(10 * time.Millisecond)
	}
	e.finish(t, cancel, done)
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
	if _, err := OpenHealth(); err == nil {
		t.Fatal("expected error")
	}
}

func TestSelfTest(t *testing.T) {
	start := time.Now()
	if err := SelfTest(context.Background(), os.Args[0]); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Fatalf("self test took %s", d)
	}
}
