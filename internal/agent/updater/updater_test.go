package updater

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"aead.dev/minisign"

	"github.com/zekihan/t3-mesh/internal/launcher"
	"github.com/zekihan/t3-mesh/internal/proto"
	"github.com/zekihan/t3-mesh/internal/release"
)

type fakeHealth struct {
	mu   sync.Mutex
	msgs []string
}

func (f *fakeHealth) rec(s string) error {
	f.mu.Lock()
	f.msgs = append(f.msgs, s)
	f.mu.Unlock()
	return nil
}
func (f *fakeHealth) Ready() error   { return f.rec("ready") }
func (f *fakeHealth) Alive() error   { return f.rec("alive") }
func (f *fakeHealth) Promote() error { return f.rec("promote") }
func (f *fakeHealth) Restart() error { return f.rec("restart") }
func (f *fakeHealth) Fail(reason, kind string) error {
	return f.rec("fail:" + kind + ":" + reason)
}

func (f *fakeHealth) get() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.msgs...)
}

func (f *fakeHealth) has(prefix string) bool {
	for _, m := range f.get() {
		if strings.HasPrefix(m, prefix) {
			return true
		}
	}
	return false
}

var _ HealthSink = (*launcher.Health)(nil)

type env struct {
	dir    string
	layout launcher.Layout
	health *fakeHealth
	srv    *httptest.Server
	dl     *release.Downloader
	bins   map[string][]byte
	broken bool
}

func newEnv(t *testing.T) *env {
	t.Helper()
	pub, priv, err := minisign.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	e := &env{dir: t.TempDir(), health: &fakeHealth{}, bins: map[string][]byte{}}
	e.layout = launcher.Layout{Dir: filepath.Join(e.dir, "install")}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if e.broken {
			http.Error(w, "boom", 500)
			return
		}
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(parts) != 2 {
			http.NotFound(w, r)
			return
		}
		v, name := parts[0], parts[1]
		bin := []byte("binary " + v)
		sum := sha256.Sum256(bin)
		mj, _ := json.Marshal(
			release.Manifest{Version: v, MinStateVersion: "v1.0.0", Assets: []release.Asset{
				{
					Platform: "linux-amd64",
					Name:     "agent-linux-amd64",
					SHA256:   hex.EncodeToString(sum[:]),
				},
			}},
		)
		switch name {
		case release.ManifestAsset:
			w.Write(mj)
		case release.SignatureAsset:
			w.Write(minisign.Sign(priv, mj))
		case "agent-linux-amd64":
			w.Write(bin)
		default:
			http.NotFound(w, r)
		}
	})
	e.srv = httptest.NewServer(mux)
	t.Cleanup(e.srv.Close)
	e.dl = &release.Downloader{
		BaseURL: e.srv.URL,
		Client:  e.srv.Client(),
		Keys:    []minisign.PublicKey{pub},
	}
	return e
}

func (e *env) stage(t *testing.T, v string) {
	t.Helper()
	p := filepath.Join(e.dir, "bin-"+v)
	if err := os.WriteFile(p, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := e.layout.Stage(v, p); err != nil {
		t.Fatal(err)
	}
}

func (e *env) probationLayout(t *testing.T, kg, cur string) {
	t.Helper()
	e.stage(t, kg)
	e.stage(t, cur)
	if err := e.layout.SetCurrent(kg); err != nil {
		t.Fatal(err)
	}
	if err := e.layout.Promote(); err != nil {
		t.Fatal(err)
	}
	if err := e.layout.SetCurrent(cur); err != nil {
		t.Fatal(err)
	}
}

func (e *env) opts(version string) Options {
	return Options{
		Version: version, Platform: "linux-amd64", StateDir: filepath.Join(e.dir, "state"),
		Layout: e.layout, Health: e.health, Downloader: e.dl, Binary: "/bin/true",
		Hooks: Hooks{
			LastHelloAck:   func() time.Time { return time.Time{} },
			HubHandshakeOK: func(context.Context) bool { return true },
			NetworkUp:      func() bool { return true },
		},
		Log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		SelfTest: func(context.Context, string) error { return nil },
	}
}

func listener(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	return ln.Addr().String()
}

func closedAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	a := ln.Addr().String()
	ln.Close()
	return a
}

// drive steps probation with fake 1 s ticks until it concludes or n steps pass.
func drive(
	t *testing.T,
	u *Updater,
	start time.Time,
	n int,
	between func(i int, now time.Time),
) time.Time {
	t.Helper()
	p := &probation{u: u, last: start}
	now := start
	for i := 0; i < n; i++ {
		now = now.Add(time.Second)
		if between != nil {
			between(i, now)
		}
		if p.step(context.Background(), now) {
			break
		}
	}
	return now
}

func TestProbationSuccess(t *testing.T) {
	e := newEnv(t)
	e.probationLayout(t, "v1.0.0", "v1.1.0")
	o := e.opts("v1.1.0")
	o.Hooks.ServeTargets = []string{listener(t)}
	u, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	if !u.OnProbation() {
		t.Fatal("want probation")
	}
	u.HelloAckReceived()
	drive(t, u, time.Unix(1000, 0), 30, nil)
	if got := e.health.get(); len(got) != 1 || got[0] != "promote" {
		t.Fatalf("msgs=%v", got)
	}
	if u.OnProbation() {
		t.Error("still on probation")
	}
}

func TestNotOnProbation(t *testing.T) {
	e := newEnv(t)
	e.stage(t, "v1.0.0")
	e.layout.SetCurrent("v1.0.0")
	e.layout.Promote()
	u, err := New(e.opts("v1.0.0"))
	if err != nil || u.OnProbation() {
		t.Fatalf("err=%v probation=%v", err, u.OnProbation())
	}
}

func TestProbationTimeoutNoHelloAck(t *testing.T) {
	e := newEnv(t)
	e.probationLayout(t, "v1.0.0", "v1.1.0")
	o := e.opts("v1.1.0")
	u, _ := New(o)
	drive(t, u, time.Unix(1000, 0), 200, nil)
	got := e.health.get()
	if len(got) != 1 || !strings.HasPrefix(got[0], "fail:dependency:no HelloAck") {
		t.Fatalf("msgs=%v", got)
	}
}

func TestProbationServeRefused(t *testing.T) {
	e := newEnv(t)
	e.probationLayout(t, "v1.0.0", "v1.1.0")
	o := e.opts("v1.1.0")
	o.Hooks.ServeTargets = []string{closedAddr(t)}
	u, _ := New(o)
	u.HelloAckReceived()
	drive(t, u, time.Unix(1000, 0), 200, nil)
	if !e.health.has("fail:dependency:serve target") {
		t.Fatalf("msgs=%v", e.health.get())
	}
}

func TestProbationManifestFailure(t *testing.T) {
	e := newEnv(t)
	e.probationLayout(t, "v1.0.0", "v1.1.0")
	e.broken = true
	u, _ := New(e.opts("v1.1.0"))
	u.HelloAckReceived()
	drive(t, u, time.Unix(1000, 0), 200, nil)
	if !e.health.has("fail:release:manifest re-fetch failed") {
		t.Fatalf("msgs=%v", e.health.get())
	}
}

func TestProbationSelfTestFailure(t *testing.T) {
	e := newEnv(t)
	e.probationLayout(t, "v1.0.0", "v1.1.0")
	o := e.opts("v1.1.0")
	o.SelfTest = func(context.Context, string) error { return errors.New("nope") }
	u, _ := New(o)
	u.HelloAckReceived()
	drive(t, u, time.Unix(1000, 0), 200, nil)
	if !e.health.has("fail:release:launcher self-test failed") {
		t.Fatalf("msgs=%v", e.health.get())
	}
}

func TestProbationEligibleTimeNotCounted(t *testing.T) {
	e := newEnv(t)
	e.probationLayout(t, "v1.0.0", "v1.1.0")
	o := e.opts("v1.1.0")
	hubUp := false
	o.Hooks.HubHandshakeOK = func(context.Context) bool { return hubUp }
	u, _ := New(o)
	// Hub down for 300 s: no failure.
	start := time.Unix(1000, 0)
	now := drive(t, u, start, 300, nil)
	if len(e.health.get()) != 0 {
		t.Fatalf("failed while hub down: %v", e.health.get())
	}
	// Hub up, no HelloAck: fails only after ~120 eligible seconds.
	hubUp = true
	p := &probation{u: u, last: now}
	steps := 0
	for ; steps < 500; steps++ {
		now = now.Add(time.Second)
		if p.step(context.Background(), now) {
			break
		}
	}
	if steps < 118 || steps > 125 {
		t.Fatalf("concluded after %d steps", steps)
	}
	if !e.health.has("fail:dependency") {
		t.Fatalf("msgs=%v", e.health.get())
	}
}

func TestProbationSleepGapIgnored(t *testing.T) {
	e := newEnv(t)
	e.probationLayout(t, "v1.0.0", "v1.1.0")
	u, _ := New(e.opts("v1.1.0"))
	p := &probation{u: u, last: time.Unix(1000, 0)}
	now := time.Unix(1000, 0)
	for i := 0; i < 100; i++ {
		now = now.Add(time.Second)
		p.step(context.Background(), now)
	}
	before := p.eligible
	now = now.Add(8 * time.Hour) // lid closed
	p.step(context.Background(), now)
	if p.eligible != before {
		t.Fatalf("gap counted: %v -> %v", before, p.eligible)
	}
	if len(e.health.get()) != 0 {
		t.Fatalf("failed after sleep: %v", e.health.get())
	}
	now = now.Add(time.Second)
	p.step(context.Background(), now)
	if p.eligible != before+time.Second {
		t.Fatalf("eligible=%v", p.eligible)
	}
}

func TestProbationReject(t *testing.T) {
	e := newEnv(t)
	e.probationLayout(t, "v1.0.0", "v1.1.0")
	u, _ := New(e.opts("v1.1.0"))
	u.OnReject(proto.Reject{Reason: "unsupported version", Version: "v1.0.0"})
	if len(e.health.get()) != 0 {
		t.Fatal("other version rejected")
	}
	u.OnReject(proto.Reject{Reason: "unsupported version", Version: "v1.1.0"})
	got := e.health.get()
	if len(got) != 1 || !strings.HasPrefix(got[0], "fail:release:") {
		t.Fatalf("msgs=%v", got)
	}
	u.OnReject(proto.Reject{Reason: "again", Version: "v1.1.0"})
	if len(e.health.get()) != 1 {
		t.Fatal("duplicate fail")
	}
}

func newRunning(t *testing.T, e *env) {
	t.Helper()
	e.stage(t, "v1.0.0")
	e.layout.SetCurrent("v1.0.0")
	e.layout.Promote()
}

func TestUpdateStagesAndRestarts(t *testing.T) {
	e := newEnv(t)
	newRunning(t, e)
	o := e.opts("v1.0.0")
	o.Hooks.LastHelloAck = func() time.Time { return time.Now() }
	o.Hooks.ServeTargets = []string{listener(t)}
	u, _ := New(o)
	u.OnRelease(proto.Release{Version: "v1.2.0", Revision: "r1"})
	u.check(context.Background())
	if got := e.health.get(); len(got) != 1 || got[0] != "restart" {
		t.Fatalf("msgs=%v", got)
	}
	if cur, _ := e.layout.Current(); cur != "v1.2.0" {
		t.Fatalf("current=%s", cur)
	}
	b, err := os.ReadFile(e.layout.Binary("v1.2.0"))
	if err != nil || string(b) != "binary v1.2.0" {
		t.Fatalf("binary=%q err=%v", b, err)
	}
	// No second install after restart was requested.
	u.check(context.Background())
	if len(e.health.get()) != 1 {
		t.Fatal("installed twice")
	}
}

func TestUpdateDeferredByPreconditions(t *testing.T) {
	e := newEnv(t)
	newRunning(t, e)
	o := e.opts("v1.0.0")
	o.Hooks.LastHelloAck = func() time.Time { return time.Now() }
	o.Hooks.ServeTargets = []string{closedAddr(t)}
	u, _ := New(o)
	u.OnRelease(proto.Release{Version: "v1.2.0"})
	u.check(context.Background())
	if len(e.health.get()) != 0 {
		t.Fatalf("msgs=%v", e.health.get())
	}
	if cur, _ := e.layout.Current(); cur != "v1.0.0" {
		t.Fatalf("current=%s", cur)
	}

	// Stale HelloAck also defers.
	o2 := e.opts("v1.0.0")
	o2.Hooks.LastHelloAck = func() time.Time { return time.Now().Add(-time.Hour) }
	u2, _ := New(o2)
	u2.OnRelease(proto.Release{Version: "v1.2.0"})
	u2.check(context.Background())
	if len(e.health.get()) != 0 {
		t.Fatalf("msgs=%v", e.health.get())
	}
}

func TestUpdateDownloadErrorNotRecorded(t *testing.T) {
	e := newEnv(t)
	newRunning(t, e)
	e.broken = true
	o := e.opts("v1.0.0")
	o.Hooks.LastHelloAck = func() time.Time { return time.Now() }
	u, _ := New(o)
	u.OnRelease(proto.Release{Version: "v1.2.0"})
	u.check(context.Background())
	if len(e.health.get()) != 0 {
		t.Fatalf("msgs=%v", e.health.get())
	}
	if f := u.FailedUpdates(); len(f) != 0 {
		t.Fatalf("failed=%v", f)
	}
}

func TestUpdateSkipsFailedVersion(t *testing.T) {
	e := newEnv(t)
	newRunning(t, e)
	o := e.opts("v1.0.0")
	o.Hooks.LastHelloAck = func() time.Time { return time.Now() }
	if err := release.RecordFailure(
		o.StateDir,
		"v1.2.0",
		"bad",
		release.KindRelease,
		time.Now(),
	); err != nil {
		t.Fatal(err)
	}
	u, _ := New(o)
	u.OnRelease(proto.Release{Version: "v1.2.0"})
	u.check(context.Background())
	if len(e.health.get()) != 0 {
		t.Fatalf("msgs=%v", e.health.get())
	}
	if f := u.FailedUpdates(); len(f) != 1 || !f[0].Final {
		t.Fatalf("failed=%v", f)
	}
}

func TestLauncherOutcomeIngested(t *testing.T) {
	e := newEnv(t)
	newRunning(t, e)
	o := e.opts("v1.0.0")
	os.MkdirAll(o.StateDir, 0o755)
	b, _ := json.Marshal(
		release.LauncherOutcome{
			Version: "v1.1.0",
			Reason:  "crash",
			Kind:    release.KindRelease,
			At:      time.Now(),
		},
	)
	os.WriteFile(filepath.Join(o.StateDir, release.LauncherOutcomeFile), b, 0o600)
	u, _ := New(o)
	if f := u.FailedUpdates(); len(f) != 1 || f[0].Version != "v1.1.0" {
		t.Fatalf("failed=%v", f)
	}
}

func TestLastAppliedAndAlive(t *testing.T) {
	e := newEnv(t)
	newRunning(t, e)
	u, _ := New(e.opts("v1.0.0"))
	u.OnRelease(proto.Release{Version: "v1.0.0", Revision: "abc"})
	if u.LastAppliedRelease() != "abc" {
		t.Fatal("applied")
	}
	u.StartupOK()
	u.Close()
	if !e.health.has("ready") {
		t.Fatalf("msgs=%v", e.health.get())
	}
}

func TestRunProbationWithRealTicker(t *testing.T) {
	e := newEnv(t)
	e.probationLayout(t, "v1.0.0", "v1.1.0")
	u, _ := New(e.opts("v1.1.0"))
	u.HelloAckReceived()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- u.Run(ctx) }()
	deadline := time.After(8 * time.Second)
	for !e.health.has("promote") {
		select {
		case <-deadline:
			t.Fatal("no promote")
		case <-time.After(50 * time.Millisecond):
		}
	}
	cancel()
	<-done
}
