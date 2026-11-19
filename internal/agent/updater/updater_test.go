package updater

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
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

var errSelfTestFailed = errors.New("nope")

const execMode = 0o755

type fakeHealth struct {
	msgs []string
	mu   sync.Mutex
}

func (f *fakeHealth) Ready() error   { return f.rec("ready") }
func (f *fakeHealth) Alive() error   { return f.rec("alive") }
func (f *fakeHealth) Promote() error { return f.rec("promote") }
func (f *fakeHealth) Restart() error { return f.rec("restart") }
func (f *fakeHealth) Fail(reason, kind string) error {
	return f.rec("fail:" + kind + ":" + reason)
}

func (f *fakeHealth) rec(s string) error {
	f.mu.Lock()
	f.msgs = append(f.msgs, s)
	f.mu.Unlock()

	return nil
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

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

var _ HealthSink = (*launcher.Health)(nil)

type env struct {
	health *fakeHealth
	srv    *httptest.Server
	dl     *release.Downloader
	bins   map[string][]byte
	dir    string
	layout launcher.Layout
	broken bool
}

func newEnv(t *testing.T) *env {
	t.Helper()

	pub, priv, err := minisign.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	testEnv := &env{dir: t.TempDir(), health: &fakeHealth{}, bins: map[string][]byte{}}
	testEnv.layout = launcher.Layout{Dir: filepath.Join(testEnv.dir, "install")}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if testEnv.broken {
			http.Error(w, "boom", http.StatusInternalServerError)

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
			_, _ = w.Write(mj)
		case release.SignatureAsset:
			_, _ = w.Write(minisign.Sign(priv, mj))
		case "agent-linux-amd64":
			_, _ = w.Write(bin) //nolint:gosec // test server
		default:
			http.NotFound(w, r)
		}
	})
	testEnv.srv = httptest.NewServer(mux)
	t.Cleanup(testEnv.srv.Close)
	testEnv.dl = &release.Downloader{
		BaseURL: testEnv.srv.URL,
		Client:  testEnv.srv.Client(),
		Keys:    []minisign.PublicKey{pub},
	}

	return testEnv
}

func (testEnv *env) stage(t *testing.T, version string) {
	t.Helper()

	path := filepath.Join(testEnv.dir, "bin-"+version)

	err := os.WriteFile(path, []byte("x"), execMode)
	if err != nil {
		t.Fatal(err)
	}

	err = testEnv.layout.Stage(version, path)
	if err != nil {
		t.Fatal(err)
	}
}

func (testEnv *env) probationLayout(t *testing.T, kg, cur string) {
	t.Helper()
	testEnv.stage(t, kg)
	testEnv.stage(t, cur)

	err := testEnv.layout.SetCurrent(kg)
	if err != nil {
		t.Fatal(err)
	}

	err = testEnv.layout.Promote()
	if err != nil {
		t.Fatal(err)
	}

	err = testEnv.layout.SetCurrent(cur)
	if err != nil {
		t.Fatal(err)
	}
}

func (testEnv *env) opts(version string) Options {
	return Options{
		Version: version, Platform: "linux-amd64", StateDir: filepath.Join(testEnv.dir, "state"),
		Layout: testEnv.layout, Health: testEnv.health, Downloader: testEnv.dl, Binary: "/bin/true",
		Hooks: Hooks{
			LastHelloAck:   func() time.Time { return time.Time{} },
			HubHandshakeOK: func(context.Context) bool { return true },
			NetworkUp:      func() bool { return true },
		},
		Log:      slog.New(slog.DiscardHandler),
		SelfTest: func(context.Context, string) error { return nil },
	}
}

func listener(t *testing.T) string {
	t.Helper()

	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}

			_ = c.Close()
		}
	}()

	return ln.Addr().String()
}

func closedAddr(t *testing.T) string {
	t.Helper()

	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	a := ln.Addr().String()
	_ = ln.Close()

	return a
}

// drive steps probation with fake 1 s ticks until it concludes or n steps pass.
func drive(
	t *testing.T,
	updater *Updater,
	start time.Time,
	count int,
	between func(i int, now time.Time),
) time.Time {
	t.Helper()

	prob := &probation{u: updater, last: start}

	now := start
	for i := range count {
		now = now.Add(time.Second)
		if between != nil {
			between(i, now)
		}

		if prob.step(t.Context(), now) {
			break
		}
	}

	return now
}

func TestProbationSuccess(t *testing.T) {
	testEnv := newEnv(t)
	testEnv.probationLayout(t, "v1.0.0", "v1.1.0")
	o := testEnv.opts("v1.1.0")
	o.Hooks.ServeTargets = []string{listener(t)}

	updater, err := New(o)
	if err != nil {
		t.Fatal(err)
	}

	if !updater.OnProbation() {
		t.Fatal("want probation")
	}

	updater.HelloAckReceived()
	drive(t, updater, time.Unix(1000, 0), 30, nil)

	if got := testEnv.health.get(); len(got) != 1 || got[0] != "promote" {
		t.Fatalf("msgs=%v", got)
	}

	if updater.OnProbation() {
		t.Error("still on probation")
	}
}

func TestNotOnProbation(t *testing.T) {
	e := newEnv(t)
	e.stage(t, "v1.0.0")
	_ = e.layout.SetCurrent("v1.0.0")
	_ = e.layout.Promote()

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
	testEnv := newEnv(t)
	testEnv.probationLayout(t, "v1.0.0", "v1.1.0")
	o := testEnv.opts("v1.1.0")
	o.Hooks.ServeTargets = []string{closedAddr(t)}
	u, _ := New(o)
	u.HelloAckReceived()
	drive(t, u, time.Unix(1000, 0), 200, nil)

	if !testEnv.health.has("fail:dependency:serve target") {
		t.Fatalf("msgs=%v", testEnv.health.get())
	}
}

func TestProbationManifestFailure(t *testing.T) {
	testEnv := newEnv(t)
	testEnv.probationLayout(t, "v1.0.0", "v1.1.0")
	testEnv.broken = true
	u, _ := New(testEnv.opts("v1.1.0"))
	u.HelloAckReceived()
	drive(t, u, time.Unix(1000, 0), 200, nil)

	if !testEnv.health.has("fail:release:manifest re-fetch failed") {
		t.Fatalf("msgs=%v", testEnv.health.get())
	}
}

func TestProbationSelfTestFailure(t *testing.T) {
	testEnv := newEnv(t)
	testEnv.probationLayout(t, "v1.0.0", "v1.1.0")
	o := testEnv.opts("v1.1.0")
	o.SelfTest = func(context.Context, string) error { return errSelfTestFailed }
	u, _ := New(o)
	u.HelloAckReceived()
	drive(t, u, time.Unix(1000, 0), 200, nil)

	if !testEnv.health.has("fail:release:launcher self-test failed") {
		t.Fatalf("msgs=%v", testEnv.health.get())
	}
}

func TestProbationEligibleTimeNotCounted(t *testing.T) {
	testEnv := newEnv(t)
	testEnv.probationLayout(t, "v1.0.0", "v1.1.0")
	o := testEnv.opts("v1.1.0")
	hubUp := false
	o.Hooks.HubHandshakeOK = func(context.Context) bool { return hubUp }
	updater, _ := New(o)
	// Hub down for 300 s: no failure.
	start := time.Unix(1000, 0)

	now := drive(t, updater, start, 300, nil)
	if len(testEnv.health.get()) != 0 {
		t.Fatalf("failed while hub down: %v", testEnv.health.get())
	}
	// Hub up, no HelloAck: fails only after ~120 eligible seconds.
	hubUp = true
	p := &probation{u: updater, last: now}

	steps := 0
	for ; steps < 500; steps++ {
		now = now.Add(time.Second)
		if p.step(t.Context(), now) {
			break
		}
	}

	if steps < 118 || steps > 125 {
		t.Fatalf("concluded after %d steps", steps)
	}

	if !testEnv.health.has("fail:dependency") {
		t.Fatalf("msgs=%v", testEnv.health.get())
	}
}

func TestProbationSleepGapIgnored(t *testing.T) {
	testEnv := newEnv(t)
	testEnv.probationLayout(t, "v1.0.0", "v1.1.0")
	u, _ := New(testEnv.opts("v1.1.0"))
	prob := &probation{u: u, last: time.Unix(1000, 0)}

	now := time.Unix(1000, 0)
	for range 100 {
		now = now.Add(time.Second)
		prob.step(t.Context(), now)
	}

	before := prob.eligible
	now = now.Add(8 * time.Hour) // lid closed
	prob.step(t.Context(), now)

	if prob.eligible != before {
		t.Fatalf("gap counted: %v -> %v", before, prob.eligible)
	}

	if len(testEnv.health.get()) != 0 {
		t.Fatalf("failed after sleep: %v", testEnv.health.get())
	}

	now = now.Add(time.Second)
	prob.step(t.Context(), now)

	if prob.eligible != before+time.Second {
		t.Fatalf("eligible=%v", prob.eligible)
	}
}

func TestProbationReject(t *testing.T) {
	testEnv := newEnv(t)
	testEnv.probationLayout(t, "v1.0.0", "v1.1.0")
	updater, _ := New(testEnv.opts("v1.1.0"))
	updater.OnReject(proto.Reject{Reason: "unsupported version", Version: "v1.0.0"})

	if len(testEnv.health.get()) != 0 {
		t.Fatal("other version rejected")
	}

	updater.OnReject(proto.Reject{Reason: "unsupported version", Version: "v1.1.0"})

	got := testEnv.health.get()
	if len(got) != 1 || !strings.HasPrefix(got[0], "fail:release:") {
		t.Fatalf("msgs=%v", got)
	}

	updater.OnReject(proto.Reject{Reason: "again", Version: "v1.1.0"})

	if len(testEnv.health.get()) != 1 {
		t.Fatal("duplicate fail")
	}
}

func newRunning(t *testing.T, e *env) {
	t.Helper()
	e.stage(t, "v1.0.0")
	_ = e.layout.SetCurrent("v1.0.0")
	_ = e.layout.Promote()
}

func TestUpdateStagesAndRestarts(t *testing.T) {
	testEnv := newEnv(t)
	newRunning(t, testEnv)
	o := testEnv.opts("v1.0.0")
	o.Hooks.LastHelloAck = time.Now
	o.Hooks.ServeTargets = []string{listener(t)}
	updater, _ := New(o)
	updater.OnRelease(proto.Release{Version: "v1.2.0", Revision: "r1"})
	updater.check(t.Context())

	if got := testEnv.health.get(); len(got) != 1 || got[0] != "restart" {
		t.Fatalf("msgs=%v", got)
	}

	if cur, _ := testEnv.layout.Current(); cur != "v1.2.0" {
		t.Fatalf("current=%s", cur)
	}

	b, err := os.ReadFile(testEnv.layout.Binary("v1.2.0"))
	if err != nil || string(b) != "binary v1.2.0" {
		t.Fatalf("binary=%q err=%v", b, err)
	}
	// No second install after restart was requested.
	updater.check(t.Context())

	if len(testEnv.health.get()) != 1 {
		t.Fatal("installed twice")
	}
}

func TestUpdateSkipsSupersededDownload(t *testing.T) {
	testEnv := newEnv(t)
	newRunning(t, testEnv)
	opts := testEnv.opts("v1.0.0")
	opts.Hooks.LastHelloAck = time.Now

	updater, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}

	transport := testEnv.dl.Client.Transport
	testEnv.dl.Client.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		resp, transportErr := transport.RoundTrip(req)
		if transportErr != nil {
			return nil, fmt.Errorf("release fixture: %w", transportErr)
		}

		if req.URL.Path == "/v1.2.0/agent-linux-amd64" {
			updater.OnRelease(proto.Release{Version: "v1.1.0", Revision: "r2"})
		}

		return resp, nil
	})

	updater.OnRelease(proto.Release{Version: "v1.2.0", Revision: "r1"})
	updater.check(t.Context())

	cur, err := testEnv.layout.Current()
	if err != nil || cur != "v1.0.0" {
		t.Fatalf("current after superseded download = %q, %v, want v1.0.0", cur, err)
	}

	if got := testEnv.health.get(); len(got) != 0 {
		t.Fatalf("health messages after superseded download = %v, want none", got)
	}

	staging := filepath.Join(testEnv.layout.Dir, ".staging-v1.2.0")

	_, err = os.Stat(staging)
	if !os.IsNotExist(err) {
		t.Fatalf("staging file after superseded download: %v, want not exist", err)
	}

	updater.check(t.Context())

	cur, err = testEnv.layout.Current()
	if err != nil || cur != "v1.1.0" {
		t.Fatalf("current after checking latest release = %q, %v, want v1.1.0", cur, err)
	}

	if got := testEnv.health.get(); len(got) != 1 || got[0] != "restart" {
		t.Fatalf("health messages after checking latest release = %v, want a restart", got)
	}
}

func TestUpdateDeferredByPreconditions(t *testing.T) {
	testEnv := newEnv(t)
	newRunning(t, testEnv)
	o := testEnv.opts("v1.0.0")
	o.Hooks.LastHelloAck = time.Now
	o.Hooks.ServeTargets = []string{closedAddr(t)}
	u, _ := New(o)
	u.OnRelease(proto.Release{Version: "v1.2.0"})
	u.check(t.Context())

	if len(testEnv.health.get()) != 0 {
		t.Fatalf("msgs=%v", testEnv.health.get())
	}

	if cur, _ := testEnv.layout.Current(); cur != "v1.0.0" {
		t.Fatalf("current=%s", cur)
	}

	// Stale HelloAck also defers.
	o2 := testEnv.opts("v1.0.0")
	o2.Hooks.LastHelloAck = func() time.Time { return time.Now().Add(-time.Hour) }
	u2, _ := New(o2)
	u2.OnRelease(proto.Release{Version: "v1.2.0"})
	u2.check(t.Context())

	if len(testEnv.health.get()) != 0 {
		t.Fatalf("msgs=%v", testEnv.health.get())
	}
}

func TestUpdateDownloadErrorNotRecorded(t *testing.T) {
	testEnv := newEnv(t)
	newRunning(t, testEnv)
	testEnv.broken = true
	o := testEnv.opts("v1.0.0")
	o.Hooks.LastHelloAck = time.Now
	updater, _ := New(o)
	updater.OnRelease(proto.Release{Version: "v1.2.0"})
	updater.check(t.Context())

	if len(testEnv.health.get()) != 0 {
		t.Fatalf("msgs=%v", testEnv.health.get())
	}

	if f := updater.FailedUpdates(); len(f) != 0 {
		t.Fatalf("failed=%v", f)
	}
}

func TestUpdateSkipsFailedVersion(t *testing.T) {
	testEnv := newEnv(t)
	newRunning(t, testEnv)
	opts := testEnv.opts("v1.0.0")

	opts.Hooks.LastHelloAck = time.Now

	err := release.RecordFailure(
		opts.StateDir,
		"v1.2.0",
		"bad",
		release.KindRelease,
		time.Now(),
	)
	if err != nil {
		t.Fatal(err)
	}

	updater, _ := New(opts)
	updater.OnRelease(proto.Release{Version: "v1.2.0"})
	updater.check(t.Context())

	if len(testEnv.health.get()) != 0 {
		t.Fatalf("msgs=%v", testEnv.health.get())
	}

	if f := updater.FailedUpdates(); len(f) != 1 || !f[0].Final {
		t.Fatalf("failed=%v", f)
	}
}

func TestLauncherOutcomeIngested(t *testing.T) {
	e := newEnv(t)
	newRunning(t, e)
	opts := e.opts("v1.0.0")
	_ = os.MkdirAll(opts.StateDir, 0o750)

	outcomeJSON, err := json.Marshal(release.LauncherOutcome{
		Version: "v1.1.0",
		Reason:  "crash",
		Kind:    release.KindRelease,
		At:      time.Now(),
	})
	if err != nil {
		t.Fatal(err)
	}

	_ = os.WriteFile(filepath.Join(opts.StateDir, release.LauncherOutcomeFile), outcomeJSON, 0o600)

	u, _ := New(opts)
	if f := u.FailedUpdates(); len(f) != 1 || f[0].Version != "v1.1.0" {
		t.Fatalf("failed=%v", f)
	}
}

func TestLastAppliedAndAlive(t *testing.T) {
	testEnv := newEnv(t)
	newRunning(t, testEnv)
	updater, _ := New(testEnv.opts("v1.0.0"))
	updater.OnRelease(proto.Release{Version: "v1.0.0", Revision: "abc"})

	if updater.LastAppliedRelease() != "abc" {
		t.Fatal("applied")
	}

	updater.StartupOK()
	updater.Close()

	if !testEnv.health.has("ready") {
		t.Fatalf("msgs=%v", testEnv.health.get())
	}
}

func TestRunProbationWithRealTicker(t *testing.T) {
	testEnv := newEnv(t)
	testEnv.probationLayout(t, "v1.0.0", "v1.1.0")
	updater, _ := New(testEnv.opts("v1.1.0"))
	updater.HelloAckReceived()

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- updater.Run(ctx) }()

	deadline := time.After(8 * time.Second)

	for !testEnv.health.has("promote") {
		select {
		case <-deadline:
			t.Fatal("no promote")
		case <-time.After(50 * time.Millisecond):
		}
	}

	cancel()
	<-done
}
