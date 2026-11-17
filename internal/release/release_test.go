package release

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"aead.dev/minisign"

	"github.com/zekihan/t3-mesh/internal/proto"
)

func mustV(t *testing.T, s string) Version {
	t.Helper()
	v, err := ParseVersion(s)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestVersion(t *testing.T) {
	for _, bad := range []string{"", "1.2.3", "v1.2", "v1.2.3.4", "v1.a.3", "v01.2.3", "v1.2.3-", "v1.2.3-a..b", "v1.2.3-a_b", "v-1.2.3", "v1.2.3/../x"} {
		if _, err := ParseVersion(bad); err == nil {
			t.Errorf("ParseVersion(%q) succeeded", bad)
		}
	}
	order := []string{
		"v0.9.9",
		"v1.0.0-alpha",
		"v1.0.0-alpha.1",
		"v1.0.0-alpha.beta",
		"v1.0.0-beta",
		"v1.0.0-beta.2",
		"v1.0.0-beta.11",
		"v1.0.0-rc.1",
		"v1.0.0",
		"v1.0.1",
		"v1.2.0",
		"v2.0.0",
		"v10.0.0",
	}
	for i, a := range order {
		if mustV(t, a).String() != a {
			t.Errorf("round trip %s", a)
		}
		for j, b := range order {
			want := 0
			if i < j {
				want = -1
			} else if i > j {
				want = 1
			}
			if got := mustV(t, a).Compare(mustV(t, b)); got != want {
				t.Errorf("Compare(%s,%s)=%d want %d", a, b, got, want)
			}
		}
	}
	if c, err := Compare("v1.0.0", "v1.0.1"); err != nil || c != -1 {
		t.Errorf("Compare strings: %d %v", c, err)
	}
	if _, err := Compare("x", "v1.0.0"); err == nil {
		t.Error("want error")
	}
}

type testKey struct {
	pub  minisign.PublicKey
	priv minisign.PrivateKey
}

func newKey(t *testing.T) testKey {
	t.Helper()
	pub, priv, err := minisign.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return testKey{pub, priv}
}

func manifestJSON(t *testing.T, version string, bin []byte) []byte {
	t.Helper()
	sum := sha256.Sum256(bin)
	b, err := json.Marshal(Manifest{
		Version:         version,
		MinStateVersion: "v1.0.0",
		Assets: []Asset{
			{
				Platform: PlatformLinuxAMD64,
				Name:     "t3-mesh-agent-linux-amd64",
				SHA256:   hex.EncodeToString(sum[:]),
			},
			{
				Platform: PlatformDarwinARM64,
				Name:     "t3-mesh-agent-darwin-arm64",
				SHA256:   hex.EncodeToString(sum[:]),
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestVerifyManifest(t *testing.T) {
	k1, k2, other := newKey(t), newKey(t), newKey(t)
	data := manifestJSON(t, "v1.2.3", []byte("x"))
	s1 := minisign.Sign(k1.priv, data)
	s2 := minisign.Sign(k2.priv, data)
	so := minisign.Sign(other.priv, data)
	both := append(append([]byte{}, s1...), s2...)
	keys := []minisign.PublicKey{k1.pub, k2.pub}

	if m, err := VerifyManifest(data, s1, keys); err != nil || m.Version != "v1.2.3" {
		t.Fatalf("single: %v", err)
	}
	if _, err := VerifyManifest(data, both, keys); err != nil {
		t.Fatalf("both: %v", err)
	}
	// Rotation: old agent trusts only k1, release carries both.
	if _, err := VerifyManifest(data, both, []minisign.PublicKey{k1.pub}); err != nil {
		t.Fatalf("old agent: %v", err)
	}
	// New agent trusts only k2, signature order reversed with CRLF.
	rev := strings.ReplaceAll(string(s2)+string(s1), "\n", "\r\n")
	if _, err := VerifyManifest(data, []byte(rev), []minisign.PublicKey{k2.pub}); err != nil {
		t.Fatalf("crlf: %v", err)
	}
	// Unknown signer first, trusted second.
	if _, err := VerifyManifest(data, append(append([]byte{}, so...), s2...), keys); err != nil {
		t.Fatalf("mixed: %v", err)
	}
	if _, err := VerifyManifest(data, so, keys); err == nil {
		t.Error("untrusted signer accepted")
	}
	if _, err := VerifyManifest(append(data[:len(data):len(data)], ' '), both, keys); err == nil {
		t.Error("tampered data accepted")
	}
	if _, err := VerifyManifest(data, nil, keys); err == nil {
		t.Error("empty sig accepted")
	}
	if _, err := VerifyManifest(data, []byte("garbage\nmore\n"), keys); err == nil {
		t.Error("garbage sig accepted")
	}
	if _, err := VerifyManifest(data, s1, nil); err == nil {
		t.Error("no keys accepted")
	}
}

func TestVerifyManifestInvalidContent(t *testing.T) {
	k := newKey(t)
	keys := []minisign.PublicKey{k.pub}
	good := "a3b3a3b3a3b3a3b3a3b3a3b3a3b3a3b3a3b3a3b3a3b3a3b3a3b3a3b3a3b3a3b3"
	cases := map[string]string{
		"badversion":   `{"version":"1.2.3","minStateVersion":"v1.0.0","assets":[]}`,
		"badmin":       `{"version":"v1.2.3","minStateVersion":"","assets":[]}`,
		"platform":     `{"version":"v1.2.3","minStateVersion":"v1.0.0","assets":[{"platform":"windows","name":"a","sha256":"` + good + `"}]}`,
		"dup":          `{"version":"v1.2.3","minStateVersion":"v1.0.0","assets":[{"platform":"linux-amd64","name":"a","sha256":"` + good + `"},{"platform":"linux-amd64","name":"b","sha256":"` + good + `"}]}`,
		"name":         `{"version":"v1.2.3","minStateVersion":"v1.0.0","assets":[{"platform":"linux-amd64","name":"../a","sha256":"` + good + `"}]}`,
		"sha":          `{"version":"v1.2.3","minStateVersion":"v1.0.0","assets":[{"platform":"linux-amd64","name":"a","sha256":"zz"}]}`,
		"unknownfield": `{"version":"v1.2.3","minStateVersion":"v1.0.0","assets":[],"url":"http://evil"}`,
		"notjson":      `nope`,
	}
	for name, c := range cases {
		if _, err := VerifyManifest([]byte(c), minisign.Sign(k.priv, []byte(c)), keys); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

type fakeRelease struct {
	manifest, sig, bin []byte
	hits               []string
}

func (f *fakeRelease) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.hits = append(f.hits, r.URL.Path)
	switch r.URL.Path {
	case "/dl/v1.2.3/manifest.json":
		w.Write(f.manifest)
	case "/dl/v1.2.3/manifest.json.minisig":
		w.Write(f.sig)
	case "/dl/v1.2.3/t3-mesh-agent-linux-amd64":
		w.Write(f.bin)
	default:
		http.NotFound(w, r)
	}
}

func setup(t *testing.T) (*Downloader, *fakeRelease, testKey) {
	t.Helper()
	k := newKey(t)
	bin := []byte("#!/bin/sh\necho hi\n")
	mj := manifestJSON(t, "v1.2.3", bin)
	f := &fakeRelease{manifest: mj, sig: minisign.Sign(k.priv, mj), bin: bin}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return &Downloader{
		BaseURL: srv.URL + "/dl",
		Client:  srv.Client(),
		Keys:    []minisign.PublicKey{k.pub},
	}, f, k
}

func TestFetchAndDownload(t *testing.T) {
	d, f, _ := setup(t)
	ctx := context.Background()
	m, err := d.Fetch(ctx, "v1.2.3")
	if err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(t.TempDir(), "versions", "v1.2.3", "t3-mesh-agent")
	if err := d.Download(ctx, m, PlatformLinuxAMD64, dest); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(dest)
	if string(got) != string(f.bin) {
		t.Error("content mismatch")
	}
	if fi, _ := os.Stat(dest); fi.Mode().Perm() != 0o755 {
		t.Errorf("mode %v", fi.Mode())
	}
	entries, _ := os.ReadDir(filepath.Dir(dest))
	if len(entries) != 1 {
		t.Errorf("leftover temp files: %v", entries)
	}
	if err := d.Download(ctx, m, "linux-arm64", dest); err == nil {
		t.Error("unknown platform accepted")
	}
}

func TestFetchRejects(t *testing.T) {
	ctx := context.Background()
	d, f, _ := setup(t)
	if _, err := d.Fetch(ctx, "v9.9.9"); err == nil {
		t.Error("404 accepted")
	}
	if _, err := d.Fetch(ctx, "v1.2.3/../../x"); err == nil {
		t.Error("bad version accepted")
	}
	f.hits = nil
	_, _ = d.Fetch(ctx, "../evil")
	if len(f.hits) != 0 {
		t.Error("request made for invalid version")
	}
	// Wrong signer.
	d2 := *d
	d2.Keys = []minisign.PublicKey{newKey(t).pub}
	if _, err := d2.Fetch(ctx, "v1.2.3"); err == nil {
		t.Error("wrong key accepted")
	}
	// Manifest for another version served under this version's URL (replay).
	k := newKey(t)
	mj := manifestJSON(t, "v1.0.0", f.bin)
	f.manifest, f.sig = mj, minisign.Sign(k.priv, mj)
	d.Keys = []minisign.PublicKey{k.pub}
	if _, err := d.Fetch(
		ctx,
		"v1.2.3",
	); err == nil ||
		!strings.Contains(err.Error(), "manifest is for") {
		t.Errorf("replay accepted: %v", err)
	}
}

func TestDownloadRejects(t *testing.T) {
	ctx := context.Background()
	d, f, _ := setup(t)
	m, err := d.Fetch(ctx, "v1.2.3")
	if err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(t.TempDir(), "bin")
	f.bin = []byte("tampered")
	if err := d.Download(
		ctx,
		m,
		PlatformLinuxAMD64,
		dest,
	); err == nil ||
		!strings.Contains(err.Error(), "sha256") {
		t.Errorf("tampered binary accepted: %v", err)
	}
	if _, err := os.Stat(dest); err == nil {
		t.Error("dest written on failure")
	}
	if entries, _ := os.ReadDir(filepath.Dir(dest)); len(entries) != 0 {
		t.Errorf("temp file left: %v", entries)
	}
}

func TestExistingDestUntouchedOnFailure(t *testing.T) {
	ctx := context.Background()
	d, f, _ := setup(t)
	m, _ := d.Fetch(ctx, "v1.2.3")
	dest := filepath.Join(t.TempDir(), "bin")
	os.WriteFile(dest, []byte("old"), 0o755)
	f.bin = []byte("bad")
	_ = d.Download(ctx, m, PlatformLinuxAMD64, dest)
	if b, _ := os.ReadFile(dest); string(b) != "old" {
		t.Error("existing file clobbered")
	}
}

func TestSizeLimit(t *testing.T) {
	d, f, k := setup(t)
	pad := make([]byte, MaxManifestSize+1)
	f.manifest = pad
	f.sig = minisign.Sign(k.priv, pad)
	if _, err := d.Fetch(
		context.Background(),
		"v1.2.3",
	); err == nil ||
		!strings.Contains(err.Error(), "exceeds") {
		t.Errorf("oversize manifest: %v", err)
	}
}

func TestDefaultKeysPlaceholders(t *testing.T) {
	if _, err := DefaultKeys(); err == nil {
		t.Error("placeholder keys must not parse")
	}
	d := &Downloader{BaseURL: "http://127.0.0.1:1"}
	if _, err := d.Fetch(context.Background(), "v1.0.0"); err == nil {
		t.Error("fetch with placeholder keys succeeded")
	}
	k := newKey(t)
	defer SetTrustedKeys([]string{k.pub.String()})()
	keys, err := DefaultKeys()
	if err != nil || len(keys) != 1 || !keys[0].Equal(k.pub) {
		t.Errorf("SetTrustedKeys: %v", err)
	}
	TrustedKeysOverride = k.pub.String() + "," + newKey(t).pub.String()
	if keys, err := DefaultKeys(); err != nil || len(keys) != 2 {
		t.Errorf("override: %v", err)
	}
	TrustedKeysOverride = ""
}

func TestStateRecordFailure(t *testing.T) {
	dir := t.TempDir()
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := RecordFailure(dir, "v1.0.1", "crash", KindRelease, t0); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := RecordFailure(
			dir,
			"v1.0.2",
			"no helloack",
			KindDependency,
			t0.Add(time.Duration(i)*time.Hour),
		); err != nil {
			t.Fatal(err)
		}
		st, _ := LoadState(dir)
		f := st.Failed["v1.0.2"]
		if f.Attempts != i+1 || f.Final != (i == 2) {
			t.Errorf("attempt %d: %+v", i+1, f)
		}
	}
	st, err := LoadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	if f := st.Failed["v1.0.1"]; !f.Final || f.Attempts != 1 || f.Kind != KindRelease {
		t.Errorf("release failure: %+v", f)
	}
	fu := st.FailedUpdates()
	if len(fu) != 2 || fu[0].Version != "v1.0.1" || !fu[1].Final || fu[1].Attempts != 3 ||
		fu[1].Reason != "no helloack" {
		t.Errorf("FailedUpdates: %+v", fu)
	}
	if err := RecordFailure(dir, "v1.0.3", "x", "bogus", t0); err == nil {
		t.Error("bad kind accepted")
	}
	if err := RecordFailure(dir, "nope", "x", KindRelease, t0); err == nil {
		t.Error("bad version accepted")
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Errorf("stray files: %v", entries)
	}
}

func TestStateMinVersionAndEmpty(t *testing.T) {
	dir := t.TempDir()
	st, err := LoadState(dir)
	if err != nil || st.MinStateVersion != "" || len(st.FailedUpdates()) != 0 {
		t.Fatalf("empty: %+v %v", st, err)
	}
	if err := RecordMinStateVersion(dir, "v1.5.0"); err != nil {
		t.Fatal(err)
	}
	if err := RecordMinStateVersion(dir, "v1.2.0"); err != nil {
		t.Fatal(err)
	}
	st, _ = LoadState(dir)
	if st.MinStateVersion != "v1.5.0" {
		t.Errorf("floor lowered: %s", st.MinStateVersion)
	}
	if err := RecordMinStateVersion(dir, "bad"); err == nil {
		t.Error("bad version accepted")
	}
	os.WriteFile(filepath.Join(dir, StateFile), []byte("{"), 0o600)
	if _, err := LoadState(dir); err == nil {
		t.Error("corrupt state accepted")
	}
}

func TestIngestLauncherOutcome(t *testing.T) {
	dir := t.TempDir()
	if err := IngestLauncherOutcome(dir); err != nil {
		t.Fatalf("missing file: %v", err)
	}
	path := filepath.Join(dir, LauncherOutcomeFile)
	at := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	os.WriteFile(
		path,
		[]byte(
			`{"version":"v1.2.3","reason":"probation:no hello","kind":"dependency","at":"2026-03-04T05:06:07Z"}`,
		),
		0o600,
	)
	if err := IngestLauncherOutcome(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("outcome file not deleted")
	}
	st, _ := LoadState(dir)
	f := st.Failed["v1.2.3"]
	if f.Final || f.Attempts != 1 || f.Reason != "probation:no hello" || !f.LastAttempt.Equal(at) {
		t.Errorf("%+v", f)
	}
	os.WriteFile(
		path,
		[]byte(
			`{"version":"v1.2.4","reason":"crash","kind":"release","at":"2026-03-04T05:06:07Z"}`,
		),
		0o600,
	)
	if err := IngestLauncherOutcome(dir); err != nil {
		t.Fatal(err)
	}
	st, _ = LoadState(dir)
	if !st.Failed["v1.2.4"].Final || len(st.Failed) != 2 {
		t.Errorf("%+v", st)
	}
	for _, bad := range []string{`{`, `{"version":"v1.0.0","kind":"weird"}`, `{"version":"x","kind":"release"}`} {
		os.WriteFile(path, []byte(bad), 0o600)
		if err := IngestLauncherOutcome(dir); err == nil {
			t.Errorf("%s accepted", bad)
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("bad file kept: %s", bad)
		}
	}
	if st, _ = LoadState(dir); len(st.Failed) != 2 {
		t.Errorf("bad outcome recorded: %+v", st)
	}
}

func TestDecide(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	run := mustV(t, "v1.2.0")
	var st State
	st.RecordFailure("v1.3.0", "crash", KindRelease, now.Add(-24*time.Hour))
	st.RecordFailure("v1.4.0", "no ack", KindDependency, now.Add(-30*time.Minute))
	st.RecordFailure("v1.5.0", "no ack", KindDependency, now.Add(-2*time.Hour))
	st.RecordFailure("v1.6.0", "no ack", KindDependency, now.Add(-3*time.Hour))
	st.RecordFailure("v1.6.0", "no ack", KindDependency, now.Add(-2*time.Hour))
	st.RecordFailure("v1.6.0", "no ack", KindDependency, now.Add(-time.Hour))
	st.MinStateVersion = "v1.1.0"

	cases := []struct {
		name string
		rel  proto.Release
		want Decision
	}{
		{"newer", proto.Release{Version: "v1.2.1"}, Install},
		{"same", proto.Release{Version: "v1.2.0"}, Skip},
		{"lower no rollback", proto.Release{Version: "v1.1.5"}, Skip},
		{"lower rollback", proto.Release{Version: "v1.1.5", RollbackAllowed: true}, Install},
		{"below floor rollback", proto.Release{Version: "v1.0.9", RollbackAllowed: true}, Skip},
		{"at floor rollback", proto.Release{Version: "v1.1.0", RollbackAllowed: true}, Install},
		{"final release failure", proto.Release{Version: "v1.3.0"}, Skip},
		{"dep within window", proto.Release{Version: "v1.4.0"}, Skip},
		{"dep after window", proto.Release{Version: "v1.5.0"}, Install},
		{"dep final", proto.Release{Version: "v1.6.0"}, Skip},
		{"invalid", proto.Release{Version: "latest"}, Skip},
		{"prerelease lower", proto.Release{Version: "v1.2.0-rc.1"}, Skip},
	}
	for _, c := range cases {
		got, why := Decide(run, c.rel, st, now)
		if got != c.want || why == "" {
			t.Errorf("%s: %v %q", c.name, got, why)
		}
	}
	// Exactly at the retry boundary the window has elapsed.
	if d, _ := Decide(
		run,
		proto.Release{Version: "v1.4.0"},
		st,
		now.Add(30*time.Minute),
	); d != Install {
		t.Error("boundary")
	}
	// Floor applies even if the version is not lower than running.
	st2 := State{MinStateVersion: "v3.0.0"}
	if d, _ := Decide(mustV(t, "v0.1.0"), proto.Release{Version: "v2.0.0"}, st2, now); d != Skip {
		t.Error("floor above upgrade target")
	}
	if Install.String() != "install" || Skip.String() != "skip" {
		t.Error("String")
	}
}

func TestPreconditions(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	now := time.Now()
	ctx := context.Background()
	if err := Preconditions(
		ctx,
		[]string{ln.Addr().String()},
		now.Add(-30*time.Second),
		now,
	); err != nil {
		t.Fatal(err)
	}
	if err := Preconditions(ctx, nil, now.Add(-30*time.Second), now); err != nil {
		t.Fatal(err)
	}
	if err := Preconditions(ctx, nil, now.Add(-2*time.Minute), now); err == nil {
		t.Error("stale HelloAck accepted")
	}
	if err := Preconditions(ctx, nil, time.Time{}, now); err == nil {
		t.Error("zero HelloAck accepted")
	}
	closed := ln.Addr().String()
	ln2, _ := net.Listen("tcp", "127.0.0.1:0")
	dead := ln2.Addr().String()
	ln2.Close()
	if err := Preconditions(ctx, []string{closed, dead}, now, now); err == nil {
		t.Error("dead target accepted")
	}
}
