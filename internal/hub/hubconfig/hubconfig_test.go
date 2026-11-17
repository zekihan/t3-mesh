package hubconfig

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const goodConfig = `
machines:
  devbox: {identity: agent-devbox, services: {t3: {kind: http}}}
  z-mac:  {identity: agent-z-mac,  disconnectAlertAfter: 24h, services: {t3: {kind: http}}}
homeCIDRs: [192.168.0.0/22, "fd12:3456:789a:1::/64"]
viewerDomain: Mesh.Noqer.com
release: {version: v0.3.0, rollbackAllowed: false}
issuer: {namespace: mtls-pki, name: clients, kind: Issuer, group: cert-manager.io}
policy:
  entries:
    mesh-t3-devbox: {identities: [z-tablet, z-phone, agent-z-mac, z-phone]}
    mesh-t3-z-mac:  {identities: [z-phone]}
  disabledIdentities: [z-old]
  blockedFingerprints: ["AB12AB12AB12AB12AB12AB12AB12AB12AB12AB12AB12AB12AB12AB12AB12AB12"]
`

func mkCert(t *testing.T, ca bool, notAfter time.Time) (certPEM, keyPEM []byte) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              notAfter,
		IsCA:                  ca,
		BasicConstraintsValid: true,
		DNSNames:              []string{"mesh.noqer.com"},
	}

	if ca {
		tpl.KeyUsage = x509.KeyUsageCertSign
	}

	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})
}

func write(t *testing.T, dir, name, content string) {
	t.Helper()

	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

type fixture struct {
	root string
	p    Paths
}

func newFixture(t *testing.T, cfg string, certEnd time.Time) *fixture {
	t.Helper()

	root := t.TempDir()
	f := &fixture{root: root, p: Paths{
		ConfigDir: filepath.Join(root, "config"),
		TrustDir:  filepath.Join(root, "trust"),
		CertDir:   filepath.Join(root, "cert"),
	}}

	write(t, f.p.ConfigDir, ConfigFile, cfg)

	ca1, _ := mkCert(t, true, time.Now().Add(1000*time.Hour))
	ca2, _ := mkCert(t, true, time.Now().Add(1000*time.Hour))
	write(t, f.p.TrustDir, TrustFile, string(ca1)+string(ca2))
	write(t, f.p.TrustDir, RevFile, "rev-1\n")

	crt, key := mkCert(t, false, certEnd)
	write(t, f.p.CertDir, CertFile, string(crt))
	write(t, f.p.CertDir, KeyFile, string(key))

	return f
}

func TestLoadDerivedState(t *testing.T) {
	f := newFixture(t, goodConfig, time.Now().Add(90*24*time.Hour))

	s, err := Load(f.p)
	if err != nil {
		t.Fatal(err)
	}

	got := s.Rules.Allow["t3.devbox"]
	if strings.Join(got, ",") != "agent-z-mac,z-phone,z-tablet" {
		t.Errorf("allow devbox = %v", got)
	}

	if s.Machines["z-mac"].DisconnectAlertAfter != 24*time.Hour ||
		s.Machines["devbox"].DisconnectAlertAfter != DefaultDisconnectAlertAfter {
		t.Errorf("disconnect thresholds = %+v", s.Machines)
	}

	if len(s.Rules.Allow["t3.z-mac"]) != 1 || s.Rules.Revision == "" {
		t.Errorf("rules = %+v", s.Rules)
	}

	if s.Revocations.BlockedFingerprints[0] != strings.Repeat("ab12", 16) {
		t.Errorf("fingerprint not normalized: %v", s.Revocations.BlockedFingerprints)
	}

	if s.Revocations.Revision == "" || s.Release.Revision == "" || s.PolicyRevision == "" {
		t.Error("missing revisions")
	}

	if s.TrustBundle.Revision != "rev-1" || s.TrustBundle.PEM == "" || s.TrustPool == nil {
		t.Errorf("trust = %+v", s.TrustBundle)
	}

	if s.ServingCert == nil || s.CertNotAfter.IsZero() {
		t.Error("no serving cert")
	}

	if m, ok := s.MachineForIdentity("agent-z-mac"); !ok || m != "z-mac" {
		t.Errorf("MachineForIdentity = %q %v", m, ok)
	}

	if _, ok := s.MachineForIdentity("z-phone"); ok {
		t.Error("z-phone is not an agent")
	}

	if s.Issuer.Name != "clients" {
		t.Errorf("issuer = %+v", s.Issuer)
	}

	if strings.Join(s.Services("devbox"), ",") != "t3" || s.Services("nope") != nil {
		t.Error("Services")
	}
}

func TestRevisionStable(t *testing.T) {
	f := newFixture(t, goodConfig, time.Now().Add(time.Hour*24*90))
	a, _ := Load(f.p)
	// Reordered identities, same content.
	reordered := strings.Replace(
		goodConfig,
		"[z-tablet, z-phone, agent-z-mac, z-phone]",
		"[agent-z-mac, z-phone, z-tablet]",
		1,
	)
	write(t, f.p.ConfigDir, ConfigFile, reordered)

	b, err := Load(f.p)
	if err != nil {
		t.Fatal(err)
	}

	if a.PolicyRevision != b.PolicyRevision || a.Rules.Revision != b.Rules.Revision {
		t.Error("revision should be order independent")
	}

	write(
		t,
		f.p.ConfigDir,
		ConfigFile,
		strings.Replace(goodConfig, "[z-phone]}", "[z-phone, z-new]}", 1),
	)

	c, _ := Load(f.p)
	if c.PolicyRevision == a.PolicyRevision || c.Release.Revision != a.Release.Revision {
		t.Error("policy revision should change, release revision not")
	}
}

func TestHostTarget(t *testing.T) {
	f := newFixture(t, goodConfig, time.Now().Add(time.Hour*24*90))
	s, _ := Load(f.p)

	cases := []struct {
		host, machine, svc string
		ok                 bool
	}{
		{"t3.devbox.mesh.noqer.com", "devbox", "t3", true},
		{"T3.Z-Mac.MESH.noqer.com:443", "z-mac", "t3", true},
		{"t3.devbox.mesh.noqer.com.", "devbox", "t3", true},
		{"t3.nope.mesh.noqer.com", "", "", false},
		{"ssh.devbox.mesh.noqer.com", "", "", false},
		{"t3.devbox.other.com", "", "", false},
		{"devbox.mesh.noqer.com", "", "", false},
		{"mesh.noqer.com", "", "", false},
		{"", "", "", false},
	}
	for _, c := range cases {
		m, sv, ok := s.HostTarget(c.host)
		if m != c.machine || sv != c.svc || ok != c.ok {
			t.Errorf("HostTarget(%q) = %q %q %v", c.host, m, sv, ok)
		}
	}
}

func TestIsHome(t *testing.T) {
	f := newFixture(t, goodConfig, time.Now().Add(time.Hour*24*90))
	s, _ := Load(f.p)

	for addr, want := range map[string]bool{
		"192.168.1.5":          true,
		"192.168.4.1":          false,
		"::ffff:192.168.2.9":   true,
		"fd12:3456:789a:1::42": true,
		"fd12:3456:789a:2::1":  false,
		"8.8.8.8":              false,
	} {
		if got := s.IsHome(netip.MustParseAddr(addr)); got != want {
			t.Errorf("IsHome(%s) = %v", addr, got)
		}
	}
}

func TestValidation(t *testing.T) {
	cases := map[string]func(string) string{
		"bad machine name": func(c string) string { return strings.ReplaceAll(c, "devbox", "Dev_Box") },
		"identity mismatch": func(c string) string {
			return strings.Replace(c, "identity: agent-devbox", "identity: agent-other", 1)
		},
		"bad kind":      func(c string) string { return strings.Replace(c, "kind: http", "kind: tcp", 1) },
		"bad cidr":      func(c string) string { return strings.Replace(c, "192.168.0.0/22", "192.168.0.0/99", 1) },
		"bad version":   func(c string) string { return strings.Replace(c, "v0.3.0", "0.3", 1) },
		"unknown entry": func(c string) string { return strings.Replace(c, "mesh-t3-z-mac", "mesh-t3-ghost", 1) },
		"empty identities": func(c string) string {
			return strings.Replace(
				c,
				"mesh-t3-z-mac:  {identities: [z-phone]}",
				"mesh-t3-z-mac:  {identities: []}",
				1,
			)
		},
		"bad fingerprint": func(c string) string {
			return strings.Replace(
				c,
				"AB12AB12AB12AB12AB12AB12AB12AB12AB12AB12AB12AB12AB12AB12AB12AB12",
				"zz",
				1,
			)
		},
		"no domain":     func(c string) string { return strings.Replace(c, "viewerDomain: Mesh.Noqer.com", "", 1) },
		"unknown field": func(c string) string { return c + "\nbogus: 1\n" },
		"not yaml":      func(string) string { return "machines: [" },
	}

	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, mutate(goodConfig), time.Now().Add(time.Hour*24*90))

			_, err := Load(f.p)
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("want ErrInvalid, got %v", err)
			}
		})
	}
}

func TestTrustAndCertErrors(t *testing.T) {
	f := newFixture(t, goodConfig, time.Now().Add(time.Hour*24*90))
	write(t, f.p.TrustDir, TrustFile, "not pem")

	if _, err := Load(f.p); err == nil {
		t.Error("empty bundle accepted")
	}

	f = newFixture(t, goodConfig, time.Now().Add(time.Hour*24*90))
	write(t, f.p.TrustDir, RevFile, "  \n")

	if _, err := Load(f.p); err == nil {
		t.Error("empty revision accepted")
	}

	f = newFixture(t, goodConfig, time.Now().Add(time.Hour*24*90))
	_, otherKey := mkCert(t, false, time.Now().Add(time.Hour))
	write(t, f.p.CertDir, KeyFile, string(otherKey))

	if _, err := Load(f.p); err == nil {
		t.Error("mismatched key accepted")
	}
}

func TestNewWatcherFirstLoadFails(t *testing.T) {
	f := newFixture(t, "machines: [", time.Now().Add(time.Hour))

	if _, err := NewWatcher(f.p, nil); err == nil {
		t.Fatal("expected error")
	}
}

func TestReloadKeepsPreviousOnFailure(t *testing.T) {
	f := newFixture(t, goodConfig, time.Now().Add(time.Hour*24*90))

	w, err := NewWatcher(f.p, nil)
	if err != nil {
		t.Fatal(err)
	}

	first := w.Current()

	write(t, f.p.ConfigDir, ConfigFile, "garbage: [")
	w.Reload(nil)

	if w.Current() != first || w.LastError() == nil {
		t.Error("failed reload must keep snapshot and record error")
	}

	// Unchanged content: no swap, no callback.
	write(t, f.p.ConfigDir, ConfigFile, goodConfig)

	called := false

	w.Reload(func(_, _ *Snapshot) { called = true })

	if called || w.Current() != first || w.LastError() != nil {
		t.Error("identical reload should be a no-op")
	}

	write(t, f.p.ConfigDir, ConfigFile, strings.Replace(goodConfig, "v0.3.0", "v0.4.0", 1))
	w.Reload(func(old, next *Snapshot) {
		called = old == first && next.Release.Version == "v0.4.0"
	})

	if !called || w.Current().Release.Version != "v0.4.0" {
		t.Error("changed reload not applied")
	}
}

func TestStalePolicy(t *testing.T) {
	f := newFixture(t, goodConfig, time.Now().Add(time.Hour*24*90))
	clock := time.Now()

	w, err := NewWatcher(f.p, nil)
	if err != nil {
		t.Fatal(err)
	}

	w.now = func() time.Time { return clock }

	if stale, _ := w.Stale(clock); stale {
		t.Fatal("fresh watcher stale")
	}

	// Valid change that fails to load because the trust bundle is broken: the
	// mounted policy revision still differs.
	write(
		t,
		f.p.ConfigDir,
		ConfigFile,
		strings.Replace(goodConfig, "[z-phone]}", "[z-phone, z-new]}", 1),
	)
	write(t, f.p.TrustDir, TrustFile, "broken")
	w.Reload(nil)

	if stale, _ := w.Stale(clock.Add(9 * time.Minute)); stale {
		t.Error("stale before 10 minutes")
	}

	stale, reason := w.Stale(clock.Add(11 * time.Minute))
	if !stale || reason == "" {
		t.Error("expected stale after 10 minutes")
	}

	// Repair trust: reload applies, stale clears.
	ca, _ := mkCert(t, true, time.Now().Add(time.Hour))
	write(t, f.p.TrustDir, TrustFile, string(ca))
	w.Reload(nil)

	if stale, _ := w.Stale(clock.Add(time.Hour)); stale {
		t.Error("stale after successful reload")
	}
}

func TestStaleInvalidPolicyFile(t *testing.T) {
	f := newFixture(t, goodConfig, time.Now().Add(time.Hour*24*90))
	clock := time.Now()
	w, _ := NewWatcher(f.p, nil)
	w.now = func() time.Time { return clock }

	write(t, f.p.ConfigDir, ConfigFile, "machines: [")
	w.Reload(nil)

	if stale, _ := w.Stale(clock.Add(11 * time.Minute)); !stale {
		t.Error("unparsable mounted policy should go stale")
	}
}

func TestStaleCert(t *testing.T) {
	clock := time.Now()
	f := newFixture(t, goodConfig, clock.Add(10*24*time.Hour))

	w, err := NewWatcher(f.p, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Near expiry but nothing newer mounted.
	if stale, _ := w.Stale(clock); stale {
		t.Error("stale without a newer cert")
	}

	// A newer cert is mounted but the key is mismatched, so the load fails.
	newCrt, _ := mkCert(t, false, clock.Add(80*24*time.Hour))
	write(t, f.p.CertDir, CertFile, string(newCrt))
	w.Reload(nil)

	if stale, reason := w.Stale(clock); !stale {
		t.Errorf("expected stale cert, reason %q", reason)
	}

	// Far from expiry: not stale even with a newer cert mounted.
	if stale, _ := w.Stale(clock.Add(-30 * 24 * time.Hour)); stale {
		t.Error("stale while cert is far from expiry")
	}
}

type recorder struct {
	mu  sync.Mutex
	ch  chan *Snapshot
	cnt int
}

func (r *recorder) on(_, next *Snapshot) {
	r.mu.Lock()
	r.cnt++
	r.mu.Unlock()

	select {
	case r.ch <- next:
	default:
	}
}

func startRun(t *testing.T, w *Watcher) *recorder {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	rec := &recorder{ch: make(chan *Snapshot, 16)}
	done := make(chan error, 1)

	go func() { done <- w.Run(ctx, rec.on) }()

	t.Cleanup(func() {
		cancel()

		if err := <-done; err != nil {
			t.Errorf("Run: %v", err)
		}
	})

	return rec
}

func (r *recorder) wait(t *testing.T, pred func(*Snapshot) bool) *Snapshot {
	t.Helper()

	timeout := time.After(10 * time.Second)

	for {
		select {
		case s := <-r.ch:
			if pred(s) {
				return s
			}
		case <-timeout:
			t.Fatal("timed out waiting for change")
		}
	}
}

func TestWatcherPicksUpPlainWrites(t *testing.T) {
	f := newFixture(t, goodConfig, time.Now().Add(time.Hour*24*90))

	w, err := NewWatcher(f.p, nil)
	if err != nil {
		t.Fatal(err)
	}

	w.debounce = 20 * time.Millisecond
	rec := startRun(t, w)

	write(t, f.p.ConfigDir, ConfigFile, strings.Replace(goodConfig, "v0.3.0", "v0.9.9", 1))
	rec.wait(t, func(s *Snapshot) bool { return s.Release.Version == "v0.9.9" })

	if w.Current().Release.Version != "v0.9.9" {
		t.Error("Current not updated")
	}
}

func TestWatcherPollBackstop(t *testing.T) {
	f := newFixture(t, goodConfig, time.Now().Add(time.Hour*24*90))

	w, _ := NewWatcher(f.p, nil)
	w.debounce = time.Hour // events never fire a reload in time
	w.poll = 30 * time.Millisecond
	rec := startRun(t, w)

	write(t, f.p.ConfigDir, ConfigFile, strings.Replace(goodConfig, "v0.3.0", "v0.5.0", 1))
	rec.wait(t, func(s *Snapshot) bool { return s.Release.Version == "v0.5.0" })
}

// k8sMount lays dir out like a Kubernetes volume: files are symlinks through
// "..data", itself a symlink to a timestamped directory.
type k8sMount struct {
	dir string
	gen int
}

func (m *k8sMount) publish(t *testing.T, files map[string]string) {
	t.Helper()

	m.gen++
	name := "..gen" + string(rune('0'+m.gen))
	gen := filepath.Join(m.dir, name)

	for f, c := range files {
		write(t, gen, f, c)
	}

	tmp := filepath.Join(m.dir, "..data_tmp")
	_ = os.Remove(tmp)

	if err := os.Symlink(name, tmp); err != nil {
		t.Fatal(err)
	}

	if err := os.Rename(tmp, filepath.Join(m.dir, "..data")); err != nil {
		t.Fatal(err)
	}

	for f := range files {
		link := filepath.Join(m.dir, f)
		if _, err := os.Lstat(link); err != nil {
			if err := os.Symlink(filepath.Join("..data", f), link); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestWatcherKubernetesSymlinkSwap(t *testing.T) {
	root := t.TempDir()
	cfg := &k8sMount{dir: filepath.Join(root, "config")}
	trust := &k8sMount{dir: filepath.Join(root, "trust")}
	cert := &k8sMount{dir: filepath.Join(root, "cert")}

	ca, _ := mkCert(t, true, time.Now().Add(time.Hour*1000))
	crt1, key1 := mkCert(t, false, time.Now().Add(20*24*time.Hour))

	cfg.publish(t, map[string]string{ConfigFile: goodConfig})
	trust.publish(t, map[string]string{TrustFile: string(ca), RevFile: "r1"})
	cert.publish(t, map[string]string{CertFile: string(crt1), KeyFile: string(key1)})

	w, err := NewWatcher(Paths{cfg.dir, trust.dir, cert.dir}, nil)
	if err != nil {
		t.Fatal(err)
	}

	w.debounce = 20 * time.Millisecond
	rec := startRun(t, w)

	cfg.publish(
		t,
		map[string]string{ConfigFile: strings.Replace(goodConfig, "z-old", "z-older", 1)},
	)
	rec.wait(t, func(s *Snapshot) bool { return s.Revocations.DisabledIdentities[0] == "z-older" })

	trust.publish(t, map[string]string{TrustFile: string(ca), RevFile: "r2"})
	rec.wait(t, func(s *Snapshot) bool { return s.TrustBundle.Revision == "r2" })

	crt2, key2 := mkCert(t, false, time.Now().Add(80*24*time.Hour))
	cert.publish(t, map[string]string{CertFile: string(crt2), KeyFile: string(key2)})

	got := rec.wait(
		t,
		func(s *Snapshot) bool { return s.CertNotAfter.After(time.Now().Add(60 * 24 * time.Hour)) },
	)
	if got.ServingCert == nil {
		t.Error("no cert")
	}

	if stale, reason := w.Stale(time.Now()); stale {
		t.Errorf("unexpectedly stale: %s", reason)
	}
}
