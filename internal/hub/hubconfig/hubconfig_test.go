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
	"strconv"
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

func mkCert(t *testing.T, ca bool, notAfter time.Time) ([]byte, []byte) {
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

	err := os.MkdirAll(dir, 0o750)
	if err != nil {
		t.Fatal(err)
	}

	err = os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600)
	if err != nil {
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
	fix := &fixture{root: root, p: Paths{
		ConfigDir: filepath.Join(root, "config"),
		TrustDir:  filepath.Join(root, "trust"),
		CertDir:   filepath.Join(root, "cert"),
	}}

	write(t, fix.p.ConfigDir, ConfigFile, cfg)

	ca1, _ := mkCert(t, true, time.Now().Add(1000*time.Hour))
	ca2, _ := mkCert(t, true, time.Now().Add(1000*time.Hour))
	write(t, fix.p.TrustDir, TrustFile, string(ca1)+string(ca2))
	write(t, fix.p.TrustDir, RevFile, "rev-1\n")

	crt, key := mkCert(t, false, certEnd)
	write(t, fix.p.CertDir, CertFile, string(crt))
	write(t, fix.p.CertDir, KeyFile, string(key))

	return fix
}

func TestLoadDerivedState(t *testing.T) {
	f := newFixture(t, goodConfig, time.Now().Add(90*24*time.Hour))

	snap, err := Load(f.p)
	if err != nil {
		t.Fatal(err)
	}

	assertRulesAndMachines(t, snap)
	assertRevisionsAndTrust(t, snap)
	assertIdentityLookups(t, snap)
}

func assertRulesAndMachines(t *testing.T, snap *Snapshot) {
	t.Helper()

	got := snap.Rules.Allow["t3.devbox"]
	if strings.Join(got, ",") != "agent-z-mac,z-phone,z-tablet" {
		t.Errorf("allow devbox = %v", got)
	}

	if snap.Machines["z-mac"].DisconnectAlertAfter != 24*time.Hour ||
		snap.Machines["devbox"].DisconnectAlertAfter != DefaultDisconnectAlertAfter {
		t.Errorf("disconnect thresholds = %+v", snap.Machines)
	}

	if len(snap.Rules.Allow["t3.z-mac"]) != 1 || snap.Rules.Revision == "" {
		t.Errorf("rules = %+v", snap.Rules)
	}
}

func assertRevisionsAndTrust(t *testing.T, snap *Snapshot) {
	t.Helper()

	if snap.Revocations.BlockedFingerprints[0] != strings.Repeat("ab12", 16) {
		t.Errorf("fingerprint not normalized: %v", snap.Revocations.BlockedFingerprints)
	}

	if snap.Revocations.Revision == "" || snap.Release.Revision == "" || snap.PolicyRevision == "" {
		t.Error("missing revisions")
	}

	if snap.TrustBundle.Revision != "rev-1" || snap.TrustBundle.PEM == "" || snap.TrustPool == nil {
		t.Errorf("trust = %+v", snap.TrustBundle)
	}

	if snap.ServingCert == nil || snap.CertNotAfter.IsZero() {
		t.Error("no serving cert")
	}
}

func assertIdentityLookups(t *testing.T, snap *Snapshot) {
	t.Helper()

	if m, ok := snap.MachineForIdentity("agent-z-mac"); !ok || m != "z-mac" {
		t.Errorf("MachineForIdentity = %q %v", m, ok)
	}

	if _, ok := snap.MachineForIdentity("z-phone"); ok {
		t.Error("z-phone is not an agent")
	}

	if snap.Issuer.Name != "clients" {
		t.Errorf("issuer = %+v", snap.Issuer)
	}

	if strings.Join(snap.Services("devbox"), ",") != "t3" || snap.Services("nope") != nil {
		t.Error("Services")
	}
}

func TestRevisionStable(t *testing.T) {
	fix := newFixture(t, goodConfig, time.Now().Add(time.Hour*24*90))
	snap, _ := Load(fix.p)
	// Reordered identities, same content.
	reordered := strings.Replace(
		goodConfig,
		"[z-tablet, z-phone, agent-z-mac, z-phone]",
		"[agent-z-mac, z-phone, z-tablet]",
		1,
	)
	write(t, fix.p.ConfigDir, ConfigFile, reordered)

	b, err := Load(fix.p)
	if err != nil {
		t.Fatal(err)
	}

	if snap.PolicyRevision != b.PolicyRevision || snap.Rules.Revision != b.Rules.Revision {
		t.Error("revision should be order independent")
	}

	write(
		t,
		fix.p.ConfigDir,
		ConfigFile,
		strings.Replace(goodConfig, "[z-phone]}", "[z-phone, z-new]}", 1),
	)

	c, _ := Load(fix.p)
	if c.PolicyRevision == snap.PolicyRevision || c.Release.Revision != snap.Release.Revision {
		t.Error("policy revision should change, release revision not")
	}
}

func TestHostTarget(t *testing.T) {
	f := newFixture(t, goodConfig, time.Now().Add(time.Hour*24*90))
	snap, _ := Load(f.p)

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
		m, sv, ok := snap.HostTarget(c.host)
		if m != c.machine || sv != c.svc || ok != c.ok {
			t.Errorf("HostTarget(%q) = %q %q %v", c.host, m, sv, ok)
		}
	}
}

func loadAPIConfig(t *testing.T, cfg string) (*Snapshot, error) {
	t.Helper()

	return Load(newFixture(t, cfg, time.Now().Add(time.Hour*24*90)).p)
}

func TestAPIConfig(t *testing.T) {
	load := loadAPIConfig

	t.Run("default host and no callers", func(t *testing.T) {
		snap, err := load(t, goodConfig)
		if err != nil {
			t.Fatal(err)
		}

		if snap.APIHost != "hub.mesh.noqer.com" || len(snap.APIIdentities) != 0 {
			t.Fatalf("api = %q %v", snap.APIHost, snap.APIIdentities)
		}

		if !snap.IsAPIHost("HUB.mesh.noqer.com:443") || snap.IsAPIHost("t3.devbox.mesh.noqer.com") {
			t.Fatal("IsAPIHost mismatch")
		}

		if _, _, ok := snap.HostTarget("hub.mesh.noqer.com"); ok {
			t.Fatal("API host resolved as a viewer host")
		}
	})

	t.Run("identities and host", func(t *testing.T) {
		snap, err := load(
			t,
			goodConfig+"api:\n  host: Api.Mesh.Noqer.com.\n  identities: [z-tablet, z-phone, z-phone]\n",
		)
		if err != nil {
			t.Fatal(err)
		}

		if snap.APIHost != "api.mesh.noqer.com" ||
			strings.Join(snap.APIIdentities, ",") != "z-phone,z-tablet" {
			t.Fatalf("api = %q %v", snap.APIHost, snap.APIIdentities)
		}

		if !snap.APICaller("z-phone") || snap.APICaller("z-other") {
			t.Fatal("APICaller mismatch")
		}

		if len(snap.Rules.Allow) != 2 {
			t.Fatalf("api.identities leaked into the rules: %v", snap.Rules.Allow)
		}
	})
}

func TestAPIConfigInvalid(t *testing.T) {
	bad := map[string]string{
		"unknown api field": "api:\n  bogus: 1\n",
		"agent identity":    "api:\n  identities: [agent-devbox]\n",
		"bad identity":      "api:\n  identities: [\"urn:x:y\"]\n",
		"blank identity":    "api:\n  identities: [\" \"]\n",
		"bad host":          "api:\n  host: not_a_host\n",
		"agent endpoint":    "api:\n  host: mesh.noqer.com\n",
		"viewer host":       "api:\n  host: t3.devbox.mesh.noqer.com\n",
	}

	for name, extra := range bad {
		t.Run(name, func(t *testing.T) {
			_, err := loadAPIConfig(t, goodConfig+extra)
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("want ErrInvalid, got %v", err)
			}
		})
	}
}

func TestDevicesConfig(t *testing.T) {
	t.Run("absent means no devices", func(t *testing.T) {
		snap, err := loadAPIConfig(t, goodConfig)
		if err != nil {
			t.Fatal(err)
		}

		if len(snap.Devices) != 0 || snap.Device("device-z-phone-mesh") {
			t.Fatalf("devices = %v", snap.Devices)
		}
	})

	t.Run("sorted and unique", func(t *testing.T) {
		snap, err := loadAPIConfig(
			t,
			goodConfig+"devices: [device-z-tablet-mesh, device-z-phone-mesh, device-z-tablet-mesh]\n",
		)
		if err != nil {
			t.Fatal(err)
		}

		if strings.Join(snap.Devices, ",") != "device-z-phone-mesh,device-z-tablet-mesh" {
			t.Fatalf("devices = %v", snap.Devices)
		}

		if !snap.Device("device-z-phone-mesh") || snap.Device("z-phone") ||
			snap.Device("agent-devbox") {
			t.Fatal("Device mismatch")
		}

		if len(snap.Rules.Allow) != 2 || len(snap.APIIdentities) != 0 {
			t.Fatalf("devices leaked into the rules or api callers: %v %v",
				snap.Rules.Allow, snap.APIIdentities)
		}
	})

	t.Run("changes the fingerprint", func(t *testing.T) {
		before, err := loadAPIConfig(t, goodConfig)
		if err != nil {
			t.Fatal(err)
		}

		after, err := loadAPIConfig(t, goodConfig+"devices: [device-z-phone-mesh]\n")
		if err != nil {
			t.Fatal(err)
		}

		if before.Fingerprint == after.Fingerprint {
			t.Fatal("snapshot fingerprint ignores devices")
		}
	})
}

func TestDevicesConfigInvalid(t *testing.T) {
	bad := map[string]string{
		"agent identity":       "devices: [agent-devbox]\n",
		"keychain identity":    "devices: [z-phone]\n",
		"missing suffix":       "devices: [device-z-phone]\n",
		"missing name":         "devices: [device-mesh]\n",
		"upper case":           "devices: [Device-Z-Phone-Mesh]\n",
		"underscore":           "devices: [device-z_phone-mesh]\n",
		"double dash":          "devices: [device-z--phone-mesh]\n",
		"blank":                "devices: [\" \"]\n",
		"uri":                  "devices: [\"urn:noqer:mtls:clients:device-z-phone-mesh\"]\n",
		"too long":             "devices: [device-" + strings.Repeat("a", 40) + "-mesh]\n",
		"one bad among good":   "devices: [device-z-phone-mesh, z-tablet]\n",
		"agent among devices":  "devices: [device-z-phone-mesh, agent-z-mac]\n",
		"unknown nested field": "devices: [device-z-phone-mesh]\nbogus: 1\n",
		"not a list":           "devices: device-z-phone-mesh\n",
	}

	for name, extra := range bad {
		t.Run(name, func(t *testing.T) {
			_, err := loadAPIConfig(t, goodConfig+extra)
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("want ErrInvalid, got %v", err)
			}
		})
	}
}

// A machine identity is always agent-<machine>, so the names cannot collide;
// the overlap check still refuses it should that rule ever loosen.
func TestDevicesOverlapWithAgentIdentity(t *testing.T) {
	cfg := &config{machines: map[string]Machine{"x": {Identity: "device-z-phone-mesh"}}}

	err := cfg.parseDevices([]string{"device-z-phone-mesh"})
	if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "agent identity") {
		t.Fatalf("want an agent-overlap error, got %v", err)
	}
}

func TestIsHome(t *testing.T) {
	f := newFixture(t, goodConfig, time.Now().Add(time.Hour*24*90))
	snap, _ := Load(f.p)

	for addr, want := range map[string]bool{
		"192.168.1.5":          true,
		"192.168.4.1":          false,
		"::ffff:192.168.2.9":   true,
		"fd12:3456:789a:1::42": true,
		"fd12:3456:789a:2::1":  false,
		"8.8.8.8":              false,
	} {
		if got := snap.IsHome(netip.MustParseAddr(addr)); got != want {
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
	fix := newFixture(t, goodConfig, time.Now().Add(time.Hour*24*90))
	write(t, fix.p.TrustDir, TrustFile, "not pem")

	_, err := Load(fix.p)
	if err == nil {
		t.Error("empty bundle accepted")
	}

	fix = newFixture(t, goodConfig, time.Now().Add(time.Hour*24*90))
	write(t, fix.p.TrustDir, RevFile, "  \n")

	_, err = Load(fix.p)
	if err == nil {
		t.Error("empty revision accepted")
	}

	fix = newFixture(t, goodConfig, time.Now().Add(time.Hour*24*90))
	_, otherKey := mkCert(t, false, time.Now().Add(time.Hour))
	write(t, fix.p.CertDir, KeyFile, string(otherKey))

	_, err = Load(fix.p)
	if err == nil {
		t.Error("mismatched key accepted")
	}
}

func TestNewWatcherFirstLoadFails(t *testing.T) {
	f := newFixture(t, "machines: [", time.Now().Add(time.Hour))

	_, err := NewWatcher(f.p, nil)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestReloadKeepsPreviousOnFailure(t *testing.T) {
	fix := newFixture(t, goodConfig, time.Now().Add(time.Hour*24*90))

	watcher, err := NewWatcher(fix.p, nil)
	if err != nil {
		t.Fatal(err)
	}

	first := watcher.Current()

	write(t, fix.p.ConfigDir, ConfigFile, "garbage: [")
	watcher.Reload(nil)

	if watcher.Current() != first || watcher.LastError() == nil {
		t.Error("failed reload must keep snapshot and record error")
	}

	// Unchanged content: no swap, no callback.
	write(t, fix.p.ConfigDir, ConfigFile, goodConfig)

	called := false

	watcher.Reload(func(_, _ *Snapshot) { called = true })

	if called || watcher.Current() != first || watcher.LastError() != nil {
		t.Error("identical reload should be a no-op")
	}

	write(t, fix.p.ConfigDir, ConfigFile, strings.Replace(goodConfig, "v0.3.0", "v0.4.0", 1))
	watcher.Reload(func(old, next *Snapshot) {
		called = old == first && next.Release.Version == "v0.4.0"
	})

	if !called || watcher.Current().Release.Version != "v0.4.0" {
		t.Error("changed reload not applied")
	}
}

func TestStalePolicy(t *testing.T) {
	fix := newFixture(t, goodConfig, time.Now().Add(time.Hour*24*90))
	clock := time.Now()

	watcher, err := NewWatcher(fix.p, nil)
	if err != nil {
		t.Fatal(err)
	}

	watcher.now = func() time.Time { return clock }

	if stale, _ := watcher.Stale(clock); stale {
		t.Fatal("fresh watcher stale")
	}

	// Valid change that fails to load because the trust bundle is broken: the
	// mounted policy revision still differs.
	write(
		t,
		fix.p.ConfigDir,
		ConfigFile,
		strings.Replace(goodConfig, "[z-phone]}", "[z-phone, z-new]}", 1),
	)
	write(t, fix.p.TrustDir, TrustFile, "broken")
	watcher.Reload(nil)

	if stale, _ := watcher.Stale(clock.Add(9 * time.Minute)); stale {
		t.Error("stale before 10 minutes")
	}

	stale, reason := watcher.Stale(clock.Add(11 * time.Minute))
	if !stale || reason == "" {
		t.Error("expected stale after 10 minutes")
	}

	// Repair trust: reload applies, stale clears.
	ca, _ := mkCert(t, true, time.Now().Add(time.Hour))
	write(t, fix.p.TrustDir, TrustFile, string(ca))
	watcher.Reload(nil)

	if stale, _ := watcher.Stale(clock.Add(time.Hour)); stale {
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
	fix := newFixture(t, goodConfig, clock.Add(10*24*time.Hour))

	watcher, err := NewWatcher(fix.p, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Near expiry but nothing newer mounted.
	if stale, _ := watcher.Stale(clock); stale {
		t.Error("stale without a newer cert")
	}

	// A newer cert is mounted but the key is mismatched, so the load fails.
	newCrt, _ := mkCert(t, false, clock.Add(80*24*time.Hour))
	write(t, fix.p.CertDir, CertFile, string(newCrt))
	watcher.Reload(nil)

	if stale, reason := watcher.Stale(clock); !stale {
		t.Errorf("expected stale cert, reason %q", reason)
	}

	// Far from expiry: not stale even with a newer cert mounted.
	if stale, _ := watcher.Stale(clock.Add(-30 * 24 * time.Hour)); stale {
		t.Error("stale while cert is far from expiry")
	}
}

type recorder struct {
	ch  chan *Snapshot
	cnt int
	mu  sync.Mutex
}

func (rec *recorder) on(_, next *Snapshot) {
	rec.mu.Lock()
	rec.cnt++
	rec.mu.Unlock()

	select {
	case rec.ch <- next:
	default:
	}
}

func startRun(t *testing.T, watcher *Watcher) *recorder {
	t.Helper()

	ctx, cancel := context.WithCancel(t.Context())
	rec := &recorder{ch: make(chan *Snapshot, 16)}
	done := make(chan error, 1)

	go func() { done <- watcher.Run(ctx, rec.on) }()

	t.Cleanup(func() {
		cancel()

		err := <-done
		if err != nil {
			t.Errorf("Run: %v", err)
		}
	})

	return rec
}

func (rec *recorder) wait(t *testing.T, pred func(*Snapshot) bool) *Snapshot {
	t.Helper()

	timeout := time.After(10 * time.Second)

	for {
		select {
		case s := <-rec.ch:
			if pred(s) {
				return s
			}
		case <-timeout:
			t.Fatal("timed out waiting for change")
		}
	}
}

func TestWatcherPicksUpPlainWrites(t *testing.T) {
	fix := newFixture(t, goodConfig, time.Now().Add(time.Hour*24*90))

	watcher, err := NewWatcher(fix.p, nil)
	if err != nil {
		t.Fatal(err)
	}

	watcher.debounce = 20 * time.Millisecond
	rec := startRun(t, watcher)

	write(t, fix.p.ConfigDir, ConfigFile, strings.Replace(goodConfig, "v0.3.0", "v0.9.9", 1))
	rec.wait(t, func(s *Snapshot) bool { return s.Release.Version == "v0.9.9" })

	if watcher.Current().Release.Version != "v0.9.9" {
		t.Error("Current not updated")
	}
}

func TestWatcherPollBackstop(t *testing.T) {
	fix := newFixture(t, goodConfig, time.Now().Add(time.Hour*24*90))

	w, _ := NewWatcher(fix.p, nil)
	w.debounce = time.Hour // events never fire a reload in time
	w.poll = 30 * time.Millisecond
	rec := startRun(t, w)

	write(t, fix.p.ConfigDir, ConfigFile, strings.Replace(goodConfig, "v0.3.0", "v0.5.0", 1))
	rec.wait(t, func(s *Snapshot) bool { return s.Release.Version == "v0.5.0" })
}

// k8sMount lays dir out like a Kubernetes volume: files are symlinks through
// "..data", itself a symlink to a timestamped directory.
type k8sMount struct {
	dir string
	gen int
}

func (mount *k8sMount) publish(t *testing.T, files map[string]string) {
	t.Helper()

	mount.gen++
	name := "..gen" + strconv.Itoa(mount.gen)
	gen := filepath.Join(mount.dir, name)

	for f, c := range files {
		write(t, gen, f, c)
	}

	tmp := filepath.Join(mount.dir, "..data_tmp")
	_ = os.Remove(tmp)

	err := os.Symlink(name, tmp)
	if err != nil {
		t.Fatal(err)
	}

	err = os.Rename(tmp, filepath.Join(mount.dir, "..data"))
	if err != nil {
		t.Fatal(err)
	}

	for f := range files {
		link := filepath.Join(mount.dir, f)

		_, err := os.Lstat(link)
		if err != nil {
			err := os.Symlink(filepath.Join("..data", f), link)
			if err != nil {
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

	watcher, err := NewWatcher(Paths{cfg.dir, trust.dir, cert.dir}, nil)
	if err != nil {
		t.Fatal(err)
	}

	watcher.debounce = 20 * time.Millisecond
	rec := startRun(t, watcher)

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

	if stale, reason := watcher.Stale(time.Now()); stale {
		t.Errorf("unexpectedly stale: %s", reason)
	}
}
