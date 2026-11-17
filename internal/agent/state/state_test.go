package state

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/zekihan/t3-mesh/internal/proto"
)

func sampleCache(t *testing.T) *Cache {
	t.Helper()

	last := time.Date(2026, time.November, 1, 12, 0, 0, 0, time.UTC)

	return &Cache{
		FormatVersion: FormatVersion,
		Machine:       "z-arch",
		Home:          true,
		Rules: proto.Rules{
			Revision: "r1",
			Allow:    map[string][]string{"t3.devbox": {"z-phone", "agent-z-mac"}},
		},
		Peers: proto.PeerTable{
			Revision: "p1",
			Peers: []proto.Peer{{
				Machine:    "devbox",
				Identity:   "agent-devbox",
				Services:   []string{"t3"},
				LANAddrs:   []string{"192.168.1.10"},
				DirectPort: 27400,
				Home:       true,
			}},
		},
		Revocations: proto.Revocations{
			Revision:            "v1",
			DisabledIdentities:  []string{"old-phone"},
			BlockedFingerprints: []string{"abcd"},
		},
		TrustBundle:    proto.TrustBundle{Revision: "t1", PEM: "-----BEGIN CERTIFICATE-----"},
		Release:        proto.Release{Version: "v0.2.0", Revision: "rel1"},
		LastHubContact: last,
		HomeGatewayMAC: "aa:bb:cc:dd:ee:ff",
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	want := sampleCache(t)

	if err := Save(dir, want); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("round trip mismatch:\n got %+v\nwant %+v", got, want)
	}
}

func TestSaveSetsFormatVersion(t *testing.T) {
	dir := t.TempDir()

	c := sampleCache(t)
	c.FormatVersion = 0

	if err := Save(dir, c); err != nil {
		t.Fatalf("Save: %v", err)
	}

	if c.FormatVersion != 0 {
		t.Fatalf("Save mutated caller's FormatVersion to %d", c.FormatVersion)
	}

	got, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if got.FormatVersion != FormatVersion {
		t.Fatalf("FormatVersion = %d", got.FormatVersion)
	}
}

func TestSaveCreatesDirAndModes(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "state")

	if err := Save(dir, sampleCache(t)); err != nil {
		t.Fatalf("Save: %v", err)
	}

	dirInfo, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}

	if mode := dirInfo.Mode().Perm(); mode != 0o700 {
		t.Fatalf("dir mode = %o, want 700", mode)
	}

	fileInfo, err := os.Stat(filepath.Join(dir, "cache.json"))
	if err != nil {
		t.Fatal(err)
	}

	if mode := fileInfo.Mode().Perm(); mode != 0o600 {
		t.Fatalf("file mode = %o, want 600", mode)
	}
}

func TestSaveLeavesNoTempFiles(t *testing.T) {
	dir := t.TempDir()

	for i := range 3 {
		c := sampleCache(t)
		c.Machine = string(rune('a' + i))

		if err := Save(dir, c); err != nil {
			t.Fatalf("Save %d: %v", i, err)
		}
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	if len(entries) != 1 || entries[0].Name() != "cache.json" {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}

		t.Fatalf("dir entries = %v, want only cache.json", names)
	}

	got, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}

	if got.Machine != "c" {
		t.Fatalf("Machine = %q, want last write", got.Machine)
	}
}

func TestSaveFailsWhenDirIsFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := Save(path, sampleCache(t)); err == nil {
		t.Fatal("Save accepted a file as directory")
	}
}

func TestLoadMissingIsEmpty(t *testing.T) {
	c, err := Load(filepath.Join(t.TempDir(), "absent"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if c.FormatVersion != FormatVersion {
		t.Fatalf("FormatVersion = %d", c.FormatVersion)
	}

	if !c.LastHubContact.IsZero() || c.Home || c.Machine != "" || c.HomeGatewayMAC != "" {
		t.Fatalf("missing cache not empty: %+v", c)
	}
}

func writeCache(t *testing.T, body string) string {
	t.Helper()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "cache.json"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	return dir
}

func TestLoadRejectsBadVersions(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{"newer version", `{"formatVersion": 2}`},
		{"much newer version", `{"formatVersion": 99}`},
		{"version zero", `{"machine": "z-arch"}`},
		{"negative version", `{"formatVersion": -1}`},
		{"malformed json", `{"formatVersion": 1,`},
		{"wrong type", `{"formatVersion": 1, "home": "yes"}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Load(writeCache(t, tt.body)); err == nil {
				t.Fatal("Load accepted bad cache")
			}
		})
	}
}

func TestLoadIgnoresUnknownFields(t *testing.T) {
	body := `{
  "formatVersion": 1,
  "machine": "z-arch",
  "home": true,
  "someFutureField": {"nested": [1, 2, 3]},
  "rules": {"revision": "r9", "allow": {}, "extra": true},
  "release": {"version": "v9", "revision": "x", "rollbackAllowed": false, "newThing": 1}
}`

	c, err := Load(writeCache(t, body))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if c.Machine != "z-arch" || !c.Home || c.Rules.Revision != "r9" || c.Release.Version != "v9" {
		t.Fatalf("known fields not read: %+v", c)
	}
}

func TestLoadAcceptsOlderVersion(t *testing.T) {
	c, err := Load(writeCache(t, `{"formatVersion": 1, "machine": "m"}`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if c.Machine != "m" {
		t.Fatalf("Machine = %q", c.Machine)
	}
}

func TestJSONFieldNames(t *testing.T) {
	data, err := json.Marshal(sampleCache(t))
	if err != nil {
		t.Fatal(err)
	}

	for _, key := range []string{
		`"formatVersion":1`, `"machine"`, `"home"`, `"rules"`, `"peers"`, `"revocations"`,
		`"trustBundle"`, `"release"`, `"lastHubContact"`, `"homeGatewayMAC"`,
	} {
		if !strings.Contains(string(data), key) {
			t.Fatalf("encoded cache lacks %s: %s", key, data)
		}
	}

	c := &Cache{FormatVersion: 1}

	data, err = json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}

	if strings.Contains(string(data), "homeGatewayMAC") {
		t.Fatalf("empty homeGatewayMAC not omitted: %s", data)
	}
}

func TestWithinWindow(t *testing.T) {
	last := time.Date(2026, time.November, 1, 12, 0, 0, 0, time.UTC)
	ttl := 168 * time.Hour

	tests := []struct {
		name string
		last time.Time
		now  time.Time
		want bool
	}{
		{"zero last contact", time.Time{}, last, false},
		{"same instant", last, last, true},
		{"inside window", last, last.Add(time.Hour), true},
		{"exactly at ttl", last, last.Add(ttl), true},
		{"one nanosecond past ttl", last, last.Add(ttl + time.Nanosecond), false},
		{"well past ttl", last, last.Add(30 * 24 * time.Hour), false},
		{"small backwards skew", last, last.Add(-time.Minute), true},
		{"clock moved far back", last, last.Add(-24 * time.Hour), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Cache{LastHubContact: tt.last}
			if got := c.WithinWindow(tt.now, ttl); got != tt.want {
				t.Fatalf("WithinWindow = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestApply(t *testing.T) {
	home := true
	rules := proto.Rules{Revision: "r2", Allow: map[string][]string{"t3.z": {"x"}}}
	peers := proto.PeerTable{Revision: "p2"}
	revs := proto.Revocations{Revision: "v2", DisabledIdentities: []string{"gone"}}
	bundle := proto.TrustBundle{Revision: "t2", PEM: "pem"}

	tests := []struct {
		name   string
		update proto.Update
		check  func(*testing.T, *Cache)
	}{
		{
			name:   "empty update changes nothing",
			update: proto.Update{},
			check: func(t *testing.T, c *Cache) {
				t.Helper()

				if c.Home || c.Rules.Revision != "r1" || c.Peers.Revision != "p1" ||
					c.Revocations.Revision != "v1" || c.TrustBundle.Revision != "t1" {
					t.Fatalf("empty update changed cache: %+v", c)
				}
			},
		},
		{
			name:   "home only",
			update: proto.Update{Home: &home},
			check: func(t *testing.T, c *Cache) {
				t.Helper()

				if !c.Home || c.Rules.Revision != "r1" {
					t.Fatalf("home update: %+v", c)
				}
			},
		},
		{
			name:   "home false clears home",
			update: proto.Update{Home: boolPtr(false)},
			check: func(t *testing.T, c *Cache) {
				t.Helper()

				if c.Home {
					t.Fatal("Home not cleared")
				}
			},
		},
		{
			name:   "rules replaced",
			update: proto.Update{Rules: &rules},
			check: func(t *testing.T, c *Cache) {
				t.Helper()

				if c.Rules.Revision != "r2" || len(c.Rules.Allow["t3.z"]) != 1 {
					t.Fatalf("rules = %+v", c.Rules)
				}
			},
		},
		{
			name:   "peers replaced",
			update: proto.Update{Peers: &peers},
			check: func(t *testing.T, c *Cache) {
				t.Helper()

				if c.Peers.Revision != "p2" || c.Peers.Peers != nil {
					t.Fatalf("peers = %+v", c.Peers)
				}
			},
		},
		{
			name:   "revocations replaced",
			update: proto.Update{Revocations: &revs},
			check: func(t *testing.T, c *Cache) {
				t.Helper()

				if c.Revocations.Revision != "v2" || c.Revocations.BlockedFingerprints != nil {
					t.Fatalf("revocations = %+v", c.Revocations)
				}
			},
		},
		{
			name:   "trust bundle replaced",
			update: proto.Update{TrustBundle: &bundle},
			check: func(t *testing.T, c *Cache) {
				t.Helper()

				if c.TrustBundle != bundle {
					t.Fatalf("trust bundle = %+v", c.TrustBundle)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := sampleCache(t)
			c.Home = false
			c.Apply(tt.update)
			tt.check(t, c)
		})
	}
}

func TestApplyLeavesContactAndMACAlone(t *testing.T) {
	c := sampleCache(t)
	before := *c

	c.Apply(proto.Update{Home: boolPtr(false)})

	if !c.LastHubContact.Equal(before.LastHubContact) || c.HomeGatewayMAC != before.HomeGatewayMAC ||
		c.Release != before.Release || c.Machine != before.Machine {
		t.Fatalf("Apply touched unrelated fields: %+v", c)
	}
}

func boolPtr(b bool) *bool { return &b }
