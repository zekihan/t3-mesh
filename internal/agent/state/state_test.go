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

	err := Save(dir, want)
	if err != nil {
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

	cache := sampleCache(t)
	cache.FormatVersion = 0

	err := Save(dir, cache)
	if err != nil {
		t.Fatalf("Save: %v", err)
	}

	if cache.FormatVersion != 0 {
		t.Fatalf("Save mutated caller's FormatVersion to %d", cache.FormatVersion)
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

	err := Save(dir, sampleCache(t))
	if err != nil {
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

		err := Save(dir, c)
		if err != nil {
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

	err := os.WriteFile(path, []byte("x"), 0o600)
	if err != nil {
		t.Fatal(err)
	}

	err = Save(path, sampleCache(t))
	if err == nil {
		t.Fatal("Save accepted a file as directory")
	}
}

func TestLoadMissingIsEmpty(t *testing.T) {
	cache, err := Load(filepath.Join(t.TempDir(), "absent"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cache.FormatVersion != FormatVersion {
		t.Fatalf("FormatVersion = %d", cache.FormatVersion)
	}

	if !cache.LastHubContact.IsZero() || cache.Home || cache.Machine != "" ||
		cache.HomeGatewayMAC != "" {
		t.Fatalf("missing cache not empty: %+v", cache)
	}
}

func writeCache(t *testing.T, body string) string {
	t.Helper()

	dir := t.TempDir()

	err := os.WriteFile(filepath.Join(dir, "cache.json"), []byte(body), 0o600)
	if err != nil {
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
			_, err := Load(writeCache(t, tt.body))
			if err == nil {
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
		last time.Time
		now  time.Time
		name string
		want bool
	}{
		{name: "zero last contact", last: time.Time{}, now: last, want: false},
		{name: "same instant", last: last, now: last, want: true},
		{name: "inside window", last: last, now: last.Add(time.Hour), want: true},
		{name: "exactly at ttl", last: last, now: last.Add(ttl), want: true},
		{
			name: "one nanosecond past ttl",
			last: last,
			now:  last.Add(ttl + time.Nanosecond),
			want: false,
		},
		{name: "well past ttl", last: last, now: last.Add(30 * 24 * time.Hour), want: false},
		{name: "small backwards skew", last: last, now: last.Add(-time.Minute), want: true},
		{name: "clock moved far back", last: last, now: last.Add(-24 * time.Hour), want: false},
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

type applyCase struct {
	update proto.Update
	check  func(*testing.T, *Cache)
	name   string
}

func TestApply(t *testing.T) {
	home := true
	rules := proto.Rules{Revision: "r2", Allow: map[string][]string{"t3.z": {"x"}}}
	tests := []applyCase{
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
			update: proto.Update{Home: new(false)},
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
	}

	runApplyCases(t, tests)
}

func TestApplyReplacesTables(t *testing.T) {
	peers := proto.PeerTable{Revision: "p2"}
	revs := proto.Revocations{Revision: "v2", DisabledIdentities: []string{"gone"}}
	bundle := proto.TrustBundle{Revision: "t2", PEM: "pem"}

	tests := []applyCase{
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

	runApplyCases(t, tests)
}

func runApplyCases(t *testing.T, tests []applyCase) {
	t.Helper()

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
	cache := sampleCache(t)
	before := *cache

	cache.Apply(proto.Update{Home: new(false)})

	if !cache.LastHubContact.Equal(before.LastHubContact) ||
		cache.HomeGatewayMAC != before.HomeGatewayMAC ||
		cache.Release != before.Release ||
		cache.Machine != before.Machine {
		t.Fatalf("Apply touched unrelated fields: %+v", cache)
	}
}

func TestApplyHomeCIDRs(t *testing.T) {
	cache := sampleCache(t)
	cache.HomeCIDRs = []string{"192.168.1.0/24"}

	cache.Apply(proto.Update{})

	if len(cache.HomeCIDRs) != 1 {
		t.Fatalf("nil pointer changed cidrs: %v", cache.HomeCIDRs)
	}

	next := []string{"10.0.0.0/8"}
	cache.Apply(proto.Update{HomeCIDRs: &next})

	if len(cache.HomeCIDRs) != 1 || cache.HomeCIDRs[0] != "10.0.0.0/8" {
		t.Fatalf("cidrs = %v", cache.HomeCIDRs)
	}

	cache.Apply(proto.Update{HomeCIDRs: &[]string{}})

	if len(cache.HomeCIDRs) != 0 {
		t.Fatalf("empty pointer did not clear: %v", cache.HomeCIDRs)
	}
}

func TestApplyDeviceLeaves(t *testing.T) {
	cache := &Cache{FormatVersion: FormatVersion}
	leaves := proto.DeviceLeaves{
		Revision: "d1",
		Leaves:   []proto.DeviceLeaf{{Identity: "device-z-phone-mesh", Fingerprint: "aa"}},
	}

	cache.Apply(proto.Update{DeviceLeaves: &leaves})

	if !reflect.DeepEqual(cache.DeviceLeaves, leaves) {
		t.Fatalf("DeviceLeaves = %+v, want %+v", cache.DeviceLeaves, leaves)
	}

	// The cache owns its copy.
	leaves.Leaves[0].Fingerprint = "zz"

	if cache.DeviceLeaves.Leaves[0].Fingerprint != "aa" {
		t.Fatal("the cache shares the update's slice")
	}

	// An update without the field leaves it alone; an empty list replaces it.
	cache.Apply(proto.Update{})

	if cache.DeviceLeaves.Revision != "d1" {
		t.Fatalf("update without leaves changed them: %+v", cache.DeviceLeaves)
	}

	cache.Apply(
		proto.Update{
			DeviceLeaves: &proto.DeviceLeaves{Revision: "d2", Leaves: []proto.DeviceLeaf{}},
		},
	)

	if cache.DeviceLeaves.Revision != "d2" || len(cache.DeviceLeaves.Leaves) != 0 {
		t.Fatalf("empty list did not replace: %+v", cache.DeviceLeaves)
	}
}

func TestApplyAckDeviceLeaves(t *testing.T) {
	cache := &Cache{FormatVersion: FormatVersion}

	// A hub that predates device leaves, or could not tell, sends none: keep the cache.
	cache.ApplyAck(&proto.HelloAck{DeviceLeaves: &proto.DeviceLeaves{
		Revision: "d1",
		Leaves:   []proto.DeviceLeaf{{Identity: "device-z-phone-mesh", Fingerprint: "aa"}},
	}})
	cache.ApplyAck(&proto.HelloAck{})

	if cache.DeviceLeaves.Revision != "d1" || len(cache.DeviceLeaves.Leaves) != 1 {
		t.Fatalf("a HelloAck without leaves cleared them: %+v", cache.DeviceLeaves)
	}

	cache.ApplyAck(&proto.HelloAck{DeviceLeaves: &proto.DeviceLeaves{Revision: "d2", Leaves: nil}})

	if cache.DeviceLeaves.Revision != "d2" || len(cache.DeviceLeaves.Leaves) != 0 {
		t.Fatalf("an empty list did not replace: %+v", cache.DeviceLeaves)
	}
}

// The new field does not change the format: a release before it reads the file,
// and this release reads a file written before it.
func TestDeviceLeavesStayCompatible(t *testing.T) {
	dir := t.TempDir()
	cache := sampleCache(t)
	cache.DeviceLeaves = proto.DeviceLeaves{
		Revision: "d1",
		Leaves:   []proto.DeviceLeaf{{Identity: "device-z-phone-mesh", Fingerprint: "aa"}},
	}

	err := Save(dir, cache)
	if err != nil {
		t.Fatal(err)
	}

	loaded, err := Load(dir)
	if err != nil || !reflect.DeepEqual(loaded.DeviceLeaves, cache.DeviceLeaves) ||
		loaded.FormatVersion != 1 {
		t.Fatalf("round trip: %+v, %v", loaded, err)
	}

	raw, err := os.ReadFile(filepath.Join(dir, "cache.json"))
	if err != nil {
		t.Fatal(err)
	}

	// The cache as the previous release declares it, without the field.
	var legacy struct {
		Machine       string `json:"machine"`
		FormatVersion int    `json:"formatVersion"`
	}

	err = json.Unmarshal(raw, &legacy)
	if err != nil || legacy.Machine != "z-arch" || legacy.FormatVersion != 1 {
		t.Fatalf("previous release cannot read the file: %+v, %v", legacy, err)
	}

	// A file written before the field loads with an empty list, and a cache
	// without leaves does not write the key at all.
	old, err := Load(writeCache(t, `{"formatVersion": 1, "machine": "m"}`))
	if err != nil || old.DeviceLeaves.Revision != "" || len(old.DeviceLeaves.Leaves) != 0 {
		t.Fatalf("old file: %+v, %v", old, err)
	}

	data, err := json.Marshal(&Cache{FormatVersion: 1})
	if err != nil || strings.Contains(string(data), "deviceLeaves") {
		t.Fatalf("empty leaves not omitted: %s (%v)", data, err)
	}
}
