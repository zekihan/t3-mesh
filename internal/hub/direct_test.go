package hub

import (
	"net/http"
	"net/netip"
	"testing"

	"github.com/zekihan/t3-mesh/internal/hub/hubconfig"
	"github.com/zekihan/t3-mesh/internal/proto"
)

// reportListener has the fake agent say where its listener for enrolled devices is.
func reportListener(t *testing.T, fakeAgent *agent, port int, addrs ...string) {
	t.Helper()

	err := fakeAgent.ctrl.Send(proto.Status{
		Version:        "v0.3.0",
		DeviceListener: &proto.DeviceListener{Port: port, Addrs: addrs},
	})
	if err != nil {
		t.Fatal(err)
	}
}

func machineNamed(t *testing.T, body, name string) apiMachine {
	t.Helper()

	for _, m := range decodeMachines(t, body) {
		if m.Name == name {
			return m
		}
	}

	t.Fatalf("no machine %q in %s", name, body)

	return apiMachine{}
}

func directOf(t *testing.T, harness *env, name string) *apiDirect {
	t.Helper()

	return machineNamed(t, harness.machines("z-phone").body, name).Direct
}

func TestAPIDirectRoute(t *testing.T) {
	harness := newEnv(t)
	harness.setConfig(cfgOpts{api: []string{"z-phone"}})
	arch := harness.connect("agent-z-arch", "arch-body")

	resp := harness.machines("z-phone")
	if resp.status != http.StatusOK {
		t.Fatalf("status %d: %s", resp.status, resp.body)
	}

	// Until the agent reports a bound listener there is no direct route, although
	// the machine is home and online, and the identity is there from the start.
	m := machineNamed(t, resp.body, "z-arch")
	if !m.Online || m.Direct != nil || m.AgentIdentity != "agent-z-arch" {
		t.Fatalf("z-arch before a report = %+v", m)
	}

	reportListener(t, arch, 27443, "127.0.0.5")

	eventually(t, func() bool { return directOf(t, harness, "z-arch") != nil })

	if got := directOf(t, harness, "z-arch"); got.Address != "127.0.0.5" || got.Port != 27443 {
		t.Fatalf("direct = %+v", got)
	}

	checkFleetDirect(t, harness)

	// The key is always present, null when there is no route.
	if !jsonHasNull(t, harness.machines("z-phone").body, "devbox", "direct") {
		t.Fatalf("devbox direct is not an explicit null: %s", harness.machines("z-phone").body)
	}

	// A Status without the listener (it closed) withdraws the route.
	err := arch.ctrl.Send(proto.Status{Version: "v0.3.0"})
	if err != nil {
		t.Fatal(err)
	}

	eventually(t, func() bool { return directOf(t, harness, "z-arch") == nil })
}

// checkFleetDirect expects the fleet to carry the same route as the machine list.
func checkFleetDirect(t *testing.T, harness *env) {
	t.Helper()

	fleet := decodeFleet(t, harness.fleet("z-phone", "127.0.0.9").body)

	for i := range fleet.Machines {
		fm := &fleet.Machines[i]

		switch fm.Name {
		case "z-arch":
			if fm.Direct == nil || fm.Direct.Address != "127.0.0.5" ||
				fm.AgentIdentity != "agent-z-arch" {
				t.Fatalf("fleet z-arch = %+v", fm)
			}
		case "devbox":
			if fm.Direct != nil || fm.AgentIdentity != "agent-devbox" {
				t.Fatalf("fleet devbox = %+v", fm)
			}
		}
	}
}

func TestAPIDirectRouteNeedsHomeAndALiveSession(t *testing.T) {
	harness := newEnv(t)
	harness.setConfig(cfgOpts{api: []string{"z-phone"}})
	arch := harness.connect("agent-z-arch", "arch-body")

	reportListener(t, arch, 27443, "127.0.0.5")

	eventually(t, func() bool { return directOf(t, harness, "z-arch") != nil })

	// The hub no longer considers the machine's tunnel source home: no route, even
	// though the agent still says it listens.
	harness.setConfig(cfgOpts{api: []string{"z-phone"}, noCIDRs: true})

	eventually(t, func() bool {
		m := machineNamed(t, harness.machines("z-phone").body, "z-arch")

		return m.Online && m.Direct == nil
	})

	harness.setConfig(cfgOpts{api: []string{"z-phone"}})

	eventually(t, func() bool { return directOf(t, harness, "z-arch") != nil })

	// Offline: none.
	arch.close()

	eventually(t, func() bool {
		m := machineNamed(t, harness.machines("z-phone").body, "z-arch")

		return !m.Online && m.Direct == nil
	})
}

// The route is the newest live session's report, never an older session's.
func TestAPIDirectRouteIsPerSession(t *testing.T) {
	harness := newEnv(t)
	harness.setConfig(cfgOpts{api: []string{"z-phone"}})
	first := harness.connect("agent-z-arch", "arch-body")

	reportListener(t, first, 27443, "127.0.0.5")

	eventually(t, func() bool { return directOf(t, harness, "z-arch") != nil })

	second := harness.connect("agent-z-arch", "arch-body")

	eventually(t, func() bool { return directOf(t, harness, "z-arch") == nil })

	reportListener(t, second, 27444, "127.0.0.6")

	eventually(t, func() bool {
		got := directOf(t, harness, "z-arch")

		return got != nil && got.Address == "127.0.0.6" && got.Port == 27444
	})
}

func TestStatusShowsTheDeviceListener(t *testing.T) {
	harness := newEnv(t)
	arch := harness.connect("agent-z-arch", "arch-body")

	err := arch.ctrl.Send(proto.Status{
		Version:        "v0.3.0",
		DeviceSessions: 2,
		DeviceListener: &proto.DeviceListener{
			Port:  27443,
			Addrs: []string{"192.168.2.71", "fd12::71"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	eventually(t, func() bool {
		var st struct {
			Machines map[string]struct {
				DeviceListener *proto.DeviceListener `json:"deviceListener"`
				DeviceSessions int                   `json:"deviceSessions"`
			} `json:"machines"`
		}

		getJSON(t, harness.ops.URL+"/status", &st)

		got := st.Machines["z-arch"]

		return got.DeviceSessions == 2 && got.DeviceListener != nil &&
			got.DeviceListener.Port == 27443 &&
			len(got.DeviceListener.Addrs) == 2
	})
}

func TestSanitizeDeviceListener(t *testing.T) {
	t.Parallel()

	tests := []struct {
		in   *proto.DeviceListener
		want *proto.DeviceListener
		name string
	}{
		{name: "nothing", in: nil, want: nil},
		{name: "no port", in: &proto.DeviceListener{Addrs: []string{"192.168.1.5"}}},
		{
			name: "port too big",
			in:   &proto.DeviceListener{Port: 70000, Addrs: []string{"192.168.1.5"}},
		},
		{
			name: "no usable address",
			in:   &proto.DeviceListener{Port: 27443, Addrs: []string{"nope", ""}},
		},
		{
			name: "normalized and deduplicated",
			in: &proto.DeviceListener{
				Port: 27443,
				Addrs: []string{
					"192.168.1.5",
					"::ffff:192.168.1.5",
					"bad",
					"fe80::1%eth0",
					"fd12::71",
				},
			},
			want: &proto.DeviceListener{
				Port:  27443,
				Addrs: []string{"192.168.1.5", "fe80::1", "fd12::71"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := sanitizeDeviceListener(tt.in)

			switch {
			case tt.want == nil && got != nil:
				t.Fatalf("got %+v, want nil", got)
			case tt.want != nil && (got == nil || got.Port != tt.want.Port ||
				!equalStrings(got.Addrs, tt.want.Addrs)):
				t.Fatalf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestSanitizeDeviceListenerBoundsTheList(t *testing.T) {
	t.Parallel()

	in := &proto.DeviceListener{Port: 27443}
	for i := range 40 {
		in.Addrs = append(in.Addrs, netip.AddrFrom4([4]byte{192, 168, 1, byte(i + 1)}).String())
	}

	got := sanitizeDeviceListener(in)
	if got == nil || len(got.Addrs) != maxLANAddrs {
		t.Fatalf("got %+v, want %d addresses", got, maxLANAddrs)
	}
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}

	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}

	return true
}

func TestDirectRouteChoosesTheHomeAddress(t *testing.T) {
	t.Parallel()

	snap := &hubconfig.Snapshot{HomePrefixes: []netip.Prefix{
		netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("fd12:3456:789a:1::/64"),
	}}

	tests := []struct {
		name   string
		source string
		want   string
		addrs  []string
	}{
		{name: "one address", addrs: []string{"127.0.0.5"}, want: "127.0.0.5"},
		{
			name:  "lowest when nothing else decides",
			addrs: []string{"127.0.0.9", "127.0.0.5"},
			want:  "127.0.0.5",
		},
		{
			name:  "IPv4 over IPv6",
			addrs: []string{"fd12:3456:789a:1::71", "127.0.0.9"},
			want:  "127.0.0.9",
		},
		{
			name:   "the tunnel source wins within the family",
			addrs:  []string{"127.0.0.2", "127.0.0.9"},
			source: "127.0.0.9",
			want:   "127.0.0.9",
		},
		{
			name:   "the source does not beat the family order",
			addrs:  []string{"fd12:3456:789a:1::71", "127.0.0.9"},
			source: "fd12:3456:789a:1::71",
			want:   "127.0.0.9",
		},
		{
			name: "IPv6 when it is all there is", addrs: []string{"fd12:3456:789a:1::71"},
			want: "fd12:3456:789a:1::71",
		},
		{name: "link-local IPv6 is not a route", addrs: []string{"fe80::1"}},
		{
			name:  "addresses outside the home prefixes are dropped",
			addrs: []string{"192.168.1.5", "127.0.0.7"},
			want:  "127.0.0.7",
		},
		{name: "only foreign addresses", addrs: []string{"192.168.1.5", "10.0.0.1"}},
		{name: "unspecified and multicast", addrs: []string{"0.0.0.0", "224.0.0.1"}},
		{name: "unparsable", addrs: []string{"not-an-ip"}},
		{name: "no addresses"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var source netip.Addr
			if tt.source != "" {
				source = netip.MustParseAddr(tt.source)
			}

			got := directRoute(snap, &proto.DeviceListener{Port: 27443, Addrs: tt.addrs}, source)

			if tt.want == "" {
				if got != nil {
					t.Fatalf("route = %+v, want none", got)
				}

				return
			}

			if got == nil || got.Address != tt.want || got.Port != 27443 {
				t.Fatalf("route = %+v, want %s:27443", got, tt.want)
			}
		})
	}

	if directRoute(snap, nil, netip.Addr{}) != nil {
		t.Fatal("a route without a report")
	}
}
