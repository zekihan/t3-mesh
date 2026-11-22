package policy

import (
	"errors"
	"testing"
	"time"

	"github.com/zekihan/t3-mesh/internal/proto"
)

func TestCheck(t *testing.T) {
	now := time.Date(2026, time.November, 17, 0, 0, 0, 0, time.UTC)
	rules := proto.Rules{Allow: map[string][]string{"t3.devbox": {"z-phone", "agent-z-arch"}}}
	revs := proto.Revocations{
		DisabledIdentities:  []string{"z-tablet"},
		BlockedFingerprints: []string{"aa"},
	}
	ok := Session{
		Identity:    "z-phone",
		Fingerprint: "bb",
		NotAfter:    now.Add(time.Hour),
		Svc:         "t3",
		Machine:     "devbox",
	}

	cases := []struct {
		want error
		mod  func(s *Session)
		name string
	}{
		{name: "allowed", mod: func(*Session) {}, want: nil},
		{name: "disabled", mod: func(s *Session) { s.Identity = "z-tablet" }, want: ErrDisabled},
		{name: "blocked upper", mod: func(s *Session) { s.Fingerprint = "AA" }, want: ErrBlocked},
		{name: "expired", mod: func(s *Session) { s.NotAfter = now }, want: ErrExpired},
		{name: "other machine", mod: func(s *Session) { s.Machine = "z-mac" }, want: ErrNotAllowed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := ok
			tc.mod(&s)

			err := Check(rules, revs, s, now)
			if !errors.Is(err, tc.want) || (tc.want == nil && err != nil) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestIdentityFromURI(t *testing.T) {
	n, err := IdentityFromURI(
		"urn:noqer:mtls:clients:agent-z-mac",
	)
	if err != nil ||
		n != "agent-z-mac" {
		t.Fatalf("got %q, %v", n, err)
	}

	for _, bad := range []string{"urn:noqer:mtls:clients:", "urn:other:x", "urn:noqer:mtls:clients:a:b"} {
		_, err := IdentityFromURI(bad)
		if err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
}

func TestCheckLeafIgnoresRules(t *testing.T) {
	now := time.Date(2026, time.November, 17, 0, 0, 0, 0, time.UTC)
	revs := proto.Revocations{
		DisabledIdentities:  []string{"z-tablet"},
		BlockedFingerprints: []string{"aa"},
	}
	sess := Session{Identity: "z-phone", Fingerprint: "bb", NotAfter: now.Add(time.Hour)}

	err := CheckLeaf(revs, sess, now)
	if err != nil {
		t.Fatalf("unlisted identity refused: %v", err)
	}

	for want, mod := range map[error]func(s *Session){
		ErrDisabled: func(s *Session) { s.Identity = "z-tablet" },
		ErrBlocked:  func(s *Session) { s.Fingerprint = "AA" },
		ErrExpired:  func(s *Session) { s.NotAfter = now },
	} {
		s := sess
		mod(&s)

		err := CheckLeaf(revs, s, now)
		if !errors.Is(err, want) {
			t.Errorf("err = %v, want %v", err, want)
		}
	}
}

func TestIsDevice(t *testing.T) {
	for _, name := range []string{
		"device-z-phone-mesh", "device-z-tablet-mesh", "device-a1-mesh", "device-a-b-c-mesh",
		"device-mesh-mesh",
	} {
		if !IsDevice(name) {
			t.Errorf("IsDevice(%q) = false", name)
		}
	}

	for _, name := range []string{
		"", "z-phone", "z-tablet", "agent-z-mac", "device-mesh", "device--mesh", "device-z-phone",
		"device-z-phone-mesh-", "device-Z-phone-mesh", "device-z_phone-mesh", "device-z-phone-mesh\n",
		"xdevice-z-phone-mesh", "device-z--phone-mesh", "device--z-mesh", "device-z-phone-meshx",
		"agent-device-z-mesh",
	} {
		if IsDevice(name) {
			t.Errorf("IsDevice(%q) = true", name)
		}
	}
}

func TestKindOf(t *testing.T) {
	cases := map[string]struct {
		kind Kind
		ok   bool
	}{
		"agent-z-mac":         {KindAgent, true},
		"device-z-phone-mesh": {KindDevice, true},
		"z-phone":             {"", false},
		"device-z-phone":      {"", false},
		"":                    {"", false},
	}

	for name, want := range cases {
		kind, ok := KindOf(name)
		if kind != want.kind || ok != want.ok {
			t.Errorf("KindOf(%q) = %q, %v; want %q, %v", name, kind, ok, want.kind, want.ok)
		}
	}
}

func TestSplitTarget(t *testing.T) {
	cases := []struct {
		target, svc, machine string
		ok                   bool
	}{
		{"t3.devbox", "t3", "devbox", true},
		{"ssh.z-mac", "ssh", "z-mac", true},
		{"t3", "", "", false},
		{"t3.", "", "", false},
		{".devbox", "", "", false},
		{".", "", "", false},
		{"", "", "", false},
		{"t3.devbox.extra", "", "", false},
		{"t3..devbox", "", "", false},
	}
	for _, tc := range cases {
		svc, machine, ok := SplitTarget(tc.target)
		if svc != tc.svc || machine != tc.machine || ok != tc.ok {
			t.Errorf(
				"SplitTarget(%q) = %q, %q, %v; want %q, %q, %v",
				tc.target, svc, machine, ok, tc.svc, tc.machine, tc.ok,
			)
		}
	}
}

func TestIdentityURI(t *testing.T) {
	if got := IdentityURI("agent-z-mac"); got != "urn:noqer:mtls:clients:agent-z-mac" {
		t.Errorf("IdentityURI = %q", got)
	}

	if got := AgentIdentity("z-mac"); got != "agent-z-mac" {
		t.Errorf("AgentIdentity = %q", got)
	}

	name, err := IdentityFromURI(IdentityURI("device-z-phone-mesh"))
	if err != nil || name != "device-z-phone-mesh" {
		t.Errorf("round trip = %q, %v", name, err)
	}
}

func TestKindsAreDisjoint(t *testing.T) {
	for _, name := range []string{"agent-device-x-mesh", "device-agent-mesh", "agent-x-mesh"} {
		if IsAgent(name) && IsDevice(name) {
			t.Errorf("%q is both an agent and a device", name)
		}
	}
}
