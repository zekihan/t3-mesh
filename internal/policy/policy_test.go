package policy

import (
	"errors"
	"testing"
	"time"

	"github.com/zekihan/t3-mesh/internal/proto"
)

func TestCheck(t *testing.T) {
	now := time.Date(2026, 11, 17, 0, 0, 0, 0, time.UTC)
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
		name string
		mod  func(s *Session)
		want error
	}{
		{"allowed", func(*Session) {}, nil},
		{"disabled", func(s *Session) { s.Identity = "z-tablet" }, ErrDisabled},
		{"blocked upper", func(s *Session) { s.Fingerprint = "AA" }, ErrBlocked},
		{"expired", func(s *Session) { s.NotAfter = now }, ErrExpired},
		{"other machine", func(s *Session) { s.Machine = "z-mac" }, ErrNotAllowed},
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
	if n, err := IdentityFromURI(
		"urn:noqer:mtls:clients:agent-z-mac",
	); err != nil ||
		n != "agent-z-mac" {
		t.Fatalf("got %q, %v", n, err)
	}
	for _, bad := range []string{"urn:noqer:mtls:clients:", "urn:other:x", "urn:noqer:mtls:clients:a:b"} {
		if _, err := IdentityFromURI(bad); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
}
