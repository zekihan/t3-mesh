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
