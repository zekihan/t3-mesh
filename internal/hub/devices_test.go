package hub

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/zekihan/t3-mesh/internal/hub/enroll"
)

const (
	devPhone  = "device-z-phone-mesh"
	devTablet = "device-z-tablet-mesh"
)

var bothDevices = []string{devPhone, devTablet}

func TestEnrollTokenKinds(t *testing.T) {
	harness := newEnv(t)
	harness.setConfig(
		cfgOpts{devices: bothDevices, disabled: []string{"device-off-mesh", "agent-z-arch"}},
	)

	cases := []struct {
		name     string
		kind     string
		identity string
		ok       bool
	}{
		{"agent", enroll.KindAgent, "agent-devbox", true},
		{"unknown agent", enroll.KindAgent, "agent-ghost", false},
		{"device name as agent", enroll.KindAgent, devPhone, false},
		{"KeyChain identity as agent", enroll.KindAgent, "z-phone", false},
		{"disabled agent", enroll.KindAgent, "agent-z-arch", false},
		{"device", enroll.KindDevice, devPhone, true},
		{"other device", enroll.KindDevice, devTablet, true},
		{"unknown device", enroll.KindDevice, "device-ghost-mesh", false},
		{"agent name as device", enroll.KindDevice, "agent-devbox", false},
		{"KeyChain identity as device", enroll.KindDevice, "z-phone", false},
		{"device lookalike", enroll.KindDevice, "device-z-phone", false},
		{"no kind", "", devPhone, false},
		{"unknown kind", "phone", devPhone, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := harness.srv.EnrollTokenAllowed(tc.kind, tc.identity)
			if (err == nil) != tc.ok {
				t.Fatalf(
					"EnrollTokenAllowed(%q, %q) = %v, want ok=%v",
					tc.kind,
					tc.identity,
					err,
					tc.ok,
				)
			}
		})
	}
}

func TestEnrollTokenKindsOnDisabledDevice(t *testing.T) {
	harness := newEnv(t)
	harness.setConfig(cfgOpts{devices: bothDevices, disabled: []string{devTablet}})

	err := harness.srv.EnrollTokenAllowed(enroll.KindDevice, devTablet)
	if err == nil {
		t.Error("token allowed for a disabled device")
	}

	err = harness.srv.EnrollTokenAllowed(enroll.KindDevice, devPhone)
	if err != nil {
		t.Errorf("token refused for an enabled device: %v", err)
	}
}

func TestNoDevicesMeansNoDeviceTokens(t *testing.T) {
	harness := newEnv(t)

	for _, id := range bothDevices {
		err := harness.srv.EnrollTokenAllowed(enroll.KindDevice, id)
		if err == nil {
			t.Errorf("token allowed for %s with no devices configured", id)
		}

		err = harness.srv.EnrollAllowed(id)
		if err == nil {
			t.Errorf("%s may enroll with no devices configured", id)
		}
	}
}

func TestEnrollAllowedDevices(t *testing.T) {
	harness := newEnv(t)
	harness.setConfig(cfgOpts{devices: bothDevices, disabled: []string{devTablet}})

	for id, ok := range map[string]bool{
		"agent-devbox":      true,
		"agent-z-arch":      true,
		devPhone:            true,
		devTablet:           false, // disabled
		"device-ghost-mesh": false,
		"z-phone":           false,
		"agent-ghost":       false,
	} {
		err := harness.srv.EnrollAllowed(id)
		if (err == nil) != ok {
			t.Errorf("EnrollAllowed(%q) = %v, want ok=%v", id, err, ok)
		}
	}
}

// The enroll-token command talks to the hub's admin socket; the same refusals
// must come back through it.
func TestEnrollTokenOverAdminSocket(t *testing.T) {
	harness := newEnv(t)
	harness.setConfig(cfgOpts{devices: bothDevices})

	path := filepath.Join(t.TempDir(), "admin.sock")
	admin := &enroll.Admin{
		Path:    path,
		Tokens:  harness.srv.tokens,
		Allowed: harness.srv.EnrollTokenAllowed,
	}

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)

	go func() { done <- admin.Serve(ctx) }()

	t.Cleanup(func() {
		cancel()

		err := <-done
		if err != nil {
			t.Error(err)
		}
	})

	eventually(t, func() bool {
		_, err := os.Stat(path)

		return err == nil
	})

	deadline, cancelReq := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancelReq()

	for _, bad := range []struct{ kind, identity string }{
		{enroll.KindAgent, devPhone},
		{enroll.KindDevice, "agent-devbox"},
		{enroll.KindDevice, "device-ghost-mesh"},
		{enroll.KindDevice, "z-phone"},
	} {
		_, _, err := enroll.RequestToken(deadline, path, bad.kind, bad.identity)
		if err == nil {
			t.Errorf("token minted for %s as %s", bad.identity, bad.kind)
		}
	}

	if harness.srv.tokens.Outstanding() {
		t.Fatal("a refused request left a token outstanding")
	}

	for _, good := range []struct{ kind, identity string }{
		{enroll.KindDevice, devPhone},
		{enroll.KindAgent, "agent-devbox"},
	} {
		token, _, err := enroll.RequestToken(deadline, path, good.kind, good.identity)
		if err != nil {
			t.Fatal(err)
		}

		id, err := harness.srv.tokens.Redeem(token)
		if err != nil || id != good.identity {
			t.Fatalf("redeem = %q, %v", id, err)
		}
	}
}
