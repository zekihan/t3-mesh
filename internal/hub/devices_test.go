package hub

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/zekihan/t3-mesh/internal/hub/enroll"
	"github.com/zekihan/t3-mesh/internal/pki"
	"github.com/zekihan/t3-mesh/internal/proto"
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

// enrollOver speaks the enrollment protocol as the app does: no client
// certificate, ALPN t3-mesh-enroll/1, one Enroll, one reply.
//
//nolint:ireturn // returns the decoded wire message, whose concrete type the caller inspects
func (harness *env) enrollOver(req proto.Message) proto.Message {
	harness.t.Helper()

	conn, err := harness.dial(nil, proto.ALPNEnroll)
	if err != nil {
		harness.t.Fatal(err)
	}

	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	err = proto.WriteMessage(conn, req)
	if err != nil {
		harness.t.Fatal(err)
	}

	msg, err := proto.ReadMessage(conn, proto.MaxMessageSize)
	if err != nil {
		harness.t.Fatal(err)
	}

	return msg
}

func deviceCSR(t *testing.T, identity string) string {
	t.Helper()

	key, err := pki.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	csr, err := pki.CreateCSR(key, identity)
	if err != nil {
		t.Fatal(err)
	}

	return string(csr)
}

func wantEnrollReject(t *testing.T, msg proto.Message) {
	t.Helper()

	rej, ok := msg.(proto.Reject)
	if !ok || rej.Reason != proto.RejectEnrollFailed {
		t.Fatalf("got %#v, want an enroll-failed Reject", msg)
	}
}

func TestDeviceEnrollmentOverTLS(t *testing.T) {
	harness := newEnv(t)
	harness.setConfig(cfgOpts{devices: bothDevices})

	token, _, err := harness.srv.tokens.Create(devPhone)
	if err != nil {
		t.Fatal(err)
	}

	csr := deviceCSR(t, devPhone)

	enrolled, ok := harness.enrollOver(proto.Enroll{Token: token, CSR: csr}).(proto.Enrolled)
	if !ok {
		t.Fatal("device enrollment failed")
	}

	certs, err := pki.ParseCertsPEM([]byte(enrolled.Certificate))
	if err != nil || len(certs) != 1 {
		t.Fatalf("certs: %v", err)
	}

	leaf := certs[0]

	if id, _ := pki.CertIdentity(leaf); id != devPhone {
		t.Fatalf("identity %q", id)
	}

	err = pki.CheckDeviceLeaf(leaf)
	if err != nil {
		t.Fatalf("leaf usages: %v", err)
	}

	if enrolled.CABundle != string(harness.ca.CertPEM) || enrolled.CARevision != "trust-1" ||
		enrolled.Chain != string(harness.ca.CertPEM) {
		t.Fatalf("reply = %+v", enrolled)
	}

	newest, _ := harness.fake.Newest(t.Context(), devPhone)
	if newest != pki.Fingerprint(leaf) {
		t.Fatalf("newest = %q, want the enrolled leaf", newest)
	}

	// Single use: the same token cannot enroll again. Another device's token keeps
	// the enrollment ALPN open so the replay reaches the handler.
	_, _, err = harness.srv.tokens.Create(devTablet)
	if err != nil {
		t.Fatal(err)
	}

	csr2 := deviceCSR(t, devPhone)
	wantEnrollReject(t, harness.enrollOver(proto.Enroll{Token: token, CSR: csr2}))
}

func TestDeviceEnrollmentRefusals(t *testing.T) {
	cases := []struct {
		name      string
		bound     string
		csrFor    string
		cfg       cfgOpts
		wantIssue bool
	}{
		{
			name:      "ok",
			cfg:       cfgOpts{devices: bothDevices},
			bound:     devPhone,
			csrFor:    devPhone,
			wantIssue: true,
		},
		{
			name:   "token for the other device",
			cfg:    cfgOpts{devices: bothDevices},
			bound:  devPhone,
			csrFor: devTablet,
		},
		{
			name:   "agent token, device CSR",
			cfg:    cfgOpts{devices: bothDevices},
			bound:  "agent-devbox",
			csrFor: devPhone,
		},
		{
			name:   "device token, agent CSR",
			cfg:    cfgOpts{devices: bothDevices},
			bound:  devPhone,
			csrFor: "agent-devbox",
		},
		{
			name:   "device token, KeyChain CSR",
			cfg:    cfgOpts{devices: bothDevices},
			bound:  devPhone,
			csrFor: "z-phone",
		},
		{
			name:   "disabled device",
			cfg:    cfgOpts{devices: bothDevices, disabled: []string{devPhone}},
			bound:  devPhone,
			csrFor: devPhone,
		},
		{name: "device not configured", cfg: cfgOpts{}, bound: devPhone, csrFor: devPhone},
		{
			name:   "other device configured",
			cfg:    cfgOpts{devices: []string{devTablet}},
			bound:  devPhone,
			csrFor: devPhone,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			harness := newEnv(t)
			harness.setConfig(tc.cfg)

			token, _, err := harness.srv.tokens.Create(tc.bound)
			if err != nil {
				t.Fatal(err)
			}

			csr := deviceCSR(t, tc.csrFor)
			msg := harness.enrollOver(proto.Enroll{Token: token, CSR: csr})

			newest, _ := harness.fake.Newest(t.Context(), tc.csrFor)

			if tc.wantIssue {
				if _, ok := msg.(proto.Enrolled); !ok || newest == "" {
					t.Fatalf("got %#v, newest %q", msg, newest)
				}

				return
			}

			wantEnrollReject(t, msg)

			if newest != "" {
				t.Fatal("a certificate was issued")
			}
		})
	}
}
