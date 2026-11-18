package hub

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
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

var (
	bothDevices = []string{devPhone, devTablet}

	errLookupBoom = errors.New("issuer unavailable")
)

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

// newDeviceFP issues a leaf for identity, as the hub does: the issuer and the
// hub's own record both name it the newest. It returns the fingerprint.
func (harness *env) newDeviceFP(identity string) string {
	harness.t.Helper()

	cert := harness.newCert(identity, farFuture)
	fp := pki.Fingerprint(cert.Leaf)
	harness.srv.setNewest(identity, fp)

	return fp
}

func (harness *env) deviceViewerStatus(identity, fp string) int {
	harness.t.Helper()

	code, _ := harness.get("t3.devbox.mesh.test", identity, fp, farFuture, "/hdr")

	return code
}

func (harness *env) deviceAPIStatus(identity, fp, path string) int {
	harness.t.Helper()

	return harness.api(http.MethodGet, apiHost, identity, fp, farFuture, path).status
}

func deviceEnv(t *testing.T) *env {
	t.Helper()

	harness := newEnv(t)
	harness.setConfig(
		cfgOpts{devices: bothDevices, api: append([]string{"z-phone"}, bothDevices...)},
	)
	harness.connect("agent-devbox", "devbox-body")

	return harness
}

func TestDeviceViewerAdmitsOnlyNewestLeaf(t *testing.T) {
	harness := deviceEnv(t)

	oldFP := harness.newDeviceFP(devPhone)
	if code := harness.deviceViewerStatus(devPhone, oldFP); code != http.StatusOK {
		t.Fatalf("newest leaf got %d", code)
	}

	newFP := harness.newDeviceFP(devPhone)
	if code := harness.deviceViewerStatus(devPhone, oldFP); code != http.StatusForbidden {
		t.Fatalf("superseded leaf got %d", code)
	}

	if code := harness.deviceViewerStatus(devPhone, newFP); code != http.StatusOK {
		t.Fatalf("new leaf got %d", code)
	}

	// One device's renewal never supersedes the other's.
	tabletFP := harness.newDeviceFP(devTablet)
	if code := harness.deviceViewerStatus(devTablet, tabletFP); code != http.StatusOK {
		t.Fatalf("tablet leaf got %d", code)
	}

	if code := harness.deviceViewerStatus(devPhone, newFP); code != http.StatusOK {
		t.Fatalf("phone leaf got %d after the tablet's issuance", code)
	}
}

func TestDeviceAPIAdmitsOnlyNewestLeaf(t *testing.T) {
	harness := deviceEnv(t)

	oldFP := harness.newDeviceFP(devPhone)
	newFP := harness.newDeviceFP(devPhone)

	for _, path := range []string{"/api/v1/machines", "/api/v1/fleet"} {
		if code := harness.deviceAPIStatus(devPhone, newFP, path); code != http.StatusOK {
			t.Errorf("GET %s with the newest leaf = %d", path, code)
		}

		if code := harness.deviceAPIStatus(devPhone, oldFP, path); code != http.StatusForbidden {
			t.Errorf("GET %s with a superseded leaf = %d", path, code)
		}
	}
}

func TestDeviceNotConfiguredIsRefused(t *testing.T) {
	harness := newEnv(t)
	harness.setConfig(cfgOpts{devices: []string{devTablet}, api: bothDevices})
	harness.connect("agent-devbox", "devbox-body")

	fp := harness.newDeviceFP(devPhone)

	if code := harness.deviceViewerStatus(devPhone, fp); code != http.StatusForbidden {
		t.Errorf("viewer: unconfigured device got %d", code)
	}

	if code := harness.deviceAPIStatus(
		devPhone,
		fp,
		"/api/v1/machines",
	); code != http.StatusForbidden {
		t.Errorf("API: unconfigured device got %d", code)
	}
}

// With no devices configured, device enrollment is off and no such leaf is admitted.
func TestDeviceIdentitiesNeedTheDevicesList(t *testing.T) {
	harness := newEnv(t)
	harness.setConfig(cfgOpts{api: []string{devPhone}})
	harness.connect("agent-devbox", "devbox-body")

	fp := harness.newDeviceFP(devPhone)

	if code := harness.deviceViewerStatus(devPhone, fp); code != http.StatusForbidden {
		t.Errorf("viewer got %d", code)
	}

	if code := harness.deviceAPIStatus(
		devPhone,
		fp,
		"/api/v1/machines",
	); code != http.StatusForbidden {
		t.Errorf("API got %d", code)
	}
}

// As for agents, a leaf the issuer has no record of is admitted (and logged).
func TestDeviceWithoutIssuanceRecordIsAdmitted(t *testing.T) {
	harness := deviceEnv(t)

	if code := harness.deviceViewerStatus(
		devPhone,
		strings.Repeat("c", 64),
	); code != http.StatusOK {
		t.Fatalf("viewer got %d", code)
	}
}

func TestDeviceCheckUnavailable(t *testing.T) {
	harness := deviceEnv(t)
	fp := harness.newDeviceFP(devPhone)

	harness.fake.SetNewestErr(errLookupBoom)

	other := strings.Repeat("d", 64)
	if code := harness.deviceViewerStatus(devPhone, other); code != http.StatusServiceUnavailable {
		t.Errorf("viewer got %d", code)
	}

	if code := harness.deviceAPIStatus(
		devPhone,
		other,
		"/api/v1/machines",
	); code != http.StatusServiceUnavailable {
		t.Errorf("API got %d", code)
	}

	// What the hub already knows needs no lookup.
	if code := harness.deviceViewerStatus(devPhone, fp); code != http.StatusOK {
		t.Errorf("known leaf got %d while the issuer was down", code)
	}

	harness.fake.SetNewestErr(nil)

	if code := harness.deviceViewerStatus(devPhone, other); code != http.StatusForbidden {
		t.Errorf("superseded leaf got %d after recovery", code)
	}
}

// A hub that restarted knows nothing yet: the issuer decides, and what it says
// is remembered.
func TestDeviceNewestAfterHubRestart(t *testing.T) {
	harness := deviceEnv(t)

	oldCert := harness.newCert(devPhone, farFuture)
	newCert := harness.newCert(
		devPhone,
		farFuture,
	) // the issuer's newest; the hub's record is empty
	oldFP, newFP := pki.Fingerprint(oldCert.Leaf), pki.Fingerprint(newCert.Leaf)

	if code := harness.deviceViewerStatus(devPhone, oldFP); code != http.StatusForbidden {
		t.Errorf("superseded leaf got %d", code)
	}

	if code := harness.deviceViewerStatus(devPhone, newFP); code != http.StatusOK {
		t.Errorf("newest leaf got %d", code)
	}
}

func TestSupersededLeafClosesOpenStream(t *testing.T) {
	harness := deviceEnv(t)
	harness.setConfig(cfgOpts{devices: bothDevices, api: bothDevices})

	phoneFP := harness.newDeviceFP(devPhone)
	tabletFP := harness.newDeviceFP(devTablet)

	phoneStream, closePhone := openStreamAs(t, harness, devPhone, phoneFP, "/stream", farFuture)
	defer closePhone()

	tabletStream, closeTablet := openStreamAs(t, harness, devTablet, tabletFP, "/stream", farFuture)
	defer closeTablet()

	// The device renews through enrollment: the old leaf's stream ends at once.
	token, _, err := harness.srv.tokens.Create(devPhone)
	if err != nil {
		t.Fatal(err)
	}

	enrolled, ok := harness.enrollOver(proto.Enroll{Token: token, CSR: deviceCSR(t, devPhone)}).(proto.Enrolled)
	if !ok {
		t.Fatal("enrollment failed")
	}

	expectStreamClosed(t, phoneStream)

	certs, err := pki.ParseCertsPEM([]byte(enrolled.Certificate))
	if err != nil {
		t.Fatal(err)
	}

	if code := harness.deviceViewerStatus(devPhone, phoneFP); code != http.StatusForbidden {
		t.Errorf("old leaf got %d", code)
	}

	if code := harness.deviceViewerStatus(
		devPhone,
		pki.Fingerprint(certs[0]),
	); code != http.StatusOK {
		t.Errorf("new leaf got %d", code)
	}

	// The other device's stream is untouched.
	expectStreamOpen(t, tabletStream)

	if code := harness.deviceViewerStatus(devTablet, tabletFP); code != http.StatusOK {
		t.Errorf("tablet got %d", code)
	}
}

func expectStreamOpen(t *testing.T, r io.Reader) {
	t.Helper()

	done := make(chan struct{})

	go func() {
		_, _ = io.Copy(io.Discard, r)

		close(done)
	}()

	select {
	case <-done:
		t.Fatal("stream was closed")
	case <-time.After(600 * time.Millisecond):
	}
}

func TestRemovedDeviceClosesOpenStream(t *testing.T) {
	harness := deviceEnv(t)
	fp := harness.newDeviceFP(devPhone)

	stream, closeFn := openStreamAs(t, harness, devPhone, fp, "/stream", farFuture)
	defer closeFn()

	harness.setConfig(cfgOpts{devices: []string{devTablet}, api: bothDevices})
	expectStreamClosed(t, stream)
}

func TestDisabledAndBlockedDeviceRefused(t *testing.T) {
	harness := deviceEnv(t)
	fp := harness.newDeviceFP(devPhone)

	harness.setConfig(cfgOpts{devices: bothDevices, api: bothDevices, disabled: []string{devPhone}})

	if code := harness.deviceViewerStatus(devPhone, fp); code != http.StatusForbidden {
		t.Errorf("disabled device on a viewer host got %d", code)
	}

	harness.setConfig(cfgOpts{devices: bothDevices, api: bothDevices, blocked: []string{fp}})

	if code := harness.deviceViewerStatus(devPhone, fp); code != http.StatusForbidden {
		t.Errorf("blocked leaf on a viewer host got %d", code)
	}

	if code := harness.deviceAPIStatus(
		devPhone,
		fp,
		"/api/v1/machines",
	); code != http.StatusForbidden {
		t.Errorf("blocked leaf on the API got %d", code)
	}
}

// An enrolled device is a viewer. It never reaches the agent tunnel, which
// relays between machines without the viewer controls.
func TestDeviceCertCannotOpenTunnel(t *testing.T) {
	harness := deviceEnv(t)

	cert := harness.newCert(devPhone, farFuture)

	conn, err := harness.dial(&cert, proto.TunnelALPN(1))
	if err == nil {
		defer func() { _ = conn.Close() }()

		_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))

		_, rerr := conn.Read(make([]byte, 1))

		var netErr net.Error
		if rerr == nil || (errors.As(rerr, &netErr) && netErr.Timeout()) {
			t.Fatalf("tunnel connection was not refused: %v", rerr)
		}
	}

	_, err = harness.connectWith(devPhone, &cert, "x")
	if err == nil {
		t.Fatal("device certificate opened a tunnel")
	}
}

func leavesOf(dl *proto.DeviceLeaves) map[string]string {
	out := map[string]string{}
	if dl == nil {
		return out
	}

	for _, leaf := range dl.Leaves {
		out[leaf.Identity] = leaf.Fingerprint
	}

	return out
}

// nextDeviceLeaves waits for an Update that carries the device leaves.
func (fakeAgent *agent) nextDeviceLeaves() proto.Update {
	fakeAgent.t.Helper()

	msg := fakeAgent.next(func(m proto.Message) bool {
		upd, ok := m.(proto.Update)

		return ok && upd.DeviceLeaves != nil
	})

	upd, _ := msg.(proto.Update)

	return upd
}

func TestAgentsGetDeviceLeavesInHelloAck(t *testing.T) {
	harness := newEnv(t)
	harness.setConfig(cfgOpts{devices: bothDevices})

	// The phone has a leaf, the tablet has none yet.
	phoneFP := harness.newDeviceFP(devPhone)
	arch := harness.connect("agent-z-arch", "arch-body")

	got := arch.ack.DeviceLeaves
	if got == nil || got.Revision == "" ||
		!maps.Equal(leavesOf(got), map[string]string{devPhone: phoneFP}) {
		t.Fatalf("ack.DeviceLeaves = %+v", got)
	}
}

// A hub that restarted has issued nothing yet; the issuer's record is used.
func TestDeviceLeavesLookedUpAfterRestart(t *testing.T) {
	harness := newEnv(t)
	harness.setConfig(cfgOpts{devices: bothDevices})

	cert := harness.newCert(devTablet, farFuture) // known to the issuer only
	arch := harness.connect("agent-z-arch", "arch-body")

	want := map[string]string{devTablet: pki.Fingerprint(cert.Leaf)}
	if got := leavesOf(arch.ack.DeviceLeaves); !maps.Equal(got, want) {
		t.Fatalf("leaves = %v, want %v", got, want)
	}
}

func TestNoDevicesMeansAnEmptyList(t *testing.T) {
	harness := newEnv(t)
	arch := harness.connect("agent-z-arch", "arch-body")

	got := arch.ack.DeviceLeaves
	if got == nil || len(got.Leaves) != 0 || got.Revision == "" {
		t.Fatalf("ack.DeviceLeaves = %+v", got)
	}

	// On the wire an empty list is [], not null.
	data, err := json.Marshal(got)
	if err != nil || !strings.Contains(string(data), `"leaves":[]`) {
		t.Fatalf("wire = %s (%v)", data, err)
	}
}

func TestDeviceLeavesPushedOnRenewal(t *testing.T) {
	harness, oldFP := renewEnv(t)
	arch := harness.connect("agent-z-arch", "arch-body")

	if got := leavesOf(arch.ack.DeviceLeaves); got[devPhone] != oldFP {
		t.Fatalf("initial leaves = %v", got)
	}

	resp := harness.renewAs(
		&renewCall{viewer: devPhone, fp: oldFP, body: newDeviceCSR(t, devPhone)},
	)
	if resp.status != http.StatusOK {
		t.Fatalf("renewal: %d %s", resp.status, resp.body)
	}

	newFP := checkRenewReply(t, harness, resp.body)
	upd := arch.nextDeviceLeaves()

	if got := leavesOf(upd.DeviceLeaves); !maps.Equal(got, map[string]string{devPhone: newFP}) {
		t.Fatalf("pushed leaves = %v, want the new leaf %s", got, newFP)
	}

	// Only what changed is sent.
	if upd.Rules != nil || upd.Revocations != nil || upd.TrustBundle != nil || upd.Peers != nil {
		t.Errorf("update carries more than the device leaves: %+v", upd)
	}

	if upd.DeviceLeaves.Revision == arch.ack.DeviceLeaves.Revision {
		t.Error("the revision did not change with the leaf")
	}
}

func TestDeviceLeavesPushedOnEnrollment(t *testing.T) {
	harness := newEnv(t)
	harness.setConfig(cfgOpts{devices: bothDevices})

	phoneFP := harness.newDeviceFP(devPhone)
	arch := harness.connect("agent-z-arch", "arch-body")

	token, _, err := harness.srv.tokens.Create(devTablet)
	if err != nil {
		t.Fatal(err)
	}

	enrolled, ok := harness.enrollOver(proto.Enroll{Token: token, CSR: deviceCSR(t, devTablet)}).(proto.Enrolled)
	if !ok {
		t.Fatal("enrollment failed")
	}

	certs, err := pki.ParseCertsPEM([]byte(enrolled.Certificate))
	if err != nil {
		t.Fatal(err)
	}

	want := map[string]string{devPhone: phoneFP, devTablet: pki.Fingerprint(certs[0])}
	if got := leavesOf(arch.nextDeviceLeaves().DeviceLeaves); !maps.Equal(got, want) {
		t.Fatalf("pushed leaves = %v, want %v", got, want)
	}
}

func TestDeviceLeavesFollowTheConfig(t *testing.T) {
	harness := newEnv(t)
	harness.setConfig(cfgOpts{devices: bothDevices})

	phoneFP := harness.newDeviceFP(devPhone)
	tabletFP := harness.newDeviceFP(devTablet)
	arch := harness.connect("agent-z-arch", "arch-body")

	// A device that is no longer configured is dropped from every agent.
	harness.setConfig(cfgOpts{devices: []string{devTablet}})

	got := leavesOf(arch.nextDeviceLeaves().DeviceLeaves)
	if !maps.Equal(got, map[string]string{devTablet: tabletFP}) {
		t.Fatalf("after removal: %v", got)
	}

	harness.setConfig(cfgOpts{devices: bothDevices})

	got = leavesOf(arch.nextDeviceLeaves().DeviceLeaves)
	if !maps.Equal(got, map[string]string{devPhone: phoneFP, devTablet: tabletFP}) {
		t.Fatalf("after re-adding: %v", got)
	}
}

// When the issuer cannot say, the agent keeps what it has: an empty list would
// take a device's direct access away because of an outage.
func TestDeviceLeavesLookupFailureSendsNothing(t *testing.T) {
	harness := newEnv(t)
	arch := harness.connect("agent-z-arch", "arch-body")

	harness.fake.SetNewestErr(errLookupBoom)
	harness.setConfig(cfgOpts{devices: bothDevices})

	select {
	case m := <-arch.msgs:
		if upd, ok := m.(proto.Update); ok && upd.DeviceLeaves != nil {
			t.Fatalf("the hub pushed %+v without knowing the leaves", upd.DeviceLeaves)
		}
	case <-time.After(700 * time.Millisecond):
	}

	// Once the issuer answers, the next push carries the list.
	phone := harness.newCert(devPhone, farFuture)
	harness.fake.SetNewestErr(nil)
	harness.setConfig(cfgOpts{devices: bothDevices, disabled: []string{"z-unrelated"}})

	got := leavesOf(arch.nextDeviceLeaves().DeviceLeaves)
	if !maps.Equal(got, map[string]string{devPhone: pki.Fingerprint(phone.Leaf)}) {
		t.Fatalf("leaves after recovery = %v", got)
	}
}

func TestStatusShowsAckedDeviceLeaves(t *testing.T) {
	harness := newEnv(t)
	harness.setConfig(cfgOpts{devices: bothDevices})
	harness.newDeviceFP(devPhone)

	arch := harness.connect("agent-z-arch", "arch-body")
	rev := arch.ack.DeviceLeaves.Revision

	err := arch.ctrl.Send(proto.Status{DeviceLeavesRevision: rev, Version: "v0.2.0"})
	if err != nil {
		t.Fatal(err)
	}

	eventually(t, func() bool {
		var doc statusDoc

		getJSON(t, harness.ops.URL+"/status", &doc)

		return doc.DeviceLeaves == rev && doc.Machines["z-arch"].Acked.DeviceLeaves == rev
	})
}
