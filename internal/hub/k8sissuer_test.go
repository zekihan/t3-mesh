package hub

import (
	"net/http"
	"slices"
	"testing"

	"github.com/zekihan/t3-mesh/internal/hub/issuer"
	"github.com/zekihan/t3-mesh/internal/hub/issuer/issuertest"
	"github.com/zekihan/t3-mesh/internal/pki"
	"github.com/zekihan/t3-mesh/internal/policy"
	"github.com/zekihan/t3-mesh/internal/proto"
)

// newK8sEnv is a hub whose issuer is the real Kubernetes one, talking to a
// stand-in API that applies the homelab approver-policies: one for the agent
// URIs and one for the enumerated device URIs.
func newK8sEnv(t *testing.T, devices ...string) (*env, *issuertest.API) {
	t.Helper()

	var api *issuertest.API

	harness := newEnvIssuer(t, func(h *env) issuer.Issuer {
		api = issuertest.NewAPI(t, h.ca, issuertest.HomelabPolicies(
			[]string{"agent-devbox", "agent-z-arch"}, []string{devPhone, devTablet},
		))

		return api.NewIssuer(t)
	})
	harness.setConfig(cfgOpts{devices: devices, api: append([]string{"z-phone"}, devices...)})

	return harness, api
}

func (harness *env) enrollDevice(identity string) string {
	harness.t.Helper()

	token, _, err := harness.srv.tokens.Create(identity)
	if err != nil {
		harness.t.Fatal(err)
	}

	enrolled, ok := harness.enrollOver(proto.Enroll{Token: token, CSR: deviceCSR(harness.t, identity)}).(proto.Enrolled)
	if !ok {
		harness.t.Fatalf("enrollment of %s failed", identity)
	}

	certs, err := pki.ParseCertsPEM([]byte(enrolled.Certificate))
	if err != nil {
		harness.t.Fatal(err)
	}

	return pki.Fingerprint(certs[0])
}

// forgetIssued makes the hub behave as if it had just restarted: it has issued
// nothing since it started, so the issuer's records are all it has.
func (harness *env) forgetIssued() {
	harness.srv.nmu.Lock()
	defer harness.srv.nmu.Unlock()

	clear(harness.srv.newest)
	clear(harness.srv.deviceKnown)
}

func TestDeviceLifecycleThroughKubernetesIssuer(t *testing.T) {
	harness, api := newK8sEnv(t, devPhone, devTablet)
	harness.connect("agent-devbox", "devbox-body")

	firstFP := harness.enrollDevice(devPhone)

	// Enrollment asked for exactly what the device policy allows.
	reqs := api.Requests()
	if len(reqs) != 1 {
		t.Fatalf("%d requests after enrollment", len(reqs))
	}

	checkDeviceRequest(t, &reqs[0])

	if code := harness.deviceViewerStatus(devPhone, firstFP); code != http.StatusOK {
		t.Fatalf("enrolled leaf got %d", code)
	}

	// A renewal is the same request with a new key, and supersedes the first leaf.
	resp := harness.renewAs(
		&renewCall{viewer: devPhone, fp: firstFP, body: newDeviceCSR(t, devPhone)},
	)
	if resp.status != http.StatusOK {
		t.Fatalf("renewal: %d %s", resp.status, resp.body)
	}

	secondFP := checkRenewReply(t, harness, resp.body)

	if code := harness.deviceViewerStatus(devPhone, firstFP); code != http.StatusForbidden {
		t.Errorf("superseded leaf got %d", code)
	}

	// After a restart the issuer's own records say the same.
	harness.forgetIssued()

	if code := harness.deviceViewerStatus(devPhone, firstFP); code != http.StatusForbidden {
		t.Errorf("superseded leaf got %d after a restart", code)
	}

	if code := harness.deviceViewerStatus(devPhone, secondFP); code != http.StatusOK {
		t.Errorf("newest leaf got %d after a restart", code)
	}

	// An agent is enrolled through the same issuer with its own usages.
	token, _, err := harness.srv.tokens.Create("agent-z-arch")
	if err != nil {
		t.Fatal(err)
	}

	agentCSR := deviceCSR(t, "agent-z-arch")

	if _, ok := harness.enrollOver(proto.Enroll{Token: token, CSR: agentCSR}).(proto.Enrolled); !ok {
		t.Fatal("agent enrollment failed")
	}

	checkEveryRequestIsOneKind(t, api)
}

func checkDeviceRequest(t *testing.T, req *issuertest.Request) {
	t.Helper()

	if req.Identity != devPhone || req.Duration != "8760h0m0s" || req.IsCA || !req.Approved ||
		req.IssuerRef != [3]string{"clients", "Issuer", "cert-manager.io"} ||
		!slices.Equal(req.Usages, []string{"client auth", "digital signature"}) ||
		len(req.CSR.URIs) != 1 || req.CSR.URIs[0].String() != "urn:noqer:mtls:clients:"+devPhone ||
		len(req.CSR.DNSNames) != 0 {
		t.Fatalf("enrollment request = %+v", req)
	}
}

// Each request the hub created is approved by one policy, and none is denied:
// a request mixing an agent's usages with a device's URI, or the other way
// round, would be allowed by neither.
func checkEveryRequestIsOneKind(t *testing.T, api *issuertest.API) {
	t.Helper()

	reqs := api.Requests()

	var devices, agents int

	for i := range reqs {
		req := &reqs[i]
		serverAuth := slices.Contains(req.Usages, "server auth")

		if !req.Approved {
			t.Errorf("request %s for %s was denied", req.Name, req.Identity)
		}

		if len(req.CSR.URIs) != 1 ||
			req.CSR.URIs[0].String() != "urn:noqer:mtls:clients:"+req.Identity {
			t.Errorf(
				"request %s: URIs %v differ from the identity %s",
				req.Name,
				req.CSR.URIs,
				req.Identity,
			)
		}

		if policy.IsDevice(req.Identity) {
			devices++

			if serverAuth {
				t.Errorf("device request %s asks for server auth", req.Name)
			}

			continue
		}

		agents++

		if !serverAuth {
			t.Errorf("agent request %s lacks server auth", req.Name)
		}
	}

	if devices == 0 || agents == 0 {
		t.Errorf("saw %d device and %d agent requests", devices, agents)
	}
}

// A device the hub is configured for but the approver-policy does not enumerate
// gets no certificate: the policy is the second line behind the hub's config.
func TestDevicePolicyDenialYieldsNoLeaf(t *testing.T) {
	const stranger = "device-z-stranger-mesh"

	harness, api := newK8sEnv(t, devPhone, stranger)

	token, _, err := harness.srv.tokens.Create(stranger)
	if err != nil {
		t.Fatal(err)
	}

	msg := harness.enrollOver(proto.Enroll{Token: token, CSR: deviceCSR(t, stranger)})
	wantEnrollReject(t, msg)

	reqs := api.Requests()
	if len(reqs) != 1 || reqs[0].Approved || reqs[0].Identity != stranger {
		t.Fatalf("requests = %+v", reqs)
	}

	harness.srv.nmu.Lock()
	known := harness.srv.newest[stranger]
	harness.srv.nmu.Unlock()

	if known != "" {
		t.Fatal("the hub recorded a leaf for a denied request")
	}
}
