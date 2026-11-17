package integration

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/yamux"

	"github.com/zekihan/t3-mesh/internal/agent"
	"github.com/zekihan/t3-mesh/internal/pki"
	"github.com/zekihan/t3-mesh/internal/pki/pkitest"
	"github.com/zekihan/t3-mesh/internal/proto"
	"github.com/zekihan/t3-mesh/internal/tunnel"
)

// Broken-release scenarios (a release that crashes, one that hangs before the
// link ports are bound, one whose serve target is stopped, launcher fallback to
// previous-good, a missing HelloAck being retried) are covered in
// internal/agent/updater and internal/launcher, not here.

// skipNoDirect skips a scenario that needs a direct listener the host cannot
// provide; see loopbackHello.
func skipNoDirect(t *testing.T, m *mesh) {
	t.Helper()

	if !m.direct.IsValid() {
		t.Skip("BLOCKED: no private LAN IPv4 address and the agent does not advertise loopback direct addresses (internal/agent/tunnel.go lanAddrs drops IsLoopback)")
	}
}

// expectRefused asserts the hub closes a connection made with c (or never
// completed the handshake): in TLS 1.3 the client's handshake finishes before
// the server judges the client certificate, so refusal shows up on first read.
func expectRefused(t *testing.T, c *tls.Conn, dialErr error) {
	t.Helper()

	if dialErr != nil {
		return
	}

	defer func() { _ = c.Close() }()

	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))

	buf := make([]byte, 1)

	_, err := c.Read(buf)
	if err == nil {
		t.Fatal("hub kept the connection and sent data, want refusal")
	}

	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		t.Fatal("hub kept the connection open, want refusal")
	}
}

// tryTunnel opens a tunnel with cert and returns the hub's first reply.
func (m *mesh) tryTunnel(cert tls.Certificate) proto.Message {
	m.t.Helper()

	c, err := m.rawDial(&cert, proto.TunnelALPN(proto.ProtocolVersion))
	if err != nil {
		m.t.Fatalf("tunnel dial: %v", err)
	}

	defer func() { _ = c.Close() }()

	ymx, err := yamux.Client(c, tunnel.YamuxConfig())
	if err != nil {
		m.t.Fatal(err)
	}

	defer func() { _ = ymx.Close() }()

	st, err := ymx.OpenStream()
	if err != nil {
		m.t.Fatal(err)
	}

	ctrl := tunnel.NewControl(st)

	if err = ctrl.Send(proto.Hello{Version: "v0.0.0", Services: []string{"t3"}, CertFingerprint: pki.Fingerprint(cert.Leaf)}); err != nil {
		m.t.Fatal(err)
	}

	select {
	case msg, ok := <-ctrl.Messages():
		if !ok {
			m.t.Fatal("control stream closed without a reply")
		}

		return msg
	case <-time.After(5 * time.Second):
		m.t.Fatal("no reply to Hello")
	}

	return nil
}

func (m *mesh) twoNodes(a, b nodeOpts) (*node, *node) {
	m.t.Helper()

	nb := m.newNode("b", b)
	na := m.newNode("a", a)

	return na, nb
}

// awaitDirect waits until a request through from's link takes the direct path:
// the hub then relays no stream for it.
func awaitDirect(t *testing.T, m *mesh, from *node) {
	t.Helper()

	eventually(t, 15*time.Second, "link on "+from.name+" goes direct", func() bool {
		h, err := tryHold(from.linkURL("/hold"), nil, "")
		if err != nil {
			return false
		}

		defer h.close()

		return m.status().Machines[from.name].LinkStreams == 0
	})
}

// ---- 1. viewer path and admission ----

func TestViewerAndAdmission(t *testing.T) {
	t.Parallel()

	m := newMesh(t, meshOpts{})
	m.twoNodes(nodeOpts{}, nodeOpts{})

	p := m.newPhone()

	if code, body := m.viewerGet(p, "b", "/"); code != http.StatusOK || body != "t3@b mtls=0" {
		t.Fatalf("viewer -> b: %d %q, want 200 \"t3@b mtls=0\" (X-Mtls headers must be stripped)", code, body)
	}

	if code, body := m.viewerGet(p, "a", "/"); code != http.StatusOK || body != "t3@a mtls=0" {
		t.Fatalf("viewer -> a: %d %q", code, body)
	}

	if code, _ := get(t, m.viewer.URL+"/", nil, "t3.b."+viewerDomain); code != http.StatusForbidden {
		t.Fatalf("viewer without headers: %d, want 403", code)
	}

	h := p.headers()
	h.Set("X-Mtls-Mesh-Viewer", "agent-a")

	if code, _ := get(t, m.viewer.URL+"/", h, "t3.b."+viewerDomain); code != http.StatusForbidden {
		t.Fatalf("agent identity as viewer: %d, want 403", code)
	}

	if code, _ := get(t, m.viewer.URL+"/", p.headers(), "t3.nope."+viewerDomain); code != http.StatusNotFound {
		t.Fatalf("unknown machine: %d, want 404", code)
	}

	st := m.status()
	for _, name := range []string{"a", "b"} {
		if ms := st.Machines[name]; !ms.Connected || ms.Sessions != 1 {
			t.Fatalf("machine %s status: %+v", name, ms)
		}
	}

	// A phone certificate chains to the clients CA but is not an agent identity.
	c, err := m.rawDial(&p.cert, proto.TunnelALPN(proto.ProtocolVersion))
	expectRefused(t, c, err)

	// No certificate and no outstanding token: refused even on the enroll ALPN.
	c, err = m.rawDial(nil, proto.ALPNEnroll)
	expectRefused(t, c, err)

	c, err = m.rawDial(nil, proto.TunnelALPN(proto.ProtocolVersion))
	expectRefused(t, c, err)

	// With a token outstanding the enroll ALPN is accepted: the hub waits for
	// the Enroll message, so the connection stays open.
	if _, _, err = m.tokens.Create("agent-a"); err != nil {
		t.Fatal(err)
	}

	c, err = m.rawDial(nil, proto.ALPNEnroll)
	if err != nil {
		t.Fatalf("enroll connection with a token outstanding: %v", err)
	}

	defer func() { _ = c.Close() }()

	_ = c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))

	if _, err = c.Read(make([]byte, 1)); err == nil {
		t.Fatal("unexpected data from hub")
	} else if ne, ok := err.(net.Error); !ok || !ne.Timeout() { //nolint:errorlint // plain check
		t.Fatalf("enroll connection with a token outstanding was refused: %v", err)
	}

	// The tunnel ALPN still needs an agent certificate.
	c2, err := m.rawDial(nil, proto.TunnelALPN(proto.ProtocolVersion))
	expectRefused(t, c2, err)
}

// ---- 2. link ports over the tunnel ----

func TestLinkOverTunnel(t *testing.T) {
	t.Parallel()

	m := newMesh(t, meshOpts{})
	a, b := m.twoNodes(nodeOpts{links: []string{"t3.b"}}, nodeOpts{links: []string{"t3.a"}})

	if code, body := get(t, a.linkURL("/"), nil, ""); code != http.StatusOK || body != "t3@b mtls=0" {
		t.Fatalf("a link t3.b: %d %q", code, body)
	}

	h := openHold(t, a.linkURL("/hold"), nil, "")
	defer h.close()

	st := m.status()
	if st.Machines["a"].LinkStreams != 1 || st.Machines["b"].OpenStreams != 1 {
		t.Fatalf("relayed stream not visible at the hub: a.linkStreams=%d b.openStreams=%d",
			st.Machines["a"].LinkStreams, st.Machines["b"].OpenStreams)
	}

	// b has no rule to reach a: the hub refuses the stream.
	if code, _ := get(t, b.linkURL("/"), nil, ""); code != http.StatusBadGateway {
		t.Fatalf("b link t3.a without a rule: %d, want 502", code)
	}

	// Link ports refuse foreign Host, Origin and Sec-Fetch-Site.
	for name, hdr := range map[string]http.Header{
		"origin":     {"Origin": {"http://evil.example"}},
		"fetch-site": {"Sec-Fetch-Site": {"cross-site"}},
	} {
		if code, _ := get(t, a.linkURL("/"), hdr, ""); code != http.StatusForbidden {
			t.Fatalf("link with foreign %s: %d, want 403", name, code)
		}
	}

	if code, _ := get(t, a.linkURL("/"), nil, "evil.example"); code != http.StatusForbidden {
		t.Fatalf("link with foreign Host: %d, want 403", code)
	}
}

// ---- 2. direct path and fallback ----

func TestDirectAndRevocation(t *testing.T) {
	t.Parallel()

	m := newMesh(t, meshOpts{})
	skipNoDirect(t, m)
	a, b := m.twoNodes(nodeOpts{direct: true, links: []string{"t3.b"}}, nodeOpts{direct: true})
	a.waitDirectListening()
	b.waitDirectListening()

	awaitDirect(t, m, a)

	h := openHold(t, a.linkURL("/hold"), nil, "")
	if st := m.status(); st.Machines["a"].LinkStreams != 0 || st.Machines["b"].OpenStreams != 0 {
		t.Fatalf("direct stream visible at the hub: %+v", st.Machines)
	}

	// Removing the rule closes the live direct session on both agents and
	// stops new ones.
	m.update(func(c *hubCfg) { c.noRelayRule = true })
	h.waitEnd(t, 5*time.Second)

	eventually(t, 5*time.Second, "link refused after the rule is gone", func() bool {
		code, _ := get(t, a.linkURL("/"), nil, "")

		return code == http.StatusBadGateway
	})
}

func TestDirectStalledPeerFallsBackToTunnel(t *testing.T) {
	t.Parallel()

	m := newMesh(t, meshOpts{})
	skipNoDirect(t, m)
	// A peer that accepts TCP and then says nothing, on b's direct port.
	port := freePort(t, m.direct.String())

	ln, err := net.Listen("tcp", net.JoinHostPort(m.direct.String(), itoa(port)))
	if err != nil {
		t.Fatal(err)
	}

	var accepted atomic.Int64

	stop := make(chan struct{})

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}

			accepted.Add(1)

			go func() {
				<-stop

				_ = c.Close()
			}()
		}
	}()
	t.Cleanup(func() {
		close(stop)

		_ = ln.Close()
	})

	a, _ := m.twoNodes(nodeOpts{direct: true, links: []string{"t3.b"}}, nodeOpts{direct: true, directPort: port})
	a.waitDirectListening()

	// Until a learns b's address it uses the tunnel without trying direct, so
	// keep asking until the stalled port saw a connection.
	eventually(t, 15*time.Second, "a tries b's stalled direct port", func() bool {
		start := time.Now()

		code, body := get(t, a.linkURL("/"), nil, "")
		if code != http.StatusOK || body != "t3@b mtls=0" {
			t.Fatalf("link during stall: %d %q, want the tunnel fallback to answer", code, body)
		}

		if d := time.Since(start); d > 4*time.Second {
			t.Fatalf("fallback took %s, the direct setup deadline is 1s", d)
		}

		return accepted.Load() > 0
	})

	h := openHold(t, a.linkURL("/hold"), nil, "")
	defer h.close()

	if st := m.status(); st.Machines["a"].LinkStreams < 1 {
		t.Fatalf("stalled direct peer: stream not relayed by the hub: %+v", st.Machines["a"])
	}
}

// ---- 3. revocation closes live sessions ----

func TestRevocationClosesLiveSessions(t *testing.T) {
	t.Parallel()

	m := newMesh(t, meshOpts{})
	a, _ := m.twoNodes(nodeOpts{links: []string{"t3.b"}}, nodeOpts{})

	p1, p2 := m.newPhone(), m.newPhone()

	v1 := m.openViewerHold(p1, "b")
	v2 := m.openViewerHold(p2, "b")
	relay := openHold(t, a.linkURL("/hold"), nil, "")

	// Block one leaf of z-phone: only that viewer stream is cut.
	m.update(func(c *hubCfg) { c.blocked = []string{p1.fp} })
	v1.waitEnd(t, 5*time.Second)

	if code, _ := m.viewerGet(p1, "b", "/"); code != http.StatusForbidden {
		t.Fatalf("blocked leaf: %d, want 403", code)
	}

	if code, body := m.viewerGet(p2, "b", "/"); code != http.StatusOK {
		t.Fatalf("other leaf of the same identity: %d %q, want 200", code, body)
	}

	assertOpen(t, v2, "viewer stream of the unblocked leaf")
	assertOpen(t, relay, "relayed stream")

	// Removing agent-a's rule cuts the relayed stream.
	m.update(func(c *hubCfg) { c.noRelayRule = true })
	relay.waitEnd(t, 5*time.Second)

	if code, _ := get(t, a.linkURL("/"), nil, ""); code != http.StatusBadGateway {
		t.Fatalf("link after rule removal: %d, want 502", code)
	}

	assertOpen(t, v2, "viewer stream after unrelated rule removal")

	// Disabling agent-a closes its tunnel.
	m.update(func(c *hubCfg) { c.disabled = []string{"agent-a"} })
	eventually(t, 5*time.Second, "agent a disconnected", func() bool { return !m.status().Machines["a"].Connected })

	if !m.status().Machines["b"].Connected {
		t.Fatal("disabling agent-a dropped agent-b")
	}
}

// assertOpen checks a held stream has not ended.
func assertOpen(t *testing.T, h *held, what string) {
	t.Helper()

	if !h.isOpen() {
		t.Fatalf("%s was cut", what)
	}
}

// ---- 4. tunnel switching ----

func TestTunnelReconnect(t *testing.T) {
	t.Parallel()

	m := newMesh(t, meshOpts{})
	a, b := m.twoNodes(nodeOpts{links: []string{"t3.b"}}, nodeOpts{})
	p := m.newPhone()

	live := m.openViewerHold(p, "b")
	before := m.tl.count()

	b.dropTunnel()
	live.waitEnd(t, 5*time.Second)

	// b dials again; the new session is the one new streams use.
	eventually(t, 15*time.Second, "b reconnects with a new connection", func() bool {
		return m.tl.count() > before && m.status().Machines["b"].Connected
	})
	eventually(t, 10*time.Second, "viewer request reaches b over the new session", func() bool {
		code, body := m.viewerGet(p, "b", "/")

		return code == http.StatusOK && body == "t3@b mtls=0"
	})

	eventually(t, 5*time.Second, "one session for b", func() bool { return m.status().Machines["b"].Sessions == 1 })

	// Same for a, the side that opens the relayed streams.
	before = m.tl.count()

	a.dropTunnel()

	eventually(t, 15*time.Second, "a reconnects with a new connection", func() bool {
		return m.tl.count() > before && m.status().Machines["a"].Connected
	})
	eventually(t, 10*time.Second, "a's link reaches b over the new session", func() bool {
		code, body := get(t, a.linkURL("/"), nil, "")

		return code == http.StatusOK && body == "t3@b mtls=0"
	})
}

// ---- 5. renewal ----

func TestRenewal(t *testing.T) {
	t.Parallel()

	m := newMesh(t, meshOpts{})
	withDirect := m.direct.IsValid()

	// Valid for 120 more days: not yet inside the 90 day renewal window.
	a, _ := m.twoNodes(nodeOpts{direct: withDirect, cacheTTL: 90 * 24 * time.Hour, links: []string{"t3.b"}, notAfter: time.Now().Add(120 * 24 * time.Hour)}, nodeOpts{direct: withDirect})
	oldFP := pki.Fingerprint(a.cert.Leaf)

	var direct *held

	if withDirect {
		a.waitDirectListening()
		awaitDirect(t, m, a)

		// A live direct session: it must outlive the renewal, since peers pin no leaf.
		direct = openHold(t, a.linkURL("/hold"), nil, "")
	}

	st := m.status().Machines["a"]
	if st.CertNotAfter == nil {
		t.Fatal("hub reports no certificate expiry for a")
	}

	oldNotAfter := *st.CertNotAfter

	// 40 days later the certificate is inside the window. The renewal check
	// runs on every new session, so cut the tunnel to trigger it.
	a.clock.Store(int64(40 * 24 * time.Hour))
	a.dropTunnel()

	eventually(t, 20*time.Second, "a renews its certificate", func() bool {
		s := m.status().Machines["a"]

		return s.Connected && s.CertNotAfter != nil && s.CertNotAfter.After(oldNotAfter.Add(100*24*time.Hour))
	})

	store := pki.Store{Dir: a.cfg.Identity.Dir}

	eventually(t, 10*time.Second, "renewed identity promoted on disk", func() bool {
		_, leaf, err := store.Load()

		return err == nil && pki.Fingerprint(leaf) != oldFP
	})

	// The hub admits only the newest leaf per identity.
	msg := m.tryTunnel(a.cert)

	rej, ok := msg.(proto.Reject)
	if !ok || rej.Reason != proto.RejectLeafNotNewest {
		t.Fatalf("old leaf after renewal: got %#v, want Reject %s", msg, proto.RejectLeafNotNewest)
	}

	if code, body := get(t, a.linkURL("/"), nil, ""); code != http.StatusOK || body != "t3@b mtls=0" {
		t.Fatalf("link after renewal: %d %q", code, body)
	}

	if withDirect {
		assertOpen(t, direct, "direct session across the renewal")

		// New direct connections work with the new certificate.
		awaitDirect(t, m, a)
	}
}

// ---- 6. enrollment ----

func TestEnrollmentEndToEnd(t *testing.T) {
	t.Parallel()

	m := newMesh(t, meshOpts{})
	b := m.newNode("b", nodeOpts{noIdentity: true, noStart: true})

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// A token is bound to one identity.
	wrong, _, err := m.tokens.Create("agent-a")
	if err != nil {
		t.Fatal(err)
	}

	if err = agent.Enroll(ctx, b.cfg, wrong, m.hubTLS()); err == nil {
		t.Fatal("enrolled agent-b with a token bound to agent-a")
	}

	token, _, err := m.tokens.Create("agent-b")
	if err != nil {
		t.Fatal(err)
	}

	if err = agent.Enroll(ctx, b.cfg, token, m.hubTLS()); err != nil {
		t.Fatalf("enroll: %v", err)
	}

	// Single use.
	other := m.newNode("b", nodeOpts{noIdentity: true, noStart: true})
	if err = agent.Enroll(ctx, other.cfg, token, m.hubTLS()); err == nil {
		t.Fatal("token enrolled twice")
	}

	b.start()

	p := m.newPhone()
	if code, body := m.viewerGet(p, "b", "/"); code != http.StatusOK || body != "t3@b mtls=0" {
		t.Fatalf("viewer -> enrolled b: %d %q", code, body)
	}

	// The hub records the issued leaf as newest.
	_, leaf, err := pki.Store{Dir: b.cfg.Identity.Dir}.Load()
	if err != nil {
		t.Fatal(err)
	}

	if got, _ := m.fake.Newest(ctx, "agent-b"); got != pki.Fingerprint(leaf) {
		t.Fatalf("newest leaf for agent-b = %s, enrolled leaf %s", got, pki.Fingerprint(leaf))
	}

	// With the token spent no enrollment is open any more.
	c, err := m.rawDial(nil, proto.ALPNEnroll)
	if err == nil && m.tokens.Outstanding() {
		_ = c.Close()

		t.Fatal("tokens still outstanding after enrollment")
	}

	expectRefused(t, c, err)
}

// ---- 7. release change ----

func TestReleaseChangeReachesAgent(t *testing.T) {
	t.Parallel()

	m := newMesh(t, meshOpts{})
	m.twoNodes(nodeOpts{}, nodeOpts{})

	first := m.status()

	eventually(t, 10*time.Second, "agents acknowledge the initial release", func() bool {
		st := m.status()

		return st.Machines["a"].Acked.Release == st.Release.Revision && st.Machines["b"].Acked.Release == st.Release.Revision
	})

	m.update(func(c *hubCfg) { c.release = "v0.4.0" })

	eventually(t, 10*time.Second, "agents acknowledge the new release", func() bool {
		st := m.status()

		return st.Release.Version == "v0.4.0" && st.Release.Revision != first.Release.Revision &&
			st.Machines["a"].Acked.Release == st.Release.Revision && st.Machines["b"].Acked.Release == st.Release.Revision
	})

	// The reload neither restarted the hub nor dropped a tunnel.
	for _, name := range []string{"a", "b"} {
		if ms := m.status().Machines[name]; !ms.Connected || ms.Sessions != 1 {
			t.Fatalf("machine %s after release bump: %+v", name, ms)
		}
	}
}

// ---- 8. stale config ----

func TestStaleConfigAlert(t *testing.T) {
	t.Parallel()

	m := newMesh(t, meshOpts{})
	m.twoNodes(nodeOpts{}, nodeOpts{})

	if code, body := m.opsGet("/alerts/stale-config"); code != http.StatusOK {
		t.Fatalf("stale-config at start: %d %q", code, body)
	}

	m.writeRaw("machines: [this is not: valid\n")
	eventually(t, 5*time.Second, "hub notices the unparsable config", func() bool { return m.watcher.LastError() != nil })

	// The loaded policy is kept, so the hub keeps serving.
	if code, _ := m.opsGet("/alerts/stale-config"); code != http.StatusOK {
		t.Fatalf("stale-config right after the break: %d, want 200 (10 minute grace)", code)
	}

	// The hub clock drives the stale check.
	m.clock.Add(int64(11 * time.Minute))

	if code, body := m.opsGet("/alerts/stale-config"); code != http.StatusServiceUnavailable || !strings.HasPrefix(body, "firing") {
		t.Fatalf("stale-config after 11 minutes: %d %q, want 503 firing", code, body)
	}

	if code, body := m.opsGet("/readyz"); code != http.StatusOK {
		t.Fatalf("readyz while stale: %d %q, want 200", code, body)
	}

	if st := m.status(); !st.Stale || st.ConfigError == "" {
		t.Fatalf("status while stale: stale=%v configError=%q", st.Stale, st.ConfigError)
	}

	p := m.newPhone()
	if code, _ := m.viewerGet(p, "b", "/"); code != http.StatusOK {
		t.Fatalf("viewer request while the config is stale: %d, want 200", code)
	}

	// Fixing the file clears the alert.
	m.writeConfig(m.cfg)
	eventually(t, 5*time.Second, "stale-config clears", func() bool {
		code, _ := m.opsGet("/alerts/stale-config")

		return code == http.StatusOK
	})
}

// ---- 9. CA rollover through the trust bundle ----

func TestTrustBundleRollover(t *testing.T) {
	t.Parallel()

	m := newMesh(t, meshOpts{})
	ca2 := pkitest.NewCA(t, "clients-v2")
	withDirect := m.direct.IsValid()
	a := m.newNode("a", nodeOpts{direct: withDirect, links: []string{"t3.b"}})

	// Before the bundle has the new CA, an identity from it is refused.
	cert2, _, _ := ca2.IssueIdentity(t, "agent-b", true, time.Now().Add(365*24*time.Hour))
	c, err := m.rawDial(&cert2, proto.TunnelALPN(proto.ProtocolVersion))
	expectRefused(t, c, err)

	m.writeTrust("trust-2", m.ca, ca2)
	eventually(t, 10*time.Second, "a acknowledges the new trust bundle", func() bool {
		return m.status().Machines["a"].Acked.TrustBundle == "trust-2"
	})

	b := m.newNode("b", nodeOpts{ca: ca2, direct: withDirect})

	if code, body := get(t, a.linkURL("/"), nil, ""); code != http.StatusOK || body != "t3@b mtls=0" {
		t.Fatalf("a -> b across CAs: %d %q", code, body)
	}

	eventually(t, 10*time.Second, "b acknowledges the trust bundle", func() bool {
		return m.status().Machines["b"].Acked.TrustBundle == "trust-2"
	})

	if !withDirect {
		t.Log("no direct address on this host: direct verification across CAs not exercised")

		return
	}

	a.waitDirectListening()
	b.waitDirectListening()

	// a (old CA) and b (new CA) verify each other against the bundle.
	awaitDirect(t, m, a)
}

func itoa(n int) string { return strconv.Itoa(n) }

// ---- outage: home links stay up with the hub gone ----

func TestHomeLinksSurviveHubOutage(t *testing.T) {
	t.Parallel()

	m := newMesh(t, meshOpts{})
	skipNoDirect(t, m)
	a, b := m.twoNodes(nodeOpts{direct: true, links: []string{"t3.b"}}, nodeOpts{direct: true})
	a.waitDirectListening()
	b.waitDirectListening()
	awaitDirect(t, m, a)

	live := openHold(t, a.linkURL("/hold"), nil, "")

	m.stopHub()

	// Past a few direct-session sweeps, so an outage that closed sessions would
	// have done so.
	time.Sleep(2500 * time.Millisecond)

	if code, body := get(t, a.linkURL("/"), nil, ""); code != http.StatusOK || body != "t3@b mtls=0" {
		t.Fatalf("a -> b with the hub down: %d %q, want a direct answer", code, body)
	}

	assertOpen(t, live, "direct session while the hub is down")

	// New direct streams keep opening, too.
	second := openHold(t, a.linkURL("/hold"), nil, "")
	assertOpen(t, second, "second direct stream with the hub down")
}
