package integration

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/zekihan/t3-mesh/internal/netwatch"
	"github.com/zekihan/t3-mesh/internal/pki"
)

// Direct connection at home: an enrolled device (the Android app) reaches a machine's
// T3 over the LAN through the agent's own TLS listener, with no hub on the path.
// Each test starts a real hub, node a with the device listener, and enrolls the
// phone's device identity through the enrollment protocol, so the leaf the agent
// admits is the one the hub issued and pushed.

const (
	phoneDevice  = "device-z-phone-mesh"
	tabletDevice = "device-z-tablet-mesh"
	hostA        = "t3.a." + viewerDomain
	foreignMAC   = "02:00:00:00:00:99"
)

type deviceRig struct {
	msh   *mesh
	a     *node
	phone tls.Certificate
}

// newDeviceRig starts a hub that lists both devices and puts the phone's device in
// a's rule (the tablet is enrolled but not in it), node a at home with the device
// listener, and enrolls the phone.
func newDeviceRig(t *testing.T, tweak func(*hubCfg)) *deviceRig {
	t.Helper()

	return newDeviceRigOn(t, tweak, "")
}

// newDeviceRigOn is newDeviceRig with node a serving the T3 at t3Addr, or its
// stand-in when empty.
func newDeviceRigOn(t *testing.T, tweak func(*hubCfg), t3Addr string) *deviceRig {
	t.Helper()

	cfg := hubCfg{
		devices: []string{phoneDevice, tabletDevice},
		rulesA:  []string{phoneDevice},
		api:     []string{"z-phone"},
	}

	if tweak != nil {
		tweak(&cfg)
	}

	msh := newMesh(t, &meshOpts{cfg: cfg})
	skipNoDirect(t, msh)

	rig := &deviceRig{msh: msh}
	rig.a = msh.newNode("a", &nodeOpts{direct: true, devices: true, fakeNet: true, t3Addr: t3Addr})
	rig.a.waitDeviceListening()

	rig.phone = msh.enrollDeviceCert(phoneDevice)
	rig.a.waitDeviceLeaf(phoneDevice, pki.Fingerprint(rig.phone.Leaf))

	return rig
}

func (nd *node) deviceAddr() string {
	return net.JoinHostPort(nd.m.direct.String(), strconv.Itoa(nd.devicePort))
}

// listening reports whether the device port accepts TCP.
func (nd *node) listening() bool {
	conn, err := (&net.Dialer{Timeout: time.Second}).DialContext(
		nd.m.t.Context(),
		"tcp",
		nd.deviceAddr(),
	)
	if err != nil {
		return false
	}

	_ = conn.Close()

	return true
}

func (nd *node) waitDeviceListening() {
	nd.m.t.Helper()
	eventually(nd.m.t, 10*time.Second, nd.name+" device listener", nd.listening)
}

// neverListens expects the device port to refuse connections for d.
func (nd *node) neverListens(d time.Duration, what string) {
	nd.m.t.Helper()

	end := time.Now().Add(d)

	for time.Now().Before(end) {
		if nd.listening() {
			nd.m.t.Fatalf("%s: %s accepts connections on the device port", what, nd.name)
		}

		<-time.After(50 * time.Millisecond)
	}
}

func (nd *node) waitDeviceLeaf(identity, fingerprint string) {
	nd.m.t.Helper()
	eventually(nd.m.t, 10*time.Second, nd.name+" learns the leaf of "+identity, func() bool {
		return nd.deviceLeaves(nd.m.t)[identity] == fingerprint
	})
}

// checkAgentCert is the check the app makes of the agent before it sends anything:
// server auth, exactly one URI naming the expected agent, chained to the clients CA.
func (msh *mesh) checkAgentCert(state *tls.ConnectionState, want string) error {
	leaf := state.PeerCertificates[0]

	name, err := pki.CertIdentity(leaf)
	if err != nil || name != want {
		return fmt.Errorf("agent identity %q, want %q: %w", name, want, err)
	}

	raw := make([][]byte, len(state.PeerCertificates))
	for i, c := range state.PeerCertificates {
		raw[i] = c.Raw
	}

	_, err = pki.VerifyPeer(raw, msh.pool, x509.ExtKeyUsageServerAuth, time.Now())
	if err != nil {
		return fmt.Errorf("agent certificate: %w", err)
	}

	return nil
}

func (nd *node) deviceTLS(cert *tls.Certificate) *tls.Config {
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{"http/1.1"},
		// The agent's leaf names an identity, not a host; checkAgentCert holds it to
		// what the app holds it to.
		InsecureSkipVerify: true, //nolint:gosec // checked by VerifyConnection
		VerifyConnection: func(state tls.ConnectionState) error {
			return nd.m.checkAgentCert(&state, nd.identity)
		},
	}

	if cert != nil {
		cfg.Certificates = []tls.Certificate{*cert}
	}

	return cfg
}

func (nd *node) dialDevice(cert *tls.Certificate) (net.Conn, error) {
	nd.m.t.Helper()

	dialer := tls.Dialer{
		Config:    nd.deviceTLS(cert),
		NetDialer: &net.Dialer{Timeout: 3 * time.Second},
	}

	conn, err := dialer.DialContext(nd.m.t.Context(), "tcp", nd.deviceAddr())
	if err != nil {
		return nil, fmt.Errorf("dial device listener: %w", err)
	}

	nd.m.t.Cleanup(func() { _ = conn.Close() })

	return conn, nil
}

type deviceReply struct {
	header http.Header
	body   string
	status int
}

// deviceDo sends one request on a fresh connection as the device and reads the reply.
func (nd *node) deviceDo(
	cert *tls.Certificate,
	method, host, path string,
	hdr http.Header,
	body string,
) deviceReply {
	nd.m.t.Helper()

	conn, err := nd.dialDevice(cert)
	if err != nil {
		nd.m.t.Fatal(err)
	}

	return doOn(nd.m.t, conn, method, host, path, hdr, body)
}

// doOn writes one request on conn and reads the reply, whichever listener it leads to.
func doOn(
	t *testing.T,
	conn net.Conn,
	method, host, path string,
	hdr http.Header,
	body string,
) deviceReply {
	t.Helper()

	req, err := http.NewRequestWithContext(
		t.Context(), method, "http://"+host+path, strings.NewReader(body),
	)
	if err != nil {
		t.Fatal(err)
	}

	req.Host = host
	req.Close = true

	maps.Copy(req.Header, hdr)

	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	err = req.Write(conn)
	if err != nil {
		t.Fatalf("write request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}

	defer func() { _ = resp.Body.Close() }()

	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	return deviceReply{status: resp.StatusCode, header: resp.Header, body: string(got)}
}

// expectDeviceRefused asserts a caller never gets an answer: the handshake fails, or the
// connection is cut before any byte. In TLS 1.3 the client finishes its handshake
// before the server judges its certificate, so the refusal shows on the first read.
func (nd *node) expectDeviceRefused(cert *tls.Certificate, what string) {
	nd.m.t.Helper()

	conn, err := nd.dialDevice(cert)
	if err != nil {
		return
	}

	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = io.WriteString(conn, "GET / HTTP/1.1\r\nHost: "+hostA+"\r\n\r\n")

	buf := make([]byte, 1)

	n, err := conn.Read(buf)
	if err == nil || n > 0 {
		nd.m.t.Fatalf("%s: got an answer, want a refusal", what)
	}

	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		nd.m.t.Fatalf("%s: connection left open, want a refusal", what)
	}
}

// deviceWS is an upgraded connection to the stand-in T3's echo endpoint.
type deviceWS struct {
	conn net.Conn
	br   *bufio.Reader
	resp deviceReply
}

// upgradeOn opens the WebSocket endpoint on conn, as the app would, and returns the
// reply to the upgrade and the reader for what follows it.
func upgradeOn(t *testing.T, conn net.Conn, host string, extra http.Header) *deviceWS {
	t.Helper()

	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	var sb strings.Builder

	sb.WriteString(
		"GET /ws HTTP/1.1\r\nHost: " + host + "\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n" +
			"Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n",
	)
	_ = extra.Write(&sb)
	sb.WriteString("\r\n")

	_, err := io.WriteString(conn, sb.String())
	if err != nil {
		t.Fatalf("write upgrade: %v", err)
	}

	br := bufio.NewReader(conn)

	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read upgrade reply: %v", err)
	}

	_ = resp.Body.Close()

	return &deviceWS{
		conn: conn, br: br,
		resp: deviceReply{status: resp.StatusCode, header: resp.Header},
	}
}

func (nd *node) openDeviceWS(cert *tls.Certificate) *deviceWS {
	nd.m.t.Helper()

	conn, err := nd.dialDevice(cert)
	if err != nil {
		nd.m.t.Fatal(err)
	}

	ws := upgradeOn(nd.m.t, conn, hostA, nil)
	if ws.resp.status != http.StatusSwitchingProtocols {
		nd.m.t.Fatalf("WebSocket upgrade: %d", ws.resp.status)
	}

	return ws
}

func (ws *deviceWS) echo(t *testing.T, msg string) {
	t.Helper()

	_ = ws.conn.SetDeadline(time.Now().Add(5 * time.Second))

	_, err := io.WriteString(ws.conn, msg+"\n")
	if err != nil {
		t.Fatalf("WebSocket write: %v", err)
	}

	line, err := ws.br.ReadString('\n')
	if err != nil || line != msg+"\n" {
		t.Fatalf("WebSocket echo = %q (%v), want %q", line, err, msg)
	}
}

// waitClosed expects the connection to be cut, not merely quiet.
func (ws *deviceWS) waitClosed(t *testing.T, wait time.Duration, what string) {
	t.Helper()

	_ = ws.conn.SetReadDeadline(time.Now().Add(wait))

	_, err := ws.br.ReadByte()
	if err == nil {
		t.Fatalf("%s: unexpected data on the WebSocket", what)
	}

	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		t.Fatalf("%s: the WebSocket is still open after %s", what, wait)
	}
}

// apiDirect returns the route the hub lists for machine a to the KeyChain phone.
func (msh *mesh) apiDirect(machine string) map[string]any {
	msh.t.Helper()

	p := msh.newPhone()
	code, body := get(msh.t, msh.viewer.URL+"/api/v1/machines", p.headers(), "hub."+viewerDomain)

	if code != http.StatusOK {
		msh.t.Fatalf("machines: %d %s", code, body)
	}

	var doc struct {
		Machines []struct {
			Direct        map[string]any `json:"direct"`
			Name          string         `json:"name"`
			AgentIdentity string         `json:"agentIdentity"`
		} `json:"machines"`
	}

	err := json.Unmarshal([]byte(body), &doc)
	if err != nil {
		msh.t.Fatalf("decode %q: %v", body, err)
	}

	for _, m := range doc.Machines {
		if m.Name == machine {
			if m.AgentIdentity != "agent-"+machine {
				msh.t.Fatalf("agentIdentity = %q", m.AgentIdentity)
			}

			return m.Direct
		}
	}

	msh.t.Fatalf("no machine %s in %s", machine, body)

	return nil
}

func TestDeviceDirectAtHome(t *testing.T) {
	t.Parallel()

	rig := newDeviceRig(t, nil)
	nd := rig.a

	// The hub lists the route once the agent reports its listener bound.
	eventually(t, 10*time.Second, "the hub lists a direct route for a", func() bool {
		return rig.msh.apiDirect("a") != nil
	})

	route := rig.msh.apiDirect("a")
	if route["address"] != nd.m.direct.String() || route["port"] != float64(nd.devicePort) {
		t.Fatalf("direct = %v, want %s:%d", route, nd.m.direct, nd.devicePort)
	}

	// HTTP reaches T3 with the viewer host as its origin.
	rep := nd.deviceDo(&rig.phone, http.MethodGet, hostA, "/", nil, "")
	if rep.status != http.StatusOK || rep.body != "t3@a mtls=0" {
		t.Fatalf("GET /: %d %q", rep.status, rep.body)
	}

	checkDeviceHeaders(t, rig)
	checkDeviceProbe(t, rig)
	checkDeviceHost(t, rig)

	// A WebSocket is proxied.
	ws := nd.openDeviceWS(&rig.phone)
	ws.echo(t, "hello")
	ws.echo(t, "again")
}

func checkDeviceHeaders(t *testing.T, rig *deviceRig) {
	t.Helper()

	rep := rig.a.deviceDo(&rig.phone, http.MethodGet, hostA, "/headers", http.Header{
		"X-Mtls-Mesh-Viewer":      {"urn:noqer:mtls:clients:z-phone"},
		"X-Mtls-Mesh-Fingerprint": {strings.Repeat("a", 64)},
		"Forwarded":               {"for=203.0.113.9"},
		"X-Forwarded-For":         {"203.0.113.9"},
		"X-Forwarded-Host":        {"evil.example"},
		"X-Forwarded-Proto":       {"http"},
		"X-Forwarded-Port":        {"8080"},
		"X-Real-Ip":               {"203.0.113.9"},
		"Origin":                  {"https://" + hostA},
	}, "")

	var seen struct {
		Header http.Header `json:"headers"`
		Host   string      `json:"host"`
	}

	err := json.Unmarshal([]byte(rep.body), &seen)
	if err != nil {
		t.Fatalf("decode %q: %v", rep.body, err)
	}

	if seen.Host != hostA {
		t.Fatalf("T3 saw Host %q, want %q unchanged", seen.Host, hostA)
	}

	for name := range seen.Header {
		lower := strings.ToLower(name)
		if strings.HasPrefix(lower, "x-mtls-") || lower == "forwarded" || lower == "x-real-ip" ||
			(strings.HasPrefix(lower, "x-forwarded-") && lower != "x-forwarded-proto") {
			t.Errorf("%s reached T3", name)
		}
	}

	if seen.Header.Get("X-Forwarded-Proto") != "https" ||
		seen.Header.Get("Origin") != "https://"+hostA {
		t.Errorf("T3 saw %v", seen.Header)
	}
}

func checkDeviceProbe(t *testing.T, rig *deviceRig) {
	t.Helper()

	rep := rig.a.deviceDo(&rig.phone, http.MethodGet, hostA, "/.well-known/t3-mesh/direct", nil, "")
	if rep.status != http.StatusOK || rep.header.Get("Cache-Control") != "no-store" {
		t.Fatalf("probe: %d %v", rep.status, rep.header)
	}

	if rep.body != `{"machine":"a","identity":"`+phoneDevice+`"}` {
		t.Fatalf("probe body = %s", rep.body)
	}
}

func checkDeviceHost(t *testing.T, rig *deviceRig) {
	t.Helper()

	for _, host := range []string{hostA + ":443", strings.ToUpper(hostA)} {
		rep := rig.a.deviceDo(&rig.phone, http.MethodGet, host, "/", nil, "")
		if rep.status != http.StatusOK {
			t.Errorf("Host %q: %d, want 200", host, rep.status)
		}
	}

	for _, host := range []string{"t3.b." + viewerDomain, "evil.example", hostA + ":8443", "hub." + viewerDomain} {
		rep := rig.a.deviceDo(&rig.phone, http.MethodGet, host, "/", nil, "")
		if rep.status != http.StatusMisdirectedRequest {
			t.Errorf("Host %q: %d, want 421", host, rep.status)
		}
	}
}

func TestDeviceDirectRefusesWhoIsNotAllowed(t *testing.T) {
	t.Parallel()

	rig := newDeviceRig(t, func(c *hubCfg) {
		// Every kind of caller the listener must refuse is also listed in the rule,
		// so the rule is not what refuses it.
		c.rulesA = append(c.rulesA, "agent-b")
	})
	nd := rig.a

	// The KeyChain identity of the same phone, which the viewer host does accept.
	keychain := rig.msh.newPhone()
	nd.expectDeviceRefused(&keychain.cert, "KeyChain identity")

	// An agent.
	agentB, _, _ := rig.msh.ca.IssueIdentity(t, "agent-b", true, time.Now().Add(time.Hour))
	nd.expectDeviceRefused(&agentB, "agent identity")

	// An enrolled device that a's rule does not list.
	tablet := rig.msh.enrollDeviceCert(tabletDevice)
	nd.waitDeviceLeaf(tabletDevice, pki.Fingerprint(tablet.Leaf))
	nd.expectDeviceRefused(&tablet, "enrolled device not in the rule")

	// No certificate at all.
	nd.expectDeviceRefused(nil, "no certificate")

	// A superseded leaf: after a re-enrollment the old one is refused, the new one admitted.
	old := rig.phone
	fresh := rig.msh.enrollDeviceCert(phoneDevice)
	nd.waitDeviceLeaf(phoneDevice, pki.Fingerprint(fresh.Leaf))
	nd.expectDeviceRefused(&old, "superseded leaf")

	rep := nd.deviceDo(&fresh, http.MethodGet, hostA, "/", nil, "")
	if rep.status != http.StatusOK {
		t.Fatalf("the newest leaf: %d", rep.status)
	}
}

func TestDeviceDirectLiveSessionsClose(t *testing.T) {
	t.Parallel()

	tests := []struct {
		apply func(rig *deviceRig)
		name  string
	}{
		{
			name: "blocked leaf",
			apply: func(rig *deviceRig) {
				fp := pki.Fingerprint(rig.phone.Leaf)
				rig.msh.update(func(c *hubCfg) { c.blocked = append(c.blocked, fp) })
			},
		},
		{
			name:  "removed from the rule",
			apply: func(rig *deviceRig) { rig.msh.update(func(c *hubCfg) { c.rulesA = nil }) },
		},
		{
			name: "superseded by a new leaf",
			apply: func(rig *deviceRig) {
				fresh := rig.msh.enrollDeviceCert(phoneDevice)
				rig.a.waitDeviceLeaf(phoneDevice, pki.Fingerprint(fresh.Leaf))
			},
		},
		{
			name: "identity disabled",
			apply: func(rig *deviceRig) {
				rig.msh.update(func(c *hubCfg) { c.disabled = append(c.disabled, phoneDevice) })
			},
		},
		{
			name: "device removed from the configuration",
			apply: func(rig *deviceRig) {
				rig.msh.update(func(c *hubCfg) {
					c.devices = []string{tabletDevice}
					c.rulesA = nil
				})
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rig := newDeviceRig(t, nil)
			ws := rig.a.openDeviceWS(&rig.phone)
			ws.echo(t, "before")

			tt.apply(rig)

			ws.waitClosed(t, 10*time.Second, tt.name)

			rig.a.expectDeviceRefused(&rig.phone, "after "+tt.name)
		})
	}
}

func TestDeviceDirectLeafExpiryClosesTheSession(t *testing.T) {
	t.Parallel()

	rig := newDeviceRig(t, nil)
	ws := rig.a.openDeviceWS(&rig.phone)
	ws.echo(t, "before")

	// The leaf is valid for a year; the agent's clock reaches its end.
	rig.a.clock.Add(int64(366 * 24 * time.Hour))

	ws.waitClosed(t, 5*time.Second, "leaf expiry")
}

func TestDeviceDirectSurvivesAHubOutage(t *testing.T) {
	t.Parallel()

	rig := newDeviceRig(t, nil)
	nd := rig.a
	ws := nd.openDeviceWS(&rig.phone)
	ws.echo(t, "before the outage")

	rig.msh.stopHub()

	// Past several sweeps, an open session stays and new ones are admitted from the
	// cached rules and leaf.
	<-time.After(2500 * time.Millisecond)
	ws.echo(t, "during the outage")

	rep := nd.deviceDo(&rig.phone, http.MethodGet, hostA, "/", nil, "")
	if rep.status != http.StatusOK || rep.body != "t3@a mtls=0" {
		t.Fatalf("during the outage: %d %q", rep.status, rep.body)
	}

	// A cold start in the outage opens the listener from the cache alone.
	nd.stop()
	nd.neverListens(300*time.Millisecond, "agent stopped")

	nd.launch()
	nd.waitDeviceListening()

	rep = nd.deviceDo(&rig.phone, http.MethodGet, hostA, "/", nil, "")
	if rep.status != http.StatusOK {
		t.Fatalf("after a cold start in the outage: %d %q", rep.status, rep.body)
	}

	// A week later the cache is spent: the session closes and nothing new gets in.
	ws = nd.openDeviceWS(&rig.phone)
	ws.echo(t, "inside the window")

	nd.clock.Add(int64(2 * time.Hour)) // the node's cache window is one hour

	ws.waitClosed(t, 5*time.Second, "cache window over")

	// Until the next reconcile the socket may still accept, and closes the connection
	// before any handshake; a network event (or the 30 s backstop) then unbinds it.
	nd.expectDeviceRefused(&rig.phone, "cache window over")
	nd.netEvent(netwatch.EventNetwork)
	nd.neverListens(500*time.Millisecond, "cache window over")
}

// An agent that boots in an outage on a foreign network whose addresses match the
// home prefixes must not open the listener: only the gateway tells it apart.
func TestDeviceDirectForeignNetworkOpensNoListener(t *testing.T) {
	t.Parallel()

	rig := newDeviceRig(t, nil)
	nd := rig.a

	rig.msh.stopHub()
	nd.stop()

	nd.gateway.Store(foreignMAC)
	nd.launch()
	nd.neverListens(1500*time.Millisecond, "cold start on a foreign network")

	// The same cache on the home network does open it, so the gateway was the reason.
	nd.stop()
	nd.gateway.Store(fixedGatewayMAC)
	nd.launch()
	nd.waitDeviceListening()

	rep := nd.deviceDo(&rig.phone, http.MethodGet, hostA, "/", nil, "")
	if rep.status != http.StatusOK {
		t.Fatalf("on the home network again: %d", rep.status)
	}
}

// A machine that carries on running when it moves to a foreign network closes the
// listener and its open sessions as soon as it notices.
func TestDeviceDirectLeavingHomeDuringAnOutageClosesIt(t *testing.T) {
	t.Parallel()

	rig := newDeviceRig(t, nil)
	nd := rig.a
	ws := nd.openDeviceWS(&rig.phone)
	ws.echo(t, "at home")

	rig.msh.stopHub()
	nd.gateway.Store(foreignMAC)
	nd.netEvent(netwatch.EventNetwork)

	ws.waitClosed(t, 5*time.Second, "moved to a foreign network")
	nd.neverListens(500*time.Millisecond, "moved to a foreign network")
}

func TestDeviceDirectFollowsTheHubsHomeVerdict(t *testing.T) {
	t.Parallel()

	rig := newDeviceRig(t, nil)
	nd := rig.a

	eventually(
		t,
		10*time.Second,
		"route listed",
		func() bool { return rig.msh.apiDirect("a") != nil },
	)

	ws := nd.openDeviceWS(&rig.phone)
	ws.echo(t, "home")

	// The hub no longer sees the machine's tunnel as home: the listener goes, its
	// sessions with it, and the route is withdrawn.
	rig.msh.update(func(c *hubCfg) { c.home = []string{"10.99.0.0/16"} })

	ws.waitClosed(t, 10*time.Second, "machine away")
	// Sessions are re-checked on their own and can close a moment before the
	// listener is unbound; new connections in between are refused at admission.
	eventually(t, 5*time.Second, "listener closed", func() bool { return !nd.listening() })
	nd.neverListens(500*time.Millisecond, "machine away")
	eventually(
		t,
		10*time.Second,
		"route withdrawn",
		func() bool { return rig.msh.apiDirect("a") == nil },
	)

	// Back home: the listener and the route return.
	rig.msh.update(func(c *hubCfg) { c.home = []string{"127.0.0.0/8"} })

	nd.waitDeviceListening()
	eventually(
		t,
		10*time.Second,
		"route listed again",
		func() bool { return rig.msh.apiDirect("a") != nil },
	)
}

// What an unpaired request gets on the direct path is what it gets through the viewer
// host: same status, headers and body, and what T3 receives is the same.
func TestDeviceDirectMatchesTheViewerPath(t *testing.T) {
	t.Parallel()

	rig := newDeviceRig(t, nil)
	msh, nd := rig.msh, rig.a
	viewer := msh.newPhone()

	viaViewer := func(method, path string, hdr http.Header, body string) deviceReply {
		conn, err := (&net.Dialer{}).DialContext(
			t.Context(),
			"tcp",
			msh.viewer.Listener.Addr().String(),
		)
		if err != nil {
			t.Fatal(err)
		}

		t.Cleanup(func() { _ = conn.Close() })

		all := viewer.headers()
		maps.Copy(all, hdr)

		return doOn(t, conn, method, hostA, path, all, body)
	}

	viaDevice := func(method, path string, hdr http.Header, body string) deviceReply {
		return nd.deviceDo(&rig.phone, method, hostA, path, hdr, body)
	}

	requests := []struct {
		hdr    http.Header
		method string
		path   string
		body   string
	}{
		{method: http.MethodGet, path: "/"},
		{method: http.MethodGet, path: "/some/unpaired/path?x=1&y=2"},
		{
			method: http.MethodGet,
			path:   "/headers",
			hdr: http.Header{
				"Origin": {"https://" + hostA},
				"Cookie": {"t3_session=abc"},
				"Accept": {"application/json"},
			},
		},
		{
			method: http.MethodPost, path: "/headers", body: `{"k":"v"}`,
			hdr: http.Header{"Content-Type": {"application/json"}},
		},
		{method: http.MethodGet, path: "/headers", hdr: http.Header{"X-Forwarded-Proto": {"http"}}},
	}

	for _, rq := range requests {
		want := viaViewer(rq.method, rq.path, rq.hdr, rq.body)
		got := viaDevice(rq.method, rq.path, rq.hdr, rq.body)

		compareReplies(t, rq.method+" "+rq.path, &want, &got)
	}

	// An upgrade: the same switching reply, and the same echo after it.
	vconn, err := (&net.Dialer{}).DialContext(
		t.Context(),
		"tcp",
		msh.viewer.Listener.Addr().String(),
	)
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = vconn.Close() })

	vws := upgradeOn(t, vconn, hostA, viewer.headers())

	dconn, err := nd.dialDevice(&rig.phone)
	if err != nil {
		t.Fatal(err)
	}

	dws := upgradeOn(t, dconn, hostA, nil)

	compareReplies(t, "WebSocket upgrade", &vws.resp, &dws.resp)
	vws.echo(t, "hello")
	dws.echo(t, "hello")
}

// compareReplies asserts two replies are the same apart from the Date header.
func compareReplies(t *testing.T, what string, want, got *deviceReply) {
	t.Helper()

	if want.status != got.status {
		t.Errorf("%s: status %d via the viewer host, %d direct", what, want.status, got.status)
	}

	wantHdr, gotHdr := want.header.Clone(), got.header.Clone()
	wantHdr.Del("Date")
	gotHdr.Del("Date")

	if !maps.EqualFunc(wantHdr, gotHdr, slices.Equal) {
		t.Errorf("%s: headers differ\n viewer: %v\n direct: %v", what, wantHdr, gotHdr)
	}

	if want.body != got.body {
		t.Errorf("%s: body differs\n viewer: %q\n direct: %q", what, want.body, got.body)
	}
}

// With T3 down, the viewer host and the direct path answer alike.
func TestDeviceDirectBackendDownMatchesTheViewerPath(t *testing.T) {
	t.Parallel()

	rig := newDeviceRig(t, nil)
	msh, nd := rig.msh, rig.a
	viewer := msh.newPhone()

	nd.t3.CloseClientConnections()
	nd.t3.Close()

	conn, err := (&net.Dialer{}).DialContext(
		t.Context(),
		"tcp",
		msh.viewer.Listener.Addr().String(),
	)
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = conn.Close() })

	want := doOn(t, conn, http.MethodGet, hostA, "/", viewer.headers(), "")
	got := nd.deviceDo(&rig.phone, http.MethodGet, hostA, "/", nil, "")

	if want.status != http.StatusBadGateway {
		t.Fatalf("viewer host with T3 down: %d", want.status)
	}

	compareReplies(t, "T3 down", &want, &got)
}
