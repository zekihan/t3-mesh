package integration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"maps"
	"net"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Compatibility with upstream T3. The rest of this package runs the real hub and
// agents in front of a stand-in T3; this test puts a real `t3 serve` behind them
// and runs what the web and mobile apps do, through the hub's viewer host and the
// agent's device listener, and again straight at T3 as the control. A check that
// fails on a proxied route and passes on "direct" is the proxy; one that fails on
// all three is T3 having changed under the test, and the test needs updating.
//
// It runs only when T3_COMPAT_BINARY names a `t3` executable. Assertions compare
// what the proxies deliver with what T3 delivers on its own (status, the headers
// that matter, body semantics), so a harmless change in T3 does not fail them.

// orchestrationQuery is what the apps add to the RPC socket URL.
const orchestrationQuery = "orchestrationProtocol=2"

//nolint:gosec // OAuth type URNs, not credentials
const (
	formType     = "application/x-www-form-urlencoded"
	jsonType     = "application/json"
	holdFor      = 4 * time.Second
	rpcWait      = 30 * time.Second
	tokenGrant   = "urn:ietf:params:oauth:grant-type:token-exchange"
	tokenBoot    = "urn:t3:params:oauth:token-type:environment-bootstrap"
	tokenAccess  = "urn:ietf:params:oauth:token-type:access_token"
	sessionPath  = "/api/auth/session"
	envPath      = "/.well-known/t3/environment"
	ticketPath   = "/api/auth/websocket-ticket"
	oauthPath    = "/oauth/token"
	browserPath  = "/api/auth/browser-session"
	bogusToken   = "bogus"
	maxPlainBody = 1 << 20
)

// reply is one HTTP answer, reduced to what is compared.
type reply struct {
	header http.Header
	body   []byte
	status int
}

// compatRoute is one way to reach T3: the proxied ones carry the headers and Host
// the real path would, "direct" carries none.
type compatRoute struct {
	client *http.Client
	dial   func() (net.Conn, error)
	hdr    http.Header
	name   string
	base   string
	host   string
	origin string
}

func directRoute(srv *t3Server) *compatRoute {
	return &compatRoute{
		name: "direct",
		client: &http.Client{
			Timeout:   30 * time.Second,
			Transport: &http.Transport{DisableKeepAlives: true},
		},
		dial: func() (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(
				context.Background(), "tcp", srv.addr,
			)
		},
		hdr:    http.Header{},
		base:   "http://" + srv.addr,
		host:   srv.addr,
		origin: "http://" + srv.addr,
	}
}

// viewerRoute is a viewer's request as Traefik hands it to the hub.
func viewerRoute(rig *deviceRig) *compatRoute {
	msh := rig.msh
	viewer := msh.newPhone()

	return &compatRoute{
		name: "viewer",
		client: &http.Client{
			Timeout:   30 * time.Second,
			Transport: &http.Transport{DisableKeepAlives: true},
		},
		dial: func() (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(
				context.Background(), "tcp", msh.viewer.Listener.Addr().String(),
			)
		},
		hdr:    viewer.headers(),
		base:   msh.viewer.URL,
		host:   hostA,
		origin: "https://" + hostA,
	}
}

// deviceRoute is an enrolled device's request straight to the agent's listener.
func deviceRoute(rig *deviceRig) *compatRoute {
	dial := func() (net.Conn, error) { return rig.a.dialDevice(&rig.phone) }

	return &compatRoute{
		name: "device",
		client: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				DisableKeepAlives: true,
				DialContext: func(context.Context, string, string) (net.Conn, error) {
					return dial()
				},
			},
		},
		dial:   dial,
		hdr:    http.Header{},
		base:   "http://" + hostA,
		host:   hostA,
		origin: "https://" + hostA,
	}
}

func (rt *compatRoute) do(
	t *testing.T,
	method, path string,
	hdr http.Header,
	body string,
) reply {
	t.Helper()

	var reader io.Reader = http.NoBody
	if body != "" {
		reader = strings.NewReader(body)
	}

	//nolint:gosec // the servers are the ones this test started
	req, err := http.NewRequestWithContext(t.Context(), method, rt.base+path, reader)
	if err != nil {
		t.Fatal(err)
	}

	req.Host = rt.host

	maps.Copy(req.Header, rt.hdr)
	maps.Copy(req.Header, hdr)

	resp, err := rt.client.Do(req) //nolint:gosec // as above
	if err != nil {
		t.Fatalf("%s %s on %s: %v", method, path, rt.name, err)
	}

	defer func() { _ = resp.Body.Close() }()

	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("%s %s on %s: read body: %v", method, path, rt.name, err)
	}

	return reply{status: resp.StatusCode, header: resp.Header, body: got}
}

// ---- comparing with what T3 says itself ----

// ignoredHeaders differ per hop or per request and say nothing about the proxy.
var ignoredHeaders = map[string]bool{
	"connection": true, "keep-alive": true, "date": true, "transfer-encoding": true,
	"te": true, "trailer": true, "upgrade": true, "content-length": true,
	"proxy-authenticate": true, "proxy-authorization": true,
}

func isJSON(rep reply) bool {
	return strings.HasPrefix(rep.header.Get("Content-Type"), jsonType)
}

// semantics decodes a JSON body without the per-request trace id.
func semantics(body []byte) (any, bool) {
	var doc any

	err := json.Unmarshal(body, &doc)
	if err != nil {
		return nil, false
	}

	if obj, ok := doc.(map[string]any); ok {
		delete(obj, "traceId")
	}

	return doc, true
}

// sameReply fails when got differs from what T3 answered on its own.
func sameReply(t *testing.T, route string, want, got reply) {
	t.Helper()

	if got.status != want.status {
		t.Errorf("%s: status %d, T3 itself answers %d\nbody: %s",
			route, got.status, want.status, clip(got.body))
	}

	for name, values := range want.header {
		lower := strings.ToLower(name)
		if ignoredHeaders[lower] {
			continue
		}

		if !slices.Equal(got.header.Values(name), values) {
			t.Errorf("%s: header %s = %q, T3 itself sends %q",
				route, name, got.header.Values(name), values)
		}
	}

	sameBody(t, route, want, got)
}

func sameBody(t *testing.T, route string, want, got reply) {
	t.Helper()

	if isJSON(want) && isJSON(got) {
		wantDoc, okWant := semantics(want.body)
		gotDoc, okGot := semantics(got.body)

		if okWant && okGot {
			if !reflect.DeepEqual(wantDoc, gotDoc) {
				t.Errorf(
					"%s: body differs\ngot:  %s\nwant: %s",
					route,
					clip(got.body),
					clip(want.body),
				)
			}

			return
		}
	}

	if !bytes.Equal(got.body, want.body) {
		t.Errorf("%s: body differs (%d bytes, T3 itself sends %d)\ngot:  %s\nwant: %s",
			route, len(got.body), len(want.body), clip(got.body), clip(want.body))
	}
}

func clip(body []byte) string {
	const limit = 300

	if len(body) > limit {
		return string(body[:limit]) + "..."
	}

	return string(body)
}

// unpairedSpec is a request any client may make before it is paired.
type unpairedSpec struct {
	hdr    http.Header
	name   string
	method string
	path   string
	body   string
}

func unpairedSpecs() []unpairedSpec {
	return []unpairedSpec{
		{name: "environment", method: http.MethodGet, path: envPath},
		{name: "index", method: http.MethodGet, path: "/"},
		{name: "pair-page", method: http.MethodGet, path: "/pair"},
		{name: "session", method: http.MethodGet, path: sessionPath},
		{name: "ticket-unauthenticated", method: http.MethodPost, path: ticketPath + "/rpc"},
		{
			name: "token-bad-credential", method: http.MethodPost, path: oauthPath,
			hdr: http.Header{"Content-Type": {formType}},
			body: url.Values{
				"grant_type": {tokenGrant}, "subject_token": {bogusToken},
				"subject_token_type": {tokenBoot}, "requested_token_type": {tokenAccess},
			}.Encode(),
		},
		{
			name: "browser-session-bad-credential", method: http.MethodPost, path: browserPath,
			hdr:  http.Header{"Content-Type": {jsonType}},
			body: `{"credential":"` + bogusToken + `"}`,
		},
	}
}

func (rt *compatRoute) unpaired(t *testing.T, spec *unpairedSpec) reply {
	t.Helper()

	hdr := http.Header{"Accept": {"*/*"}}
	maps.Copy(hdr, spec.hdr)

	return rt.do(t, spec.method, spec.path, hdr, spec.body)
}

// upgradeSpec is a WebSocket upgrade a client makes without a valid ticket.
type upgradeSpec struct {
	name   string
	target string
}

func upgradeSpecs() []upgradeSpec {
	return []upgradeSpec{
		{name: "no-protocol-version", target: "/ws"},
		{name: "no-ticket", target: "/ws?" + orchestrationQuery},
		{name: "bad-ticket", target: "/ws?" + orchestrationQuery + "&wsTicket=" + bogusToken},
	}
}

// rawUpgrade tries an upgrade and returns whatever answered it.
func (rt *compatRoute) rawUpgrade(t *testing.T, target string, withOrigin bool) upgradeReply {
	t.Helper()

	conn, err := rt.dial()
	if err != nil {
		t.Fatalf("dial %s: %v", rt.name, err)
	}

	t.Cleanup(func() { _ = conn.Close() })

	hdr := rt.hdr.Clone()
	if withOrigin {
		hdr.Set("Origin", rt.origin)
	}

	return wsUpgrade(t, conn, rt.host, target, hdr)
}

// ---- the test ----

func TestT3Compat(t *testing.T) {
	bin := os.Getenv(t3BinaryEnv)
	if bin == "" {
		t.Skipf("%s is not set; this test runs against a real t3 executable", t3BinaryEnv)
	}

	srv := startT3(t, bin)
	t.Logf("t3 serve %s on %s", srv.version, srv.addr)

	rig := newDeviceRigOn(t, nil, srv.addr, "t3.b")
	control := directRoute(srv)
	routes := []*compatRoute{control, viewerRoute(rig), deviceRoute(rig)}

	rig.msh.newNode("b", &nodeOpts{t3Addr: srv.addr})
	t.Run("link-assets", func(t *testing.T) { checkLinkAssets(t, control, rig.a, srv) })

	ref := t3Reference(t, control)

	for _, rt := range routes {
		t.Run(rt.name, func(t *testing.T) {
			rt.checkUnpaired(t, ref)
			rt.checkLarge(t, ref)
			rt.checkPairing(t, srv)
			rt.checkWebSocket(t, srv)
		})
	}
}

// reference is what T3 answers on its own.
type reference struct {
	http      map[string]reply
	ws        map[string]reply
	assetPath string
	assetBody reply
}

// assetRe finds the static assets a page or script refers to.
var assetRe = regexp.MustCompile(`/?assets/[A-Za-z0-9_.-]+\.(?:js|css)`)

const maxCrawl = 80

// largestAsset follows the scripts T3's index loads, and the ones they list, and
// returns the biggest it finds: a large body that proxies must pass whole.
func largestAsset(t *testing.T, control *compatRoute, index []byte) (string, reply) {
	t.Helper()

	var (
		best     string
		bestRep  reply
		seen     = map[string]bool{}
		frontier = [][]byte{index}
	)

	for depth := 0; depth < 2 && len(seen) < maxCrawl; depth++ {
		var next [][]byte

		for _, page := range frontier {
			for _, found := range assetRe.FindAll(page, -1) {
				path := "/" + strings.TrimPrefix(string(found), "/")
				if seen[path] || len(seen) >= maxCrawl {
					continue
				}

				seen[path] = true

				rep := control.do(t, http.MethodGet, path, nil, "")
				if rep.status != http.StatusOK {
					continue
				}

				next = append(next, rep.body)

				if len(rep.body) > len(bestRep.body) {
					best, bestRep = path, rep
				}
			}
		}

		frontier = next
	}

	return best, bestRep
}

// t3Reference records what T3 answers on its own, and fails early when T3 no
// longer looks like the server this test was written against.
func t3Reference(t *testing.T, control *compatRoute) *reference {
	t.Helper()

	ref := &reference{http: map[string]reply{}, ws: map[string]reply{}}

	for _, spec := range unpairedSpecs() {
		ref.http[spec.name] = control.unpaired(t, &spec)
	}

	for _, spec := range upgradeSpecs() {
		up := control.rawUpgrade(t, spec.target, true)
		ref.ws[spec.name] = reply{status: up.status, header: up.header, body: []byte(up.body)}
	}

	env := ref.http["environment"]

	var doc struct {
		EnvironmentID string `json:"environmentId"`
		ServerVersion string `json:"serverVersion"`
		Protocol      int    `json:"orchestrationProtocolVersion"`
	}

	err := json.Unmarshal(env.body, &doc)
	if env.status != http.StatusOK || err != nil || doc.EnvironmentID == "" || doc.Protocol == 0 {
		t.Fatalf("T3's %s changed: %d %s (%v); the test needs updating",
			envPath, env.status, clip(env.body), err)
	}

	index := ref.http["index"]
	if index.status != http.StatusOK || !strings.Contains(string(index.body), "<html") {
		t.Fatalf("T3's / is not a page any more: %d %s", index.status, clip(index.body))
	}

	ref.assetPath, ref.assetBody = largestAsset(t, control, index.body)

	return ref
}

func (rt *compatRoute) checkUnpaired(t *testing.T, ref *reference) {
	t.Helper()

	t.Run("unpaired", func(t *testing.T) {
		for _, spec := range unpairedSpecs() {
			t.Run(spec.name, func(t *testing.T) {
				sameReply(t, rt.name, ref.http[spec.name], rt.unpaired(t, &spec))
			})
		}
	})

	t.Run("unpaired-websocket", func(t *testing.T) {
		for _, spec := range upgradeSpecs() {
			t.Run(spec.name, func(t *testing.T) {
				up := rt.rawUpgrade(t, spec.target, true)
				got := reply{status: up.status, header: up.header, body: []byte(up.body)}

				sameReply(t, rt.name, ref.ws[spec.name], got)
			})
		}
	})
}

// checkLarge fetches T3's main script through the route and compares it, byte for
// byte, with what T3 serves on its own.
func (rt *compatRoute) checkLarge(t *testing.T, ref *reference) {
	t.Helper()

	t.Run("large-response", func(t *testing.T) {
		if ref.assetPath == "" {
			t.Skip("no static asset found from T3's index")
		}

		want := ref.assetBody
		got := rt.do(t, http.MethodGet, ref.assetPath, nil, "")

		if got.status != want.status || len(got.body) != len(want.body) {
			t.Fatalf("%s on %s: status %d, %d bytes; T3 itself: %d, %d bytes",
				ref.assetPath, rt.name, got.status, len(got.body), want.status, len(want.body))
		}

		if digest(got.body) != digest(want.body) {
			t.Fatalf("%s on %s: %d bytes arrive altered", ref.assetPath, rt.name, len(got.body))
		}

		t.Logf("%s: %d bytes intact", ref.assetPath, len(got.body))
	})
}

func digest(b []byte) string {
	sum := sha256.Sum256(b)

	return hex.EncodeToString(sum[:])
}

// ---- pairing ----

// bearerFor redeems a fresh pairing credential for a bearer token, the way the
// mobile app does.
func (rt *compatRoute) bearerFor(t *testing.T, srv *t3Server) string {
	t.Helper()

	form := url.Values{
		"grant_type": {tokenGrant}, "subject_token": {srv.pairingCredential(t)},
		"subject_token_type": {tokenBoot}, "requested_token_type": {tokenAccess},
		"client_label": {"t3-mesh compat"}, "client_device_type": {"mobile"},
	}

	rep := rt.do(t, http.MethodPost, oauthPath, http.Header{
		"Content-Type": {formType}, "Accept": {jsonType},
	}, form.Encode())

	var tok struct {
		AccessToken string `json:"access_token"` //nolint:tagliatelle // OAuth wire name
		TokenType   string `json:"token_type"`   //nolint:tagliatelle // OAuth wire name
	}

	err := json.Unmarshal(rep.body, &tok)
	if rep.status != http.StatusOK || err != nil || tok.AccessToken == "" ||
		tok.TokenType != "Bearer" {
		t.Fatalf("redeeming a pairing credential on %s: %d %s (%v)",
			rt.name, rep.status, clip(rep.body), err)
	}

	return tok.AccessToken
}

func bearer(token string) http.Header {
	return http.Header{"Authorization": {"Bearer " + token}, "Accept": {jsonType}}
}

// sessionAuthenticated asks T3 who the credentials in hdr are.
func (rt *compatRoute) sessionAuthenticated(t *testing.T, hdr http.Header) bool {
	t.Helper()

	rep := rt.do(t, http.MethodGet, sessionPath, hdr, "")

	var doc struct {
		Authenticated bool `json:"authenticated"`
	}

	err := json.Unmarshal(rep.body, &doc)
	if rep.status != http.StatusOK || err != nil {
		t.Fatalf("GET %s on %s: %d %s (%v)", sessionPath, rt.name, rep.status, clip(rep.body), err)
	}

	return doc.Authenticated
}

// ticketFor mints a WebSocket ticket for the RPC socket, falling back to the bare
// path as the apps do for a server that predates ticket audiences.
func (rt *compatRoute) ticketFor(t *testing.T, token string) string {
	t.Helper()

	rep := rt.do(t, http.MethodPost, ticketPath+"/rpc", bearer(token), "")
	if rep.status == http.StatusNotFound {
		rep = rt.do(t, http.MethodPost, ticketPath, bearer(token), "")
	}

	var doc struct {
		Ticket string `json:"ticket"`
	}

	err := json.Unmarshal(rep.body, &doc)
	if rep.status != http.StatusOK || err != nil || doc.Ticket == "" {
		t.Fatalf("minting a WebSocket ticket on %s: %d %s (%v)",
			rt.name, rep.status, clip(rep.body), err)
	}

	return doc.Ticket
}

func (rt *compatRoute) checkPairing(t *testing.T, srv *t3Server) {
	t.Helper()

	t.Run("pairing-bearer", func(t *testing.T) {
		token := rt.bearerFor(t, srv)

		if !rt.sessionAuthenticated(t, bearer(token)) {
			t.Fatalf("T3 on %s does not know the bearer token it just issued", rt.name)
		}

		if rt.sessionAuthenticated(t, bearer("not-"+token)) {
			t.Fatalf("T3 on %s accepts a token it never issued", rt.name)
		}

		_ = rt.ticketFor(t, token)
	})

	// The web app pairs with a session cookie, from a page whose origin is the host
	// the proxies forward.
	t.Run("pairing-cookie", func(t *testing.T) {
		rep := rt.do(t, http.MethodPost, browserPath, http.Header{
			"Content-Type": {jsonType}, "Origin": {rt.origin},
		}, `{"credential":"`+srv.pairingCredential(t)+`"}`)

		cookies := (&http.Response{Header: rep.header}).Cookies()
		if rep.status != http.StatusOK || len(cookies) == 0 {
			t.Fatalf("browser session on %s: %d %s, cookies %v",
				rt.name, rep.status, clip(rep.body), rep.header.Values("Set-Cookie"))
		}

		hdr := http.Header{"Cookie": {cookies[0].Name + "=" + cookies[0].Value}}
		if !rt.sessionAuthenticated(t, hdr) {
			t.Fatalf("T3 on %s does not accept the session cookie it just set", rt.name)
		}

		// The proxies tell T3 the page is on https (X-Forwarded-Proto), and T3 then marks
		// the session cookie Secure; the direct route is plain http.
		if rt.name != "direct" && !cookies[0].Secure {
			t.Errorf(
				"the session cookie on %s is not Secure: T3 did not see X-Forwarded-Proto: https",
				rt.name,
			)
		}
	})
}

// ---- RPC socket ----

// rpcFrame is the part of an Effect RPC message the test reads.
type rpcFrame struct {
	Tag       string `json:"_tag"` //nolint:tagliatelle // Effect wire name
	RequestID string `json:"requestId"`
	Exit      struct {
		Tag string `json:"_tag"` //nolint:tagliatelle // Effect wire name
	} `json:"exit"`
}

func rpcRequest(id, tag string) []byte {
	return []byte(
		`{"_tag":"Request","id":"` + id + `","tag":"` + tag + `","payload":{},"headers":[]}`,
	)
}

// await reads messages until done accepts one, and returns its size.
func awaitRPC(t *testing.T, ws *wsConn, what string, done func(f *rpcFrame) bool) int {
	t.Helper()

	end := time.Now().Add(rpcWait)

	for time.Now().Before(end) {
		msg, err := ws.next(time.Until(end))
		if err != nil {
			t.Fatalf("%s: %v", what, err)
		}

		if msg.op == wsOpClose {
			t.Fatalf("%s: T3 closed the socket", what)
		}

		var frame rpcFrame

		if msg.op == wsOpText && json.Unmarshal(msg.payload, &frame) == nil && done(&frame) {
			return len(msg.payload)
		}
	}

	t.Fatalf("%s: no answer within %s", what, rpcWait)

	return 0
}

// call sends an RPC and waits for its successful exit; it returns the message size.
func callRPC(t *testing.T, ws *wsConn, id, tag string) int {
	t.Helper()

	err := ws.send(wsOpText, rpcRequest(id, tag))
	if err != nil {
		t.Fatalf("%s: %v", tag, err)
	}

	var failed string

	size := awaitRPC(t, ws, tag, func(f *rpcFrame) bool {
		if f.Tag != "Exit" || f.RequestID != id {
			return false
		}

		if f.Exit.Tag != "Success" {
			failed = f.Exit.Tag
		}

		return true
	})

	if failed != "" {
		t.Fatalf("%s ended in %s", tag, failed)
	}

	return size
}

// openRPC pairs, mints a ticket and opens the RPC socket.
func (rt *compatRoute) openRPC(t *testing.T, token string, withOrigin bool) *wsConn {
	t.Helper()

	target := "/ws?" + orchestrationQuery + "&wsTicket=" + url.QueryEscape(rt.ticketFor(t, token))

	up := rt.rawUpgrade(t, target, withOrigin)
	if up.status != http.StatusSwitchingProtocols {
		t.Fatalf(
			"RPC socket on %s: upgrade answered %d %s",
			rt.name,
			up.status,
			clip([]byte(up.body)),
		)
	}

	return up.ws
}

// holdOpen keeps a socket up for d, exchanging protocol and WebSocket pings, as a
// phone does between requests.
func holdOpen(t *testing.T, ws *wsConn, d time.Duration) {
	t.Helper()

	for end := time.Now().Add(d); time.Now().Before(end); {
		err := ws.send(wsOpText, []byte(`{"_tag":"Ping"}`))
		if err == nil {
			err = ws.send(wsOpPing, []byte("t3-mesh"))
		}

		if err != nil {
			t.Fatalf("ping: %v", err)
		}

		var gotPong, gotFrame bool

		for !gotPong || !gotFrame {
			msg, err := ws.next(5 * time.Second)
			if err != nil {
				t.Fatalf("waiting for pong (protocol %v, WebSocket %v): %v", gotPong, gotFrame, err)
			}

			switch msg.op {
			case wsOpPong:
				gotFrame = true
			case wsOpClose:
				t.Fatal("T3 closed the socket while it was idle")
			case wsOpText:
				if strings.Contains(string(msg.payload), `"Pong"`) {
					gotPong = true
				}
			}
		}

		<-time.After(time.Second)
	}
}

func (rt *compatRoute) checkWebSocket(t *testing.T, srv *t3Server) {
	t.Helper()

	t.Run("websocket", func(t *testing.T) {
		token := rt.bearerFor(t, srv)

		for _, withOrigin := range []bool{true, false} {
			name := "no-origin"
			if withOrigin {
				name = "origin"
			}

			t.Run(name, func(t *testing.T) {
				ws := rt.openRPC(t, token, withOrigin)
				defer func() { _ = ws.conn.Close() }()

				rt.exerciseSocket(t, ws)
			})
		}
	})
}

// exerciseSocket makes the requests the apps make on connect, reads a large
// message and a stream, keeps the socket open, and closes it cleanly.
func (rt *compatRoute) exerciseSocket(t *testing.T, ws *wsConn) {
	t.Helper()

	_ = callRPC(t, ws, "1", "server.probe")

	size := callRPC(t, ws, "2", "server.getConfig")
	t.Logf("%s: server.getConfig answered in one %d byte message", rt.name, size)

	// A subscription stays open and streams; the first chunk shows it does.
	err := ws.send(wsOpText, rpcRequest("3", "subscribeServerConfig"))
	if err != nil {
		t.Fatal(err)
	}

	chunk := awaitRPC(t, ws, "subscribeServerConfig", func(f *rpcFrame) bool {
		return f.Tag == "Chunk" && f.RequestID == "3"
	})
	t.Logf("%s: subscription chunk of %d bytes", rt.name, chunk)

	holdOpen(t, ws, holdFor)

	_ = callRPC(t, ws, "4", "server.probe")

	err = ws.close()
	if err != nil {
		t.Fatalf("closing the socket: %v", err)
	}
}

// assetRPC returns the value from an Effect RPC exit.
func assetRPC(t *testing.T, ws *wsConn, id, tag string, payload any) json.RawMessage {
	t.Helper()

	request, err := json.Marshal(
		map[string]any{
			"_tag":    "Request",
			"id":      id,
			"tag":     tag,
			"payload": payload,
			"headers": []any{},
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	err = ws.send(wsOpText, request)
	if err != nil {
		t.Fatal(err)
	}

	for {
		msg, err := ws.next(rpcWait)
		if err != nil {
			t.Fatal(err)
		}

		var frame struct {
			Tag       string `json:"_tag"` //nolint:tagliatelle // Effect wire name
			RequestID string `json:"requestId"`
			Exit      struct {
				Tag   string          `json:"_tag"` //nolint:tagliatelle // Effect wire name
				Value json.RawMessage `json:"value"`
			} `json:"exit"`
		}
		if msg.op != wsOpText || json.Unmarshal(msg.payload, &frame) != nil ||
			frame.Tag != "Exit" ||
			frame.RequestID != id {
			continue
		}

		if frame.Exit.Tag != "Success" {
			t.Fatalf("%s: %s", tag, msg.payload)
		}

		return frame.Exit.Value
	}
}

//nolint:gocyclo // Exercises both upload and signed download flows.
func checkLinkAssets(t *testing.T, control *compatRoute, source *node, srv *t3Server) {
	t.Helper()
	token := control.bearerFor(t, srv)

	ws := control.openRPC(t, token, true)
	defer func() { _ = ws.conn.Close() }()

	png, err := base64.StdEncoding.DecodeString(
		"iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+/a0sAAAAASUVORK5CYII=",
	)
	if err != nil {
		t.Fatal(err)
	}

	for i, spec := range []struct{ name, mime, kind, body, mode, dest string }{
		{"image.png", "image/png", "image", string(png), "no-cors", "image"},
		{"preview.html", "text/html", "file", "<!doctype html><p>compat preview</p>", "navigate", "iframe"},
	} {
		t.Run(spec.dest, func(t *testing.T) {
			payload := map[string]any{
				"type":      spec.kind,
				"name":      spec.name,
				"mimeType":  spec.mime,
				"sizeBytes": len(spec.body),
			}

			var upload struct {
				AttachmentID string `json:"attachmentId"`
				RelativeURL  string `json:"relativeUrl"`
			}

			err = json.Unmarshal(
				assetRPC(t, ws, strconv.Itoa(i*2+10), "attachments.createUploadUrl", payload),
				&upload,
			)
			if err != nil ||
				upload.RelativeURL == "" {
				t.Fatalf("upload URL: %+v %v", upload, err)
			}

			rep := control.do(
				t,
				http.MethodPost,
				upload.RelativeURL,
				http.Header{"Content-Type": {spec.mime}},
				spec.body,
			)
			if rep.status < 200 || rep.status >= 300 {
				t.Fatalf("upload: %d %s", rep.status, rep.body)
			}

			resource := map[string]any{
				"_tag":         "attachment",
				"attachmentId": upload.AttachmentID,
				"fileName":     spec.name,
				"mimeType":     spec.mime,
				"disposition":  "inline",
			}

			var asset struct {
				RelativeURL string `json:"relativeUrl"`
			}

			err = json.Unmarshal(
				assetRPC(
					t,
					ws,
					strconv.Itoa(i*2+11),
					"assets.createUrl",
					map[string]any{"resource": resource},
				),
				&asset,
			)
			if err != nil ||
				asset.RelativeURL == "" {
				t.Fatalf("asset URL: %+v %v", asset, err)
			}

			hdr := http.Header{
				"Sec-Fetch-Site": {"cross-site"},
				"Sec-Fetch-Mode": {spec.mode},
				"Sec-Fetch-Dest": {spec.dest},
			}
			want := control.do(t, http.MethodGet, asset.RelativeURL, nil, "")
			link := &compatRoute{
				name:   "link",
				base:   source.linkURL(""),
				host:   strings.TrimPrefix(source.linkURL(""), "http://"),
				client: &http.Client{Timeout: 30 * time.Second},
			}

			got := link.do(t, http.MethodGet, asset.RelativeURL, hdr, "")
			if want.status != http.StatusOK || got.status != want.status ||
				!bytes.Equal(got.body, want.body) {
				t.Fatalf(
					"asset direct=%d %q link=%d %q",
					want.status,
					clip(want.body),
					got.status,
					clip(got.body),
				)
			}

			if spec.dest == "iframe" &&
				(!strings.Contains(got.header.Get("Content-Security-Policy"), "sandbox") ||
					got.header.Get("X-Content-Type-Options") != "nosniff") {
				t.Fatalf("missing sandbox headers: %v", got.header)
			}
		})
	}
}
