package hub

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/yamux"

	"github.com/zekihan/t3-mesh/internal/hub/hubconfig"
	"github.com/zekihan/t3-mesh/internal/policy"
	"github.com/zekihan/t3-mesh/internal/proto"
	"github.com/zekihan/t3-mesh/internal/tunnel"
)

// rejectGrace is how long a rejected session may drain before it is forced closed.
const rejectGrace = 2 * time.Second

// Bounds on what an agent may announce in Hello and Status.
const (
	maxVersionLen        = 64
	maxLANAddrs          = 16
	maxAnnouncedServices = 64
	maxServiceNameLen    = 64
)

var (
	errSessionEnded   = errors.New("session ended")
	errControlEnded   = errors.New("control stream ended")
	errPushEnded      = errors.New("push loop ended")
	errClosedAfterRej = errors.New("closed by peer after reject")
	errRejected       = errors.New("rejected")
	errNoHello        = errors.New("control stream closed before hello")
	errHelloTimeout   = errors.New("hello timed out")
	errFirstNotHello  = errors.New("first message is not Hello")
)

type machineState struct {
	name         string
	sessions     []*session // ordered by hub accept time, oldest first
	lastSeen     time.Time
	certNotAfter time.Time
	lastLANAddrs []string
	version      string
	announced    []string
	status       *proto.Status
	warnings     []string
	lastPort     int
}

func (m *machineState) newestLive() *session {
	for _, v := range slices.Backward(m.sessions) {
		if !v.closing.Load() {
			return v
		}
	}

	return nil
}

// sentState is what the agent already has; used only by the push loop.
type sentState struct {
	rules, revs, trust, release, peers, cidrs, devices, viewerDomain string
	home                                                             bool
}

type session struct {
	// What the agent last reported about its listener for enrolled devices,
	// sanitized; nil while it is not bound. Guarded by server.mu.
	device      *proto.DeviceListener
	notAfter    time.Time
	accepted    time.Time
	source      netip.Addr
	closeErr    error
	ctx         context.Context //nolint:containedctx // the session owns its lifetime context, shared by its goroutines
	leaf        *x509.Certificate
	kick        chan struct{}
	conn        *tls.Conn
	ymx         *yamux.Session
	ctrl        *tunnel.Control
	log         *slog.Logger
	cancel      context.CancelFunc
	s           *Server
	hello       proto.Hello
	fingerprint string
	identity    string
	machine     string
	sent        sentState
	streams     atomic.Int64
	id          uint64
	linkStream  atomic.Int64
	rejectOnce  sync.Once
	closeOnce   sync.Once
	renewing    atomic.Bool
	closing     atomic.Bool
	home        bool
}

func (sess *session) close(reason error) {
	sess.closeOnce.Do(func() {
		sess.closing.Store(true)
		sess.closeErr = reason
		sess.cancel()
		_ = sess.ctrl.Close()
		_ = sess.ymx.Close()
		sess.s.unregister(sess)
		sess.s.closeTrackedFor(sess)
	})
}

// reject sends Reject, ends routing to the session at once and closes it.
func (sess *session) reject(rej proto.Reject) {
	sess.rejectOnce.Do(func() {
		sess.closing.Store(true)
		sess.s.log.Info(
			"Reject",
			slog.Any("machine", sess.machine),
			slog.Any("identity", sess.identity),
			slog.Any("reason", rej.Reason),
			slog.Any("detail", rej.Detail),
		)
		//nolint:errcheck // best-effort notice; the peer may already be gone
		_ = sess.ctrl.Send(rej)
		sess.s.closeTrackedFor(sess)
		//nolint:errcheck // best-effort half-close; the connection is torn down right after
		_ = sess.conn.CloseWrite()

		grace := time.AfterFunc(
			rejectGrace,
			func() { sess.close(fmt.Errorf("%w: %s", errRejected, rej.Reason)) },
		)

		go func() {
			select {
			case <-sess.ymx.CloseChan():
				grace.Stop()
				sess.close(errClosedAfterRej)
			case <-sess.ctx.Done():
				grace.Stop()
			}
		}()
	})
}

func (sess *session) kickNow() {
	select {
	case sess.kick <- struct{}{}:
	default:
	}
}

func (server *Server) allSessions() []*session {
	server.mu.Lock()
	defer server.mu.Unlock()

	var out []*session
	for _, m := range server.machines {
		out = append(out, m.sessions...)
	}

	return out
}

func (server *Server) kickAll() {
	for _, c := range server.allSessions() {
		c.kickNow()
	}
}

func (server *Server) liveSession(machine string) *session {
	server.mu.Lock()
	defer server.mu.Unlock()

	if m := server.machines[machine]; m != nil {
		return m.newestLive()
	}

	return nil
}

func (server *Server) warnLocked(m *machineState, msg string) {
	m.warnings = append(m.warnings, server.now().UTC().Format(time.RFC3339)+" "+msg)
	if len(m.warnings) > maxWarnings {
		m.warnings = m.warnings[len(m.warnings)-maxWarnings:]
	}
}

func (server *Server) warn(machine, msg string) {
	server.mu.Lock()
	defer server.mu.Unlock()

	server.warnLocked(server.machineLocked(machine), msg)
}

func (server *Server) machineLocked(name string) *machineState {
	m := server.machines[name]
	if m == nil {
		m = &machineState{name: name}
		server.machines[name] = m
	}

	return m
}

func (server *Server) register(sess *session) []*session {
	server.mu.Lock()
	defer server.mu.Unlock()

	state := server.machineLocked(sess.machine)
	state.sessions = append(state.sessions, sess)
	state.lastSeen = server.now()
	state.version = sess.hello.Version
	state.announced = sess.hello.Services
	state.lastLANAddrs = slices.Clone(sess.hello.LANAddrs)
	state.lastPort = sess.hello.DirectPort
	state.certNotAfter = sess.notAfter

	var superseded []*session

	if len(state.sessions) > maxSessionsPerMachine {
		superseded = slices.Clone(state.sessions[:len(state.sessions)-maxSessionsPerMachine])
	}

	return superseded
}

func (server *Server) unregister(c *session) {
	server.mu.Lock()
	m := server.machines[c.machine]

	if m != nil {
		m.sessions = slices.DeleteFunc(m.sessions, func(x *session) bool { return x == c })
		m.lastSeen = server.now()
	}
	server.mu.Unlock()

	server.kickAll()
}

func (server *Server) serveSession(
	ctx context.Context,
	conn *tls.Conn,
	source netip.Addr,
	state *tls.ConnectionState,
) {
	snap := server.cfg.Current()

	adm, err := server.admit(snap, state.PeerCertificates, server.now())
	if err != nil {
		server.log.InfoContext(
			ctx,
			"Rejected peer",
			slog.String("source", source.String()),
			slog.String("reason", err.Error()),
		)

		return
	}

	log := server.log.With(
		slog.Any("machine", adm.machine),
		slog.Any("identity", adm.identity),
		slog.Any("fingerprint", adm.fingerprint),
		slog.String("source", source.String()),
	)

	ymx, err := yamux.Server(conn, tunnel.YamuxConfig())
	if err != nil {
		log.WarnContext(
			ctx,
			"Yamux setup failed",
			slog.Any("error", err),
		)

		return
	}

	defer func() { _ = ymx.Close() }()

	actx, acancel := context.WithTimeout(ctx, helloTimeout)
	stream, err := ymx.AcceptStreamWithContext(actx)

	acancel()

	if err != nil {
		log.InfoContext(
			ctx,
			"No control stream",
			slog.String("error", err.Error()),
		)

		return
	}

	ctrl := tunnel.NewControl(stream)
	defer func() { _ = ctrl.Close() }()

	hello, err := readHello(ctx, ctrl)
	if err != nil {
		log.InfoContext(
			ctx,
			"Reject",
			slog.String("reason", "bad hello"),
			slog.String("error", err.Error()),
		)

		return
	}

	ok, noRecord, err := server.checkNewest(ctx, adm.identity, adm.fingerprint)

	switch {
	case err != nil:
		log.WarnContext(
			ctx,
			"Reject",
			slog.String("reason", "newest-leaf lookup failed"),
			slog.String("error", err.Error()),
		)

		rejectHello(ctx, conn, ymx, ctrl,
			proto.Reject{Reason: proto.RejectOther, Detail: "certificate check unavailable"},
		)

		return
	case !ok:
		log.InfoContext(
			ctx,
			"Reject",
			slog.Any("reason", proto.RejectLeafNotNewest),
		)
		server.warn(
			adm.machine,
			"tunnel refused: leaf "+adm.fingerprint+" is not the newest issued",
		)

		rejectHello(ctx, conn, ymx, ctrl,
			proto.Reject{
				Reason: proto.RejectLeafNotNewest,
				Detail: "a newer certificate was issued for this identity",
			},
		)

		return
	case noRecord:
		log.WarnContext(
			ctx,
			"No issuance record for leaf; admitting",
			slog.String("reason", "issuer has no record for identity"),
		)
		server.warn(adm.machine, "no issuance record for "+adm.identity+"; leaf admitted unchecked")
	}

	if hello.CertFingerprint != "" && !strings.EqualFold(hello.CertFingerprint, adm.fingerprint) {
		log.WarnContext(
			ctx,
			"Hello fingerprint differs from TLS leaf",
			slog.Any("announced", hello.CertFingerprint),
		)
	}

	sctx, cancel := context.WithCancel(ctx)
	defer cancel()

	sess := &session{
		s: server, machine: adm.machine, identity: adm.identity, fingerprint: adm.fingerprint,
		notAfter: adm.leaf.NotAfter, leaf: adm.leaf, source: source, accepted: server.now(),
		conn: conn, ymx: ymx, ctrl: ctrl, log: log, ctx: sctx, cancel: cancel,
		kick: make(chan struct{}, 1), hello: hello, home: snap.IsHome(source),
	}

	server.mu.Lock()
	server.nextID++
	sess.id = server.nextID
	server.mu.Unlock()

	for _, old := range server.register(sess) {
		old.reject(
			proto.Reject{Reason: proto.RejectOther, Detail: "too many sessions for this machine"},
		)
	}

	defer sess.close(errSessionEnded)

	err = sess.sendHelloAck()
	if err != nil {
		log.WarnContext(
			ctx,
			"Hello ack failed",
			slog.String("error", err.Error()),
		)

		return
	}

	sess.logConnect(snap)
	server.kickAll()

	var wg sync.WaitGroup

	wg.Go(sess.controlLoop)
	wg.Go(sess.acceptLoop)
	wg.Go(sess.pushLoop)
	wg.Go(func() {
		err := ctrl.RunLiveness(sctx, tunnel.PingInterval, tunnel.MaxMissed)
		sess.close(fmt.Errorf("liveness: %w", err))
	})

	<-sctx.Done()
	sess.close(context.Cause(sctx))
	wg.Wait()

	log.InfoContext(
		ctx,
		"Disconnect",
		slog.String("duration", server.now().Sub(sess.accepted).String()),
		slog.Any("reason", sess.closeErr),
	)
}

func rejectHello(
	ctx context.Context,
	conn *tls.Conn,
	ymx *yamux.Session,
	ctrl *tunnel.Control,
	rej proto.Reject,
) {
	err := ctrl.Send(rej)
	if err != nil {
		return
	}

	// Closing yamux now could fail the client's in-flight Hello write before
	// the client checks for Reject. Give the peer time to read it and disconnect.
	err = conn.SetReadDeadline(time.Now().Add(rejectGrace))
	if err != nil {
		return
	}

	select {
	case <-ymx.CloseChan():
	case <-ctx.Done():
	}
}

func readHello(ctx context.Context, ctrl *tunnel.Control) (proto.Hello, error) {
	timer := time.NewTimer(helloTimeout)
	defer timer.Stop()

	select {
	case msg, ok := <-ctrl.Messages():
		if !ok {
			return proto.Hello{}, errNoHello
		}

		hello, isHello := msg.(proto.Hello)
		if !isHello {
			return proto.Hello{}, fmt.Errorf("%w: got %s", errFirstNotHello, msg.MessageType())
		}

		return sanitizeHello(&hello), nil
	case <-timer.C:
		return proto.Hello{}, errHelloTimeout
	case <-ctx.Done():
		return proto.Hello{}, fmt.Errorf("hello: %w", ctx.Err())
	}
}

func sanitizeHello(incoming *proto.Hello) proto.Hello {
	hello := *incoming
	hello.Version = truncate(hello.Version, maxVersionLen)

	var addrs []string

	for _, a := range hello.LANAddrs {
		if len(addrs) >= maxLANAddrs {
			break
		}

		ip, err := netip.ParseAddr(a)
		if err == nil {
			addrs = append(addrs, ip.String())
		}
	}

	hello.LANAddrs = addrs

	if hello.DirectPort < 0 || hello.DirectPort > 65535 {
		hello.DirectPort = 0
	}

	svcs := slices.Clone(hello.Services)
	if len(svcs) > maxAnnouncedServices {
		svcs = svcs[:maxAnnouncedServices]
	}

	for i := range svcs {
		svcs[i] = truncate(svcs[i], maxServiceNameLen)
	}

	slices.Sort(svcs)
	hello.Services = slices.Compact(svcs)

	return hello
}

// sanitizeDeviceListener keeps what an agent reported about its device listener
// only when it is usable: a port, and at least one address that parses. Addresses
// are normalized, deduplicated and bounded like the LAN addresses of a Hello.
func sanitizeDeviceListener(in *proto.DeviceListener) *proto.DeviceListener {
	if in == nil || in.Port < 1 || in.Port > 65535 {
		return nil
	}

	addrs := make([]string, 0, min(len(in.Addrs), maxLANAddrs))

	for _, text := range in.Addrs {
		if len(addrs) >= maxLANAddrs {
			break
		}

		addr, err := netip.ParseAddr(text)
		if err != nil {
			continue
		}

		norm := addr.Unmap().WithZone("").String()
		if !slices.Contains(addrs, norm) {
			addrs = append(addrs, norm)
		}
	}

	if len(addrs) == 0 {
		return nil
	}

	return &proto.DeviceListener{Port: in.Port, Addrs: addrs}
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}

	return s
}

func serviceDiff(announced, configured []string) ([]string, []string) {
	var missing, unexpected []string

	for _, c := range configured {
		if !slices.Contains(announced, c) {
			missing = append(missing, c)
		}
	}

	for _, a := range announced {
		if !slices.Contains(configured, a) {
			unexpected = append(unexpected, a)
		}
	}

	return missing, unexpected
}

func (sess *session) logConnect(snap *hubconfig.Snapshot) {
	path := pathName(sess.home)
	sess.log.Info(
		"Connect",
		slog.Any("path", path),
		slog.String("version", sess.hello.Version),
		slog.Any("services", sess.hello.Services),
		slog.String("notAfter", sess.notAfter.UTC().Format(time.RFC3339)),
	)

	missing, unexpected := serviceDiff(sess.hello.Services, snap.Services(sess.machine))
	if len(missing) > 0 || len(unexpected) > 0 {
		sess.log.Warn(
			"Announced services differ from configuration",
			slog.Any("missing", missing),
			slog.Any("unexpected", unexpected),
		)
		sess.s.warn(
			sess.machine,
			fmt.Sprintf("announced services differ: missing=%v unexpected=%v", missing, unexpected),
		)
	}
}

// Path names of a tunnel: through the LAN or through the public gateways.
const (
	pathLAN = "LAN"
	pathOCI = "OCI"
)

func pathName(home bool) string {
	if home {
		return pathLAN
	}

	return pathOCI
}

type desired struct {
	rules   proto.Rules
	revs    proto.Revocations
	trust   proto.TrustBundle
	release proto.Release
	peers   proto.PeerTable
	// Nil when the issuer could not say, and then nothing is sent.
	devices      *proto.DeviceLeaves
	viewerDomain string
	cidrs        []string
	home         bool
}

// desiredState computes what the agent should hold now. It updates the
// session's home flag from the current configuration.
func (sess *session) desiredState() (desired, bool) {
	var (
		want        desired
		homeChanged bool
	)

	snap := sess.s.cfg.Current()
	home := snap.IsHome(sess.source)
	want.devices = sess.s.deviceLeaves(sess.ctx, snap)

	if want.devices == nil {
		// The issuer could not say; ask again soon rather than wait for the next change.
		time.AfterFunc(sess.s.deviceRetry, sess.kickNow)
	}

	sess.s.mu.Lock()
	if home != sess.home {
		sess.home = home
		homeChanged = true
	}

	want.peers = sess.s.peersLocked(snap, sess)
	sess.s.mu.Unlock()

	want.home = home
	want.rules = snap.Rules
	want.revs = snap.Revocations
	want.trust = snap.TrustBundle
	want.release = snap.Release
	want.viewerDomain = snap.ViewerDomain

	for _, p := range snap.HomePrefixes {
		want.cidrs = append(want.cidrs, p.String())
	}

	return want, homeChanged
}

func (sess *session) sendHelloAck() error {
	want, _ := sess.desiredState()

	err := sess.ctrl.Send(proto.HelloAck{
		Machine: sess.machine, Home: want.home, Release: want.release, Rules: want.rules,
		Peers: want.peers, Revocations: want.revs, TrustBundle: want.trust, HomeCIDRs: want.cidrs,
		DeviceLeaves: want.devices, ViewerDomain: want.viewerDomain,
	})
	if err != nil {
		return fmt.Errorf("hub: send HelloAck: %w", err)
	}

	sess.sent = sentState{
		rules: want.rules.Revision, revs: want.revs.Revision, trust: want.trust.Revision,
		release: want.release.Revision, peers: want.peers.Revision, home: want.home,
		cidrs: strings.Join(want.cidrs, ","), viewerDomain: want.viewerDomain,
	}

	if want.devices != nil {
		sess.sent.devices = want.devices.Revision
	}

	return nil
}

func (sess *session) pushLoop() {
	defer sess.close(errPushEnded)

	for {
		select {
		case <-sess.ctx.Done():
			return
		case <-sess.kick:
			err := sess.push()
			if err != nil {
				sess.log.Warn(
					"Update failed",
					slog.String("error", err.Error()),
				)

				return
			}
		}
	}
}

func (sess *session) push() error {
	want, homeChanged := sess.desiredState()
	if homeChanged {
		sess.log.Info(
			"Path change",
			slog.Any("path", pathName(want.home)),
		)
		sess.s.kickAll()
	}

	upd, dirt := sess.diff(&want)
	if dirt {
		err := sess.ctrl.Send(upd)
		if err != nil {
			return fmt.Errorf("hub: send Update: %w", err)
		}

		sess.sent.rules = want.rules.Revision
		sess.sent.revs = want.revs.Revision
		sess.sent.trust = want.trust.Revision
		sess.sent.peers = want.peers.Revision
		sess.sent.home = want.home
		sess.sent.cidrs = strings.Join(want.cidrs, ",")
		sess.sent.viewerDomain = want.viewerDomain

		if want.devices != nil {
			sess.sent.devices = want.devices.Revision
		}
	}

	if want.release.Revision != sess.sent.release {
		err := sess.ctrl.Send(want.release)
		if err != nil {
			return fmt.Errorf("hub: send Release: %w", err)
		}

		sess.sent.release = want.release.Revision
	}

	return nil
}

// diff builds the Update holding what differs from what the agent already has.
func (sess *session) diff(want *desired) (proto.Update, bool) {
	var (
		upd  proto.Update
		dirt bool
	)

	if want.rules.Revision != sess.sent.rules {
		upd.Rules, dirt = &want.rules, true
	}

	if want.revs.Revision != sess.sent.revs {
		upd.Revocations, dirt = &want.revs, true
	}

	if want.trust.Revision != sess.sent.trust {
		upd.TrustBundle, dirt = &want.trust, true
	}

	if want.peers.Revision != sess.sent.peers {
		upd.Peers, dirt = &want.peers, true
	}

	if want.devices != nil && want.devices.Revision != sess.sent.devices {
		upd.DeviceLeaves, dirt = want.devices, true
	}

	if want.viewerDomain != sess.sent.viewerDomain {
		domain := want.viewerDomain
		upd.ViewerDomain, dirt = &domain, true
	}

	if want.home != sess.sent.home {
		h := want.home
		upd.Home, dirt = &h, true
	}

	if cidrs := strings.Join(want.cidrs, ","); cidrs != sess.sent.cidrs {
		list := slices.Clone(want.cidrs)
		if list == nil {
			list = []string{}
		}

		upd.HomeCIDRs, dirt = &list, true
	}

	return upd, dirt
}

// Builds the peer table for the given session; server.mu must be held.
func (server *Server) peersLocked(snap *hubconfig.Snapshot, sess *session) proto.PeerTable {
	names := make([]string, 0, len(snap.Machines))
	for n := range snap.Machines {
		names = append(names, n)
	}

	slices.Sort(names)

	peers := []proto.Peer{}

	for _, name := range names {
		if name == sess.machine {
			continue
		}

		var svcs []string

		for _, svc := range snap.Services(name) {
			if policy.Allowed(snap.Rules, sess.identity, svc, name) {
				svcs = append(svcs, svc)
			}
		}

		if len(svcs) == 0 {
			continue
		}

		peer := proto.Peer{Machine: name, Identity: snap.Machines[name].Identity, Services: svcs}

		if ms := server.machines[name]; ms != nil {
			if live := ms.newestLive(); live != nil {
				peer.LANAddrs = live.hello.LANAddrs
				peer.DirectPort = live.hello.DirectPort
				peer.Home = live.home
			} else {
				// Offline: last-known addresses let agents try them during a hub outage.
				peer.LANAddrs = ms.lastLANAddrs
				peer.DirectPort = ms.lastPort
			}
		}

		peers = append(peers, peer)
	}

	//nolint:errcheck,errchkjson // Peer holds only strings, numbers and slices, so Marshal cannot fail
	data, _ := json.Marshal(peers)
	sum := sha256.Sum256(data)

	return proto.PeerTable{Revision: hex.EncodeToString(sum[:8]), Peers: peers}
}

func (sess *session) controlLoop() {
	defer sess.close(errControlEnded)

	for msg := range sess.ctrl.Messages() {
		switch typed := msg.(type) {
		case proto.Status:
			sess.s.recordStatus(sess, &typed)
		case proto.Renew:
			if !sess.renewing.CompareAndSwap(false, true) {
				//nolint:errcheck // best-effort notice; the peer may already be gone
				_ = sess.ctrl.Send(
					proto.Reject{
						Reason: proto.RejectRenewFailed,
						Detail: "renewal already in progress",
					},
				)

				continue
			}

			sess.s.wg.Go(func() {
				defer sess.renewing.Store(false)

				sess.handleRenew(typed)
			})
		default:
			sess.log.Debug(
				"Unexpected control message",
				slog.Any("type", msg.MessageType()),
			)
		}
	}
}

func (sess *session) acceptLoop() {
	for {
		st, err := sess.ymx.AcceptStream()
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				sess.close(fmt.Errorf("accept stream: %w", err))
			} else {
				sess.close(err)
			}

			return
		}

		sess.s.wg.Go(func() { sess.s.handleAgentStream(sess, st) })
	}
}

func (server *Server) recordStatus(sess *session, st *proto.Status) {
	server.mu.Lock()
	defer server.mu.Unlock()

	m := server.machineLocked(sess.machine)
	cp := *st
	m.status = &cp
	sess.device = sanitizeDeviceListener(st.DeviceListener)

	if st.Version != "" {
		m.version = truncate(st.Version, maxVersionLen)
	}
}
