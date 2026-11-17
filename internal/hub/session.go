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

// rejectGrace is how long a rejected session may drain before it is forced
// closed. The hub half-closes the TLS connection at once after Reject.
const rejectGrace = 2 * time.Second

type machineState struct {
	name         string
	sessions     []*session // ordered by hub accept time, oldest first
	lastSeen     time.Time
	version      string
	announced    []string
	certNotAfter time.Time
	status       *proto.Status
	warnings     []string
}

func (m *machineState) newestLive() *session {
	for i := len(m.sessions) - 1; i >= 0; i-- {
		if !m.sessions[i].closing.Load() {
			return m.sessions[i]
		}
	}

	return nil
}

// sentState is what the agent already has; used only by the push loop.
type sentState struct {
	rules, revs, trust, release, peers, cidrs string
	home                                      bool
}

type session struct {
	s           *Server
	id          uint64
	machine     string
	identity    string
	fingerprint string
	notAfter    time.Time
	leaf        *x509.Certificate
	source      netip.Addr
	accepted    time.Time
	conn        *tls.Conn
	ymx         *yamux.Session
	ctrl        *tunnel.Control
	log         *slog.Logger
	ctx         context.Context
	cancel      context.CancelFunc

	closing    atomic.Bool
	closeOnce  sync.Once
	rejectOnce sync.Once
	closeErr   error
	kick       chan struct{}
	renewing   atomic.Bool
	streams    atomic.Int64
	linkStream atomic.Int64

	// guarded by s.mu
	hello proto.Hello
	home  bool

	sent sentState
}

func (c *session) close(reason error) {
	c.closeOnce.Do(func() {
		c.closing.Store(true)
		c.closeErr = reason
		c.cancel()
		_ = c.ctrl.Close()
		_ = c.ymx.Close()
		c.s.unregister(c)
		c.s.closeTrackedFor(c)
	})
}

// reject sends Reject, ends routing to the session at once and closes it.
func (c *session) reject(rej proto.Reject) {
	c.rejectOnce.Do(func() {
		c.closing.Store(true)
		c.s.log.Info(
			"reject",
			"machine",
			c.machine,
			"identity",
			c.identity,
			"reason",
			rej.Reason,
			"detail",
			rej.Detail,
		)
		_ = c.ctrl.Send(rej)
		c.s.closeTrackedFor(c)
		_ = c.conn.CloseWrite()

		t := time.AfterFunc(rejectGrace, func() { c.close(fmt.Errorf("rejected: %s", rej.Reason)) })
		go func() {
			select {
			case <-c.ymx.CloseChan():
				t.Stop()
				c.close(errors.New("closed by peer after reject"))
			case <-c.ctx.Done():
				t.Stop()
			}
		}()
	})
}

func (c *session) kickNow() {
	select {
	case c.kick <- struct{}{}:
	default:
	}
}

func (s *Server) allSessions() []*session {
	s.mu.Lock()
	defer s.mu.Unlock()

	var out []*session
	for _, m := range s.machines {
		out = append(out, m.sessions...)
	}

	return out
}

func (s *Server) kickAll() {
	for _, c := range s.allSessions() {
		c.kickNow()
	}
}

func (s *Server) liveSession(machine string) *session {
	s.mu.Lock()
	defer s.mu.Unlock()

	if m := s.machines[machine]; m != nil {
		return m.newestLive()
	}

	return nil
}

func (s *Server) warnLocked(m *machineState, msg string) {
	m.warnings = append(m.warnings, s.now().UTC().Format(time.RFC3339)+" "+msg)
	if len(m.warnings) > maxWarnings {
		m.warnings = m.warnings[len(m.warnings)-maxWarnings:]
	}
}

func (s *Server) warn(machine, msg string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.warnLocked(s.machineLocked(machine), msg)
}

func (s *Server) machineLocked(name string) *machineState {
	m := s.machines[name]
	if m == nil {
		m = &machineState{name: name}
		s.machines[name] = m
	}

	return m
}

func (s *Server) register(c *session) (superseded []*session) {
	s.mu.Lock()
	defer s.mu.Unlock()

	m := s.machineLocked(c.machine)
	m.sessions = append(m.sessions, c)
	m.lastSeen = s.now()
	m.version = c.hello.Version
	m.announced = c.hello.Services
	m.certNotAfter = c.notAfter

	if len(m.sessions) > maxSessionsPerMachine {
		superseded = slices.Clone(m.sessions[:len(m.sessions)-maxSessionsPerMachine])
	}

	return superseded
}

func (s *Server) unregister(c *session) {
	s.mu.Lock()
	m := s.machines[c.machine]

	if m != nil {
		m.sessions = slices.DeleteFunc(m.sessions, func(x *session) bool { return x == c })
		m.lastSeen = s.now()
	}
	s.mu.Unlock()

	s.kickAll()
}

func (s *Server) serveSession(
	ctx context.Context,
	conn *tls.Conn,
	source netip.Addr,
	state tls.ConnectionState,
) {
	snap := s.cfg.Current()

	adm, err := s.admit(snap, state.PeerCertificates, s.now())
	if err != nil {
		s.log.Info("rejected peer", "source", source.String(), "reason", err.Error())

		return
	}

	log := s.log.With(
		"machine",
		adm.machine,
		"identity",
		adm.identity,
		"fingerprint",
		adm.fingerprint,
		"source",
		source.String(),
	)

	ymx, err := yamux.Server(conn, tunnel.YamuxConfig())
	if err != nil {
		log.Warn("yamux setup failed", "error", err)

		return
	}

	defer func() { _ = ymx.Close() }()

	actx, acancel := context.WithTimeout(ctx, helloTimeout)
	stream, err := ymx.AcceptStreamWithContext(actx)

	acancel()

	if err != nil {
		log.Info("no control stream", "error", err.Error())

		return
	}

	ctrl := tunnel.NewControl(stream)
	defer func() { _ = ctrl.Close() }()

	hello, err := readHello(ctx, ctrl)
	if err != nil {
		log.Info("reject", "reason", "bad hello", "error", err.Error())

		return
	}

	ok, noRecord, err := s.checkNewest(ctx, adm.identity, adm.fingerprint)

	switch {
	case err != nil:
		log.Warn("reject", "reason", "newest-leaf lookup failed", "error", err.Error())
		_ = ctrl.Send(
			proto.Reject{Reason: proto.RejectOther, Detail: "certificate check unavailable"},
		)

		return
	case !ok:
		log.Info("reject", "reason", proto.RejectLeafNotNewest)
		s.warn(adm.machine, "tunnel refused: leaf "+adm.fingerprint+" is not the newest issued")
		_ = ctrl.Send(
			proto.Reject{
				Reason: proto.RejectLeafNotNewest,
				Detail: "a newer certificate was issued for this identity",
			},
		)

		return
	case noRecord:
		log.Warn(
			"no issuance record for leaf; admitting",
			"reason",
			"issuer has no record for identity",
		)
		s.warn(adm.machine, "no issuance record for "+adm.identity+"; leaf admitted unchecked")
	}

	if hello.CertFingerprint != "" && !strings.EqualFold(hello.CertFingerprint, adm.fingerprint) {
		log.Warn("hello fingerprint differs from TLS leaf", "announced", hello.CertFingerprint)
	}

	sctx, cancel := context.WithCancel(ctx)
	defer cancel()

	sess := &session{
		s: s, machine: adm.machine, identity: adm.identity, fingerprint: adm.fingerprint,
		notAfter: adm.leaf.NotAfter, leaf: adm.leaf, source: source, accepted: s.now(),
		conn: conn, ymx: ymx, ctrl: ctrl, log: log, ctx: sctx, cancel: cancel,
		kick: make(chan struct{}, 1), hello: hello, home: snap.IsHome(source),
	}

	s.mu.Lock()
	s.nextID++
	sess.id = s.nextID
	s.mu.Unlock()

	for _, old := range s.register(sess) {
		old.reject(
			proto.Reject{Reason: proto.RejectOther, Detail: "too many sessions for this machine"},
		)
	}

	defer sess.close(errors.New("session ended"))

	if err := sess.sendHelloAck(); err != nil {
		log.Warn("hello ack failed", "error", err.Error())

		return
	}

	sess.logConnect(snap)
	s.kickAll()

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

	log.Info(
		"disconnect",
		"duration",
		s.now().Sub(sess.accepted).String(),
		"reason",
		fmt.Sprint(sess.closeErr),
	)
}

func readHello(ctx context.Context, ctrl *tunnel.Control) (proto.Hello, error) {
	t := time.NewTimer(helloTimeout)
	defer t.Stop()

	select {
	case msg, ok := <-ctrl.Messages():
		if !ok {
			return proto.Hello{}, errors.New("control stream closed before hello")
		}

		h, isHello := msg.(proto.Hello)
		if !isHello {
			return proto.Hello{}, fmt.Errorf("first message is %s, want Hello", msg.MessageType())
		}

		return sanitizeHello(h), nil
	case <-t.C:
		return proto.Hello{}, errors.New("hello timed out")
	case <-ctx.Done():
		return proto.Hello{}, fmt.Errorf("hello: %w", ctx.Err())
	}
}

func sanitizeHello(h proto.Hello) proto.Hello {
	h.Version = truncate(h.Version, 64)

	var addrs []string

	for _, a := range h.LANAddrs {
		if len(addrs) >= 16 {
			break
		}

		if ip, err := netip.ParseAddr(a); err == nil {
			addrs = append(addrs, ip.String())
		}
	}

	h.LANAddrs = addrs

	if h.DirectPort < 0 || h.DirectPort > 65535 {
		h.DirectPort = 0
	}

	svcs := slices.Clone(h.Services)
	if len(svcs) > 64 {
		svcs = svcs[:64]
	}

	for i := range svcs {
		svcs[i] = truncate(svcs[i], 64)
	}

	slices.Sort(svcs)
	h.Services = slices.Compact(svcs)

	return h
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}

	return s
}

func serviceDiff(announced, configured []string) (missing, unexpected []string) {
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

func (c *session) logConnect(snap *hubconfig.Snapshot) {
	path := pathName(c.home)
	c.log.Info(
		"connect",
		"path",
		path,
		"version",
		c.hello.Version,
		"services",
		c.hello.Services,
		"notAfter",
		c.notAfter.UTC().Format(time.RFC3339),
	)

	missing, unexpected := serviceDiff(c.hello.Services, snap.Services(c.machine))
	if len(missing) > 0 || len(unexpected) > 0 {
		c.log.Warn(
			"announced services differ from configuration",
			"missing",
			missing,
			"unexpected",
			unexpected,
		)
		c.s.warn(
			c.machine,
			fmt.Sprintf("announced services differ: missing=%v unexpected=%v", missing, unexpected),
		)
	}
}

func pathName(home bool) string {
	if home {
		return "LAN"
	}

	return "OCI"
}

type desired struct {
	rules   proto.Rules
	revs    proto.Revocations
	trust   proto.TrustBundle
	release proto.Release
	peers   proto.PeerTable
	cidrs   []string
	home    bool
}

// desiredState computes what the agent should hold now. It updates the
// session's home flag from the current configuration.
func (c *session) desiredState() (d desired, homeChanged bool) {
	snap := c.s.cfg.Current()
	home := snap.IsHome(c.source)

	c.s.mu.Lock()
	if home != c.home {
		c.home = home
		homeChanged = true
	}

	d.peers = c.s.peersLocked(snap, c)
	c.s.mu.Unlock()

	d.home = home
	d.rules = snap.Rules
	d.revs = snap.Revocations
	d.trust = snap.TrustBundle
	d.release = snap.Release

	for _, p := range snap.HomePrefixes {
		d.cidrs = append(d.cidrs, p.String())
	}

	return d, homeChanged
}

func (c *session) sendHelloAck() error {
	d, _ := c.desiredState()

	err := c.ctrl.Send(proto.HelloAck{
		Machine: c.machine, Home: d.home, Release: d.release, Rules: d.rules,
		Peers: d.peers, Revocations: d.revs, TrustBundle: d.trust, HomeCIDRs: d.cidrs,
	})
	if err != nil {
		return fmt.Errorf("hub: send HelloAck: %w", err)
	}

	c.sent = sentState{
		rules: d.rules.Revision, revs: d.revs.Revision, trust: d.trust.Revision,
		release: d.release.Revision, peers: d.peers.Revision, home: d.home,
		cidrs: strings.Join(d.cidrs, ","),
	}

	return nil
}

func (c *session) pushLoop() {
	defer c.close(errors.New("push loop ended"))

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-c.kick:
			if err := c.push(); err != nil {
				c.log.Warn("update failed", "error", err.Error())

				return
			}
		}
	}
}

func (c *session) push() error {
	d, homeChanged := c.desiredState()
	if homeChanged {
		c.log.Info("path change", "path", pathName(d.home))
		c.s.kickAll()
	}

	var (
		upd  proto.Update
		dirt bool
	)

	if d.rules.Revision != c.sent.rules {
		upd.Rules, dirt = &d.rules, true
	}

	if d.revs.Revision != c.sent.revs {
		upd.Revocations, dirt = &d.revs, true
	}

	if d.trust.Revision != c.sent.trust {
		upd.TrustBundle, dirt = &d.trust, true
	}

	if d.peers.Revision != c.sent.peers {
		upd.Peers, dirt = &d.peers, true
	}

	if d.home != c.sent.home {
		h := d.home
		upd.Home, dirt = &h, true
	}

	if cidrs := strings.Join(d.cidrs, ","); cidrs != c.sent.cidrs && len(d.cidrs) > 0 {
		upd.HomeCIDRs, dirt = d.cidrs, true
	}

	if dirt {
		if err := c.ctrl.Send(upd); err != nil {
			return fmt.Errorf("hub: send Update: %w", err)
		}

		c.sent.rules, c.sent.revs, c.sent.trust, c.sent.peers, c.sent.home = d.rules.Revision, d.revs.Revision, d.trust.Revision, d.peers.Revision, d.home
		c.sent.cidrs = strings.Join(d.cidrs, ",")
	}

	if d.release.Revision != c.sent.release {
		if err := c.ctrl.Send(d.release); err != nil {
			return fmt.Errorf("hub: send Release: %w", err)
		}

		c.sent.release = d.release.Revision
	}

	return nil
}

// peersLocked builds the peer table for c. s.mu must be held.
func (s *Server) peersLocked(snap *hubconfig.Snapshot, c *session) proto.PeerTable {
	names := make([]string, 0, len(snap.Machines))
	for n := range snap.Machines {
		names = append(names, n)
	}

	slices.Sort(names)

	peers := []proto.Peer{}

	for _, name := range names {
		if name == c.machine {
			continue
		}

		var svcs []string

		for _, svc := range snap.Services(name) {
			if policy.Allowed(snap.Rules, c.identity, svc, name) {
				svcs = append(svcs, svc)
			}
		}

		if len(svcs) == 0 {
			continue
		}

		p := proto.Peer{Machine: name, Identity: snap.Machines[name].Identity, Services: svcs}

		if ms := s.machines[name]; ms != nil {
			if live := ms.newestLive(); live != nil {
				p.LANAddrs = live.hello.LANAddrs
				p.DirectPort = live.hello.DirectPort
				p.Home = live.home
			}
		}

		peers = append(peers, p)
	}

	b, _ := json.Marshal(peers)
	sum := sha256.Sum256(b)

	return proto.PeerTable{Revision: hex.EncodeToString(sum[:8]), Peers: peers}
}

func (c *session) controlLoop() {
	defer c.close(errors.New("control stream ended"))

	for msg := range c.ctrl.Messages() {
		switch m := msg.(type) {
		case proto.Status:
			c.s.recordStatus(c, m)
		case proto.Renew:
			if !c.renewing.CompareAndSwap(false, true) {
				_ = c.ctrl.Send(
					proto.Reject{
						Reason: proto.RejectRenewFailed,
						Detail: "renewal already in progress",
					},
				)

				continue
			}

			c.s.wg.Go(func() {
				defer c.renewing.Store(false)
				c.handleRenew(m)
			})
		default:
			c.log.Debug("unexpected control message", "type", msg.MessageType())
		}
	}
}

func (c *session) acceptLoop() {
	for {
		st, err := c.ymx.AcceptStream()
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				c.close(fmt.Errorf("accept stream: %w", err))
			} else {
				c.close(err)
			}

			return
		}

		c.s.wg.Go(func() { c.s.handleAgentStream(c, st) })
	}
}

func (s *Server) recordStatus(c *session, st proto.Status) {
	s.mu.Lock()
	defer s.mu.Unlock()

	m := s.machineLocked(c.machine)
	cp := st
	m.status = &cp

	if st.Version != "" {
		m.version = truncate(st.Version, 64)
	}
}
