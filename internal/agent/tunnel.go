package agent

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/hashicorp/yamux"

	"github.com/zekihan/t3-mesh/internal/pki"
	"github.com/zekihan/t3-mesh/internal/proto"
	"github.com/zekihan/t3-mesh/internal/tunnel"
)

const (
	dialTimeout      = 10 * time.Second
	handshakeTimeout = 10 * time.Second
	ackTimeout       = 15 * time.Second
	retirePoll       = time.Second
	touchPoll        = 5 * time.Second
)

// rejectError is a hub Reject received instead of a HelloAck.
type rejectError struct{ rej proto.Reject }

func (e *rejectError) Error() string {
	return fmt.Sprintf("hub rejected session (%s): %s", e.rej.Reason, e.rej.Detail)
}

// session is one tunnel session to the hub.
type session struct {
	a       *Agent
	conn    net.Conn
	ymx     *yamux.Session
	ctrl    *tunnel.Control
	peer    netip.Addr
	local   netip.Addr
	ack     proto.HelloAck
	started time.Time

	done chan struct{}
	once sync.Once

	renewCh chan proto.Message
}

func (s *session) close() {
	s.once.Do(func() {
		_ = s.ctrl.Close()
		_ = s.ymx.Close()
		_ = s.conn.Close()

		close(s.done)
	})
}

// openStreams is the number of open streams excluding the control stream.
func (s *session) openStreams() int {
	return max(s.ymx.NumStreams()-1, 0)
}

func addrOf(a net.Addr) netip.Addr {
	if ta, ok := a.(*net.TCPAddr); ok {
		return ta.AddrPort().Addr().Unmap().WithZone("")
	}

	return netip.Addr{}
}

func (a *Agent) tunnelTLS(ident tls.Certificate) *tls.Config {
	cfg := &tls.Config{}
	if a.hubTLS != nil {
		cfg = a.hubTLS.Clone()
	}

	cfg.MinVersion = tls.VersionTLS13
	cfg.NextProtos = []string{proto.TunnelALPN(proto.ProtocolVersion)}
	cfg.Certificates = []tls.Certificate{ident}

	if cfg.ServerName == "" {
		cfg.ServerName = a.cfg.HubHost()
	}

	return cfg
}

// hello builds the Hello for ident.
func (a *Agent) hello(ident tls.Certificate) proto.Hello {
	services := make([]string, 0, len(a.cfg.Serve))
	for svc := range a.cfg.Serve {
		services = append(services, svc)
	}

	slices.Sort(services)

	h := proto.Hello{Version: a.version, Services: services}
	if ident.Leaf != nil {
		h.CertFingerprint = pki.Fingerprint(ident.Leaf)
	}

	if a.cfg.Direct.Enabled {
		h.DirectPort = a.cfg.Direct.Port
		h.LANAddrs = a.lanAddrs()
	}

	return h
}

// lanAddrs returns the local addresses inside the cached home CIDRs. Before the
// hub has ever sent them, it falls back to every private, non-link-local
// address, so the first Hello still lets the hub build a peer table.
func (a *Agent) lanAddrs() []string {
	local, err := a.localAddrs()
	if err != nil {
		a.log.Warn("list local addresses", "err", err)

		return nil
	}

	a.mu.Lock()
	prefixes := a.prefixes
	a.mu.Unlock()

	var picked []netip.Addr

	if len(prefixes) > 0 {
		for _, ad := range local {
			for _, p := range prefixes {
				if p.Contains(ad) {
					picked = append(picked, ad)

					break
				}
			}
		}
	} else {
		for _, ad := range local {
			if ad.IsPrivate() && !ad.IsLinkLocalUnicast() {
				picked = append(picked, ad)
			}
		}
	}

	// Loopback is kept only when a configured home prefix contains it (tests);
	// the fallback above never picks it because it is not private.
	out := make([]string, 0, len(picked))
	for _, ad := range picked {
		if ad.IsLinkLocalUnicast() {
			continue
		}

		out = append(out, ad.String())
	}

	return out
}

// connect dials the hub with ident, opens the control stream and completes the
// Hello/HelloAck exchange. The returned session is not yet adopted.
func (a *Agent) connect(ctx context.Context, ident tls.Certificate) (*session, error) {
	d := net.Dialer{Timeout: dialTimeout}

	raw, err := d.DialContext(ctx, "tcp", a.cfg.HubAddr())
	if err != nil {
		return nil, fmt.Errorf("dial hub: %w", err)
	}

	hctx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	defer cancel()

	tc := tls.Client(raw, a.tunnelTLS(ident))
	if err = tc.HandshakeContext(hctx); err != nil {
		_ = raw.Close()

		return nil, fmt.Errorf("tls handshake with hub: %w", err)
	}

	ymx, err := yamux.Client(tc, tunnel.YamuxConfig())
	if err != nil {
		_ = tc.Close()

		return nil, fmt.Errorf("yamux client: %w", err)
	}

	stream, err := ymx.OpenStream()
	if err != nil {
		_ = ymx.Close()

		return nil, fmt.Errorf("open control stream: %w", err)
	}

	ctrl := tunnel.NewControl(stream)

	s := &session{
		a: a, conn: tc, ymx: ymx, ctrl: ctrl,
		peer: addrOf(raw.RemoteAddr()), local: addrOf(raw.LocalAddr()),
		started: a.now(), done: make(chan struct{}),
		renewCh: make(chan proto.Message, 1),
	}

	if err = ctrl.Send(a.hello(ident)); err != nil {
		s.close()

		return nil, fmt.Errorf("send hello: %w", err)
	}

	ack, err := awaitAck(ctx, ctrl)
	if err != nil {
		s.close()

		return nil, err
	}

	s.ack = ack

	return s, nil
}

func awaitAck(ctx context.Context, ctrl *tunnel.Control) (proto.HelloAck, error) {
	timer := time.NewTimer(ackTimeout)
	defer timer.Stop()

	select {
	case msg, ok := <-ctrl.Messages():
		if !ok {
			return proto.HelloAck{}, fmt.Errorf(
				"control stream closed before HelloAck: %w",
				ctrl.Err(),
			)
		}

		switch m := msg.(type) {
		case proto.HelloAck:
			return m, nil
		case proto.Reject:
			return proto.HelloAck{}, &rejectError{rej: m}
		default:
			return proto.HelloAck{}, fmt.Errorf("unexpected %s before HelloAck", msg.MessageType())
		}
	case <-timer.C:
		return proto.HelloAck{}, errors.New("no HelloAck from hub")
	case <-ctx.Done():
		return proto.HelloAck{}, fmt.Errorf("waiting for HelloAck: %w", ctx.Err())
	}
}

// handleConnectErr logs a failed connect and feeds a Reject to the updater.
func (a *Agent) handleConnectErr(err error) {
	if rej, ok := errors.AsType[*rejectError](err); ok {
		a.log.Warn(
			"hub rejected session",
			"reason",
			rej.rej.Reason,
			"detail",
			rej.rej.Detail,
			"version",
			rej.rej.Version,
		)
		a.warn("hub rejected session: " + rej.rej.Reason)

		if a.upd != nil {
			a.upd.OnReject(rej.rej)
		}

		return
	}

	a.log.Warn("tunnel connect failed", "err", err)
}

// connectNewest connects with the pending renewed identity when one is on
// disk, promoting it on success, and otherwise with the current identity. The
// hub admits only the newest issued leaf, which is the renewed one from the
// moment the hub issued it, so a renewal whose first tunnel failed must not
// leave the agent dialling with the old certificate.
func (a *Agent) connectNewest(ctx context.Context) (*session, error) {
	next, _, err := a.store.LoadNext()
	if err != nil {
		return a.connect(ctx, a.identity())
	}

	s, nerr := a.connect(ctx, next)
	if nerr == nil {
		a.promote(next)

		return s, nil
	}

	a.log.Warn("tunnel with pending renewed certificate failed", "err", nerr)

	s, err = a.connect(ctx, a.identity())
	if err != nil {
		return nil, err
	}

	// The hub admitted the current leaf and refused the pending one, so the
	// pending one was superseded or never became the newest.
	if _, rejected := errors.AsType[*rejectError](nerr); rejected {
		a.discardNext()
	}

	return s, nil
}

// establish connects when no session is current.
func (a *Agent) establish(ctx context.Context) error {
	a.dialMu.Lock()
	defer a.dialMu.Unlock()

	if a.current() != nil {
		return nil
	}

	s, err := a.connectNewest(ctx)
	if err != nil {
		a.handleConnectErr(err)

		return err
	}

	a.adopt(s)

	return nil
}

// adopt makes s the current session, applies its HelloAck and starts its
// goroutines. It returns the previous current session, if any.
func (a *Agent) adopt(s *session) *session {
	a.mu.Lock()
	a.applyAckLocked(s.ack)
	old := a.cur
	a.cur = s
	a.live[s] = struct{}{}
	a.lastHelloAck = a.now()
	a.mu.Unlock()

	a.saveCache()

	a.log.Info("tunnel connected", "machine", s.ack.Machine, "home", s.ack.Home,
		"peer", s.peer.String(), "release", s.ack.Release.Version)

	if a.upd != nil {
		a.upd.HelloAckReceived()

		if s.ack.Release.Version != "" {
			a.upd.OnRelease(s.ack.Release)
		}
	}

	s.start()
	a.reconcileDirect()
	signal(a.curChanged)
	signal(a.statusNudge)
	signal(a.renewKick)

	return old
}

func (a *Agent) applyAckLocked(ack proto.HelloAck) {
	c := a.cache
	c.Machine = ack.Machine
	c.Home = ack.Home
	c.Release = ack.Release
	c.Rules = ack.Rules
	c.Peers = ack.Peers
	c.Revocations = ack.Revocations
	c.TrustBundle = ack.TrustBundle

	if len(ack.HomeCIDRs) > 0 {
		c.HomeCIDRs = ack.HomeCIDRs
	}

	c.LastHubContact = a.now()

	if ack.Home {
		a.cacheGatewayLocked()
	}

	a.deriveLocked()
}

// cacheGatewayLocked records the default gateway MAC of a hub-confirmed home
// session.
func (a *Agent) cacheGatewayLocked() {
	mac, err := a.gatewayMAC()
	if err != nil {
		a.log.Warn("home gateway unknown", "err", err)

		return
	}

	a.cache.HomeGatewayMAC = mac
}

func (s *session) start() {
	a := s.a

	a.wg.Go(func() {
		select {
		case <-a.ctx.Done():
			s.close()
		case <-s.done:
		}
	})
	a.wg.Go(func() {
		defer s.close()

		for msg := range s.ctrl.Messages() {
			a.handleMessage(s, msg)
		}
	})
	a.wg.Go(func() {
		defer s.close()

		for {
			st, err := s.ymx.AcceptStream()
			if err != nil {
				return
			}

			go a.handleHubStream(st)
		}
	})
	a.wg.Go(func() {
		err := s.ctrl.RunLiveness(a.ctx, tunnel.PingInterval, tunnel.MaxMissed)
		if errors.Is(err, tunnel.ErrDead) {
			a.log.Warn("tunnel liveness lost", "peer", s.peer.String())
		}

		s.close()
	})
	a.wg.Go(func() {
		t := time.NewTicker(touchPoll)
		defer t.Stop()

		for {
			select {
			case <-s.done:
				a.sessionEnded(s)

				return
			case <-t.C:
				if time.Since(s.ctrl.LastPong()) < 2*tunnel.PingInterval {
					a.touchHub()
				}
			}
		}
	})
}

func (a *Agent) sessionEnded(s *session) {
	a.mu.Lock()
	delete(a.live, s)

	wasCur := a.cur == s
	if wasCur {
		a.cur = nil
	}
	a.mu.Unlock()

	a.log.Info(
		"tunnel closed",
		"peer",
		s.peer.String(),
		"current",
		wasCur,
		"err",
		fmt.Sprint(s.ctrl.Err()),
	)

	if wasCur {
		a.saveCache()
		a.reconcileDirect()
	}

	signal(a.curChanged)
}

// retire closes a replaced session once its streams have ended. A session that
// stops answering pings is closed by its own liveness loop.
func (a *Agent) retire(old *session) {
	a.log.Info("tunnel retiring", "peer", old.peer.String(), "streams", old.openStreams())

	t := time.NewTicker(retirePoll)
	defer t.Stop()

	for {
		if old.openStreams() == 0 {
			old.close()

			return
		}

		select {
		case <-old.done:
			return
		case <-a.ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (a *Agent) delay(attempt int) time.Duration {
	limit := a.backoffMax
	if attempt < 30 {
		limit = min(limit, a.backoffBase<<attempt)
	}

	if limit <= 0 {
		return 0
	}

	return time.Duration(rand.Int64N(int64(limit) + 1)) //nolint:gosec // jitter, not security
}

func (a *Agent) sleep(ctx context.Context, d time.Duration) {
	if d <= 0 {
		return
	}

	t := time.NewTimer(d)
	defer t.Stop()

	select {
	case <-ctx.Done():
	case <-a.kick:
	case <-t.C:
	}
}

// tunnelLoop keeps a current session, reconnecting with exponential backoff and
// full jitter capped at backoffMax.
func (a *Agent) tunnelLoop(ctx context.Context) {
	attempt := 0
	wasUp := false

	var connectedAt time.Time

	for ctx.Err() == nil {
		if a.current() != nil {
			if connectedAt.IsZero() {
				connectedAt = time.Now()
			}

			select {
			case <-ctx.Done():
				return
			case <-a.curChanged:
			}

			continue
		}

		if !connectedAt.IsZero() {
			if time.Since(connectedAt) >= stableAfter {
				attempt = 0
			} else {
				attempt++
			}

			connectedAt = time.Time{}
			wasUp = true
		}

		if wasUp {
			a.sleep(ctx, a.delay(attempt))

			wasUp = false

			if ctx.Err() != nil {
				return
			}
		}

		if err := a.establish(ctx); err != nil {
			attempt++

			a.sleep(ctx, a.delay(attempt))
		}
	}
}

// replaceSession opens a new session with the current identity. On success the
// new session becomes current and the old one is retired; on failure nothing
// changes.
func (a *Agent) replaceSession(ctx context.Context, reason string) bool {
	a.dialMu.Lock()
	defer a.dialMu.Unlock()

	a.log.Info("tunnel replacing", "reason", reason)

	s, err := a.connectNewest(ctx)
	if err != nil {
		a.handleConnectErr(err)

		return false
	}

	if old := a.adopt(s); old != nil {
		a.wg.Go(func() { a.retire(old) })
	}

	return true
}

func (a *Agent) handleMessage(s *session, msg proto.Message) {
	switch m := msg.(type) {
	case proto.Update:
		a.applyUpdate(m)
	case proto.Release:
		a.mu.Lock()
		a.cache.Release = m
		a.mu.Unlock()

		a.log.Info("release advertised", "version", m.Version, "revision", m.Revision)

		if a.upd != nil {
			a.upd.OnRelease(m)
		}

		signal(a.statusNudge)
	case proto.Renewed:
		deliver(s.renewCh, m)
	case proto.Reject:
		if m.Reason == proto.RejectRenewFailed {
			deliver(s.renewCh, m)

			return
		}

		a.log.Warn(
			"hub rejected session",
			"reason",
			m.Reason,
			"detail",
			m.Detail,
			"version",
			m.Version,
		)
		a.warn("hub rejected session: " + m.Reason)

		if a.upd != nil {
			a.upd.OnReject(m)
		}

		s.close()
	default:
		a.log.Debug("unexpected control message", "type", msg.MessageType())
	}
}

func deliver(ch chan proto.Message, m proto.Message) {
	select {
	case ch <- m:
	default:
	}
}

func (a *Agent) applyUpdate(u proto.Update) {
	var mac string

	if u.Home != nil && *u.Home {
		mac, _ = a.gatewayMAC() //nolint:errcheck // best effort, keeps the previous MAC
	}

	a.mu.Lock()
	a.cache.Apply(u)
	a.cache.LastHubContact = a.now()

	if mac != "" {
		a.cache.HomeGatewayMAC = mac
	}

	a.deriveLocked()
	a.mu.Unlock()

	a.saveCache()
	a.log.Info("update applied",
		"home", u.Home != nil, "rules", u.Rules != nil, "peers", u.Peers != nil,
		"revocations", u.Revocations != nil, "trust_bundle", u.TrustBundle != nil)

	a.reconcileDirect()
	signal(a.statusNudge)
}
