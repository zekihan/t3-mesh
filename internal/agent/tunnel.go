package agent

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
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
	peer    netip.Addr
	local   netip.Addr
	started time.Time
	conn    net.Conn
	a       *Agent
	ymx     *yamux.Session
	ctrl    *tunnel.Control
	done    chan struct{}
	renewCh chan proto.Message
	ack     proto.HelloAck
	once    sync.Once
}

func (sess *session) close() {
	sess.once.Do(func() {
		_ = sess.ctrl.Close()
		_ = sess.ymx.Close()
		_ = sess.conn.Close()

		close(sess.done)
	})
}

// openStreams is the number of open streams excluding the control stream.
func (sess *session) openStreams() int {
	return max(sess.ymx.NumStreams()-1, 0)
}

func addrOf(a net.Addr) netip.Addr {
	if ta, ok := a.(*net.TCPAddr); ok {
		return ta.AddrPort().Addr().Unmap().WithZone("")
	}

	return netip.Addr{}
}

func (agent *Agent) tunnelTLS(ident *tls.Certificate) *tls.Config {
	cfg := &tls.Config{}
	if agent.hubTLS != nil {
		cfg = agent.hubTLS.Clone()
	}

	cfg.MinVersion = tls.VersionTLS13
	cfg.NextProtos = []string{proto.TunnelALPN(proto.ProtocolVersion)}
	cfg.Certificates = []tls.Certificate{*ident}

	if cfg.ServerName == "" {
		cfg.ServerName = agent.cfg.HubHost()
	}

	return cfg
}

// hello builds the Hello for ident.
func (agent *Agent) hello(ident *tls.Certificate) proto.Hello {
	services := make([]string, 0, len(agent.cfg.Serve))
	for svc := range agent.cfg.Serve {
		services = append(services, svc)
	}

	slices.Sort(services)

	hello := proto.Hello{Version: agent.version, Services: services}
	if ident.Leaf != nil {
		hello.CertFingerprint = pki.Fingerprint(ident.Leaf)
	}

	if agent.cfg.Direct.Enabled {
		hello.DirectPort = agent.cfg.Direct.Port
		hello.LANAddrs = agent.lanAddrs()
	}

	return hello
}

// lanAddrs returns the local addresses inside the cached home CIDRs. Before the
// hub has ever sent them, it falls back to every private, non-link-local
// address, so the first Hello still lets the hub build a peer table.
func (agent *Agent) lanAddrs() []string {
	local, err := agent.localAddrs()
	if err != nil {
		agent.log.Warn("List local addresses", slog.Any("err", err))

		return nil
	}

	agent.mu.Lock()
	prefixes := agent.prefixes
	agent.mu.Unlock()

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
func (agent *Agent) connect(ctx context.Context, ident *tls.Certificate) (*session, error) {
	d := net.Dialer{Timeout: dialTimeout}

	raw, err := d.DialContext(ctx, "tcp", agent.cfg.HubAddr())
	if err != nil {
		return nil, fmt.Errorf("dial hub: %w", err)
	}

	hctx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	defer cancel()

	tc := tls.Client(raw, agent.tunnelTLS(ident))

	err = tc.HandshakeContext(hctx)
	if err != nil {
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

	sess := &session{
		a: agent, conn: tc, ymx: ymx, ctrl: ctrl,
		peer: addrOf(raw.RemoteAddr()), local: addrOf(raw.LocalAddr()),
		started: agent.now(), done: make(chan struct{}),
		renewCh: make(chan proto.Message, 1),
	}

	err = ctrl.Send(agent.hello(ident))
	if err != nil {
		sess.close()

		return nil, fmt.Errorf("send hello: %w", err)
	}

	ack, err := awaitAck(ctx, ctrl)
	if err != nil {
		sess.close()

		return nil, err
	}

	sess.ack = ack

	return sess, nil
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
			return proto.HelloAck{}, fmt.Errorf(
				"%s before HelloAck: %w",
				msg.MessageType(),
				errUnexpectedReply,
			)
		}
	case <-timer.C:
		return proto.HelloAck{}, errNoHelloAck
	case <-ctx.Done():
		return proto.HelloAck{}, fmt.Errorf("waiting for HelloAck: %w", ctx.Err())
	}
}

// handleConnectErr logs a failed connect and feeds a Reject to the updater.
func (agent *Agent) handleConnectErr(err error) {
	if rej, ok := errors.AsType[*rejectError](err); ok {
		agent.log.Warn(
			"Hub rejected session",
			slog.Any("reason", rej.rej.Reason),
			slog.Any("detail", rej.rej.Detail),
			slog.Any("version", rej.rej.Version),
		)
		agent.warn("hub rejected session: " + rej.rej.Reason)

		if agent.upd != nil {
			agent.upd.OnReject(rej.rej)
		}

		return
	}

	agent.log.Warn("Tunnel connect failed", slog.Any("err", err))
}

// connectNewest connects with the pending renewed identity when one is on
// disk, promoting it on success, and otherwise with the current identity. The
// hub admits only the newest issued leaf, which is the renewed one from the
// moment the hub issued it, so a renewal whose first tunnel failed must not
// leave the agent dialing with the old certificate.
func (agent *Agent) connectNewest(ctx context.Context) (*session, error) {
	next, _, err := agent.store.LoadNext()
	if err != nil {
		current := agent.identity()

		return agent.connect(ctx, &current)
	}

	sess, nerr := agent.connect(ctx, &next)
	if nerr == nil {
		agent.promote(&next)

		return sess, nil
	}

	agent.log.WarnContext(
		ctx,
		"Tunnel with pending renewed certificate failed",
		slog.Any("err", nerr),
	)

	current := agent.identity()

	sess, err = agent.connect(ctx, &current)
	if err != nil {
		return nil, err
	}

	// The hub admitted the current leaf and refused the pending one, so the
	// pending one was superseded or never became the newest.
	if _, rejected := errors.AsType[*rejectError](nerr); rejected {
		agent.discardNext()
	}

	return sess, nil
}

// establish connects when no session is current.
func (agent *Agent) establish(ctx context.Context) error {
	agent.dialMu.Lock()
	defer agent.dialMu.Unlock()

	if agent.current() != nil {
		return nil
	}

	sess, err := agent.connectNewest(ctx)
	if err != nil {
		agent.handleConnectErr(err)

		return err
	}

	agent.adopt(sess) //nolint:contextcheck // sessions outlive the connect ctx

	return nil
}

// adopt makes s the current session, applies its HelloAck and starts its
// goroutines. It returns the previous current session, if any.
func (agent *Agent) adopt(sess *session) *session {
	agent.mu.Lock()
	agent.applyAckLocked(&sess.ack)
	old := agent.cur
	agent.cur = sess
	agent.live[sess] = struct{}{}
	agent.lastHelloAck = agent.now()
	agent.mu.Unlock()

	agent.saveCache()

	agent.log.Info("Tunnel connected", slog.String("machine", sess.ack.Machine),
		slog.Bool("home", sess.ack.Home),
		slog.String("peer", sess.peer.String()),
		slog.String("release", sess.ack.Release.Version),
	)

	if agent.upd != nil {
		agent.upd.HelloAckReceived()

		if sess.ack.Release.Version != "" {
			agent.upd.OnRelease(sess.ack.Release)
		}
	}

	sess.start()
	agent.reconcileDirect()
	signal(agent.curChanged)
	signal(agent.statusNudge)
	signal(agent.renewKick)

	return old
}

func (agent *Agent) applyAckLocked(ack *proto.HelloAck) {
	cache := agent.cache
	cache.Machine = ack.Machine
	cache.Home = ack.Home
	cache.Release = ack.Release
	cache.Rules = ack.Rules
	cache.Peers = ack.Peers
	cache.Revocations = ack.Revocations
	cache.TrustBundle = ack.TrustBundle

	if len(ack.HomeCIDRs) > 0 {
		cache.HomeCIDRs = ack.HomeCIDRs
	}

	cache.LastHubContact = agent.now()

	if ack.Home {
		agent.cacheGatewayLocked()
	}

	agent.deriveLocked()
}

// cacheGatewayLocked records the default gateway MAC of a hub-confirmed home
// session.
func (agent *Agent) cacheGatewayLocked() {
	mac, err := agent.gatewayMAC()
	if err != nil {
		agent.log.Warn("Home gateway unknown", slog.Any("err", err))

		return
	}

	agent.cache.HomeGatewayMAC = mac
}

func (sess *session) start() {
	agent := sess.a

	agent.wg.Go(func() {
		select {
		case <-agent.ctx.Done():
			sess.close()
		case <-sess.done:
		}
	})
	agent.wg.Go(func() {
		defer sess.close()

		for msg := range sess.ctrl.Messages() {
			agent.handleMessage(sess, msg)
		}
	})
	agent.wg.Go(func() {
		defer sess.close()

		for {
			st, err := sess.ymx.AcceptStream()
			if err != nil {
				return
			}

			go agent.handleHubStream(st)
		}
	})
	agent.wg.Go(func() {
		err := sess.ctrl.RunLiveness(agent.ctx, tunnel.PingInterval, tunnel.MaxMissed)
		if errors.Is(err, tunnel.ErrDead) {
			agent.log.Warn("Tunnel liveness lost", slog.String("peer", sess.peer.String()))
		}

		sess.close()
	})
	agent.wg.Go(func() {
		ticker := time.NewTicker(touchPoll)
		defer ticker.Stop()

		for {
			select {
			case <-sess.done:
				agent.sessionEnded(sess)

				return
			case <-ticker.C:
				if time.Since(sess.ctrl.LastPong()) < 2*tunnel.PingInterval {
					agent.touchHub()
				}
			}
		}
	})
}

func (agent *Agent) sessionEnded(sess *session) {
	agent.mu.Lock()
	delete(agent.live, sess)

	wasCur := agent.cur == sess
	if wasCur {
		agent.cur = nil
	}
	agent.mu.Unlock()

	agent.log.Info(
		"Tunnel closed",
		slog.String("peer", sess.peer.String()),
		slog.Bool("current", wasCur),
		slog.Any("err", sess.ctrl.Err()),
	)

	if wasCur {
		agent.saveCache()
		agent.reconcileDirect()
	}

	signal(agent.curChanged)
}

// retire closes a replaced session once its streams have ended. A session that
// stops answering pings is closed by its own liveness loop.
func (agent *Agent) retire(old *session) {
	agent.log.Info("Tunnel retiring", slog.String("peer", old.peer.String()),
		slog.Int("streams", old.openStreams()),
	)

	ticker := time.NewTicker(retirePoll)
	defer ticker.Stop()

	for {
		if old.openStreams() == 0 {
			old.close()

			return
		}

		select {
		case <-old.done:
			return
		case <-agent.ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (agent *Agent) delay(attempt int) time.Duration {
	limit := agent.backoffMax
	if attempt < maxBackoffShift {
		limit = min(limit, agent.backoffBase<<attempt)
	}

	if limit <= 0 {
		return 0
	}

	return time.Duration(rand.Int64N(int64(limit) + 1)) //nolint:gosec // jitter, not security
}

func (agent *Agent) sleep(ctx context.Context, d time.Duration) {
	if d <= 0 {
		return
	}

	t := time.NewTimer(d)
	defer t.Stop()

	select {
	case <-ctx.Done():
	case <-agent.kick:
	case <-t.C:
	}
}

// tunnelLoop keeps a current session, reconnecting with exponential backoff and
// full jitter capped at backoffMax.
func (agent *Agent) tunnelLoop(ctx context.Context) {
	attempt := 0
	wasUp := false

	var connectedAt time.Time

	for ctx.Err() == nil {
		if agent.current() != nil {
			if connectedAt.IsZero() {
				connectedAt = time.Now()
			}

			select {
			case <-ctx.Done():
				return
			case <-agent.curChanged:
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
			agent.sleep(ctx, agent.delay(attempt))

			wasUp = false

			if ctx.Err() != nil {
				return
			}
		}

		err := agent.establish(ctx)
		if err != nil {
			attempt++

			agent.sleep(ctx, agent.delay(attempt))
		}
	}
}

// replaceSession opens a new session with the current identity. On success the
// new session becomes current and the old one is retired; on failure nothing
// changes.
func (agent *Agent) replaceSession(ctx context.Context, reason string) bool {
	agent.dialMu.Lock()
	defer agent.dialMu.Unlock()

	agent.log.InfoContext(ctx, "Tunnel replacing", slog.String("reason", reason))

	sess, err := agent.connectNewest(ctx)
	if err != nil {
		agent.handleConnectErr(err)

		return false
	}

	old := agent.adopt(sess) //nolint:contextcheck // sessions outlive the connect ctx
	if old != nil {
		agent.wg.Go(func() { agent.retire(old) })
	}

	return true
}

func (agent *Agent) handleMessage(sess *session, msg proto.Message) {
	switch typed := msg.(type) {
	case proto.Update:
		agent.applyUpdate(typed)
	case proto.Release:
		agent.mu.Lock()
		agent.cache.Release = typed
		agent.mu.Unlock()

		agent.log.Info("Release advertised", slog.String("version", typed.Version),
			slog.String("revision", typed.Revision),
		)

		if agent.upd != nil {
			agent.upd.OnRelease(typed)
		}

		signal(agent.statusNudge)
	case proto.Renewed:
		deliver(sess.renewCh, typed)
	case proto.Reject:
		if typed.Reason == proto.RejectRenewFailed {
			deliver(sess.renewCh, typed)

			return
		}

		agent.log.Warn(
			"Hub rejected session",
			slog.String("reason", typed.Reason),
			slog.String("detail", typed.Detail),
			slog.String("version", typed.Version),
		)
		agent.warn("hub rejected session: " + typed.Reason)

		if agent.upd != nil {
			agent.upd.OnReject(typed)
		}

		sess.close()
	default:
		agent.log.Debug("Unexpected control message", slog.String("type", msg.MessageType()))
	}
}

func deliver(ch chan proto.Message, m proto.Message) {
	select {
	case ch <- m:
	default:
	}
}

func (agent *Agent) applyUpdate(update proto.Update) {
	var mac string

	if update.Home != nil && *update.Home {
		mac, _ = agent.gatewayMAC() //nolint:errcheck // best effort, keeps the previous MAC
	}

	agent.mu.Lock()
	agent.cache.Apply(update)
	agent.cache.LastHubContact = agent.now()

	if mac != "" {
		agent.cache.HomeGatewayMAC = mac
	}

	agent.deriveLocked()
	agent.mu.Unlock()

	agent.saveCache()
	agent.log.Info("Update applied",
		slog.Bool("home", update.Home != nil),
		slog.Bool("rules", update.Rules != nil),
		slog.Bool("peers", update.Peers != nil),
		slog.Bool("revocations", update.Revocations != nil),
		slog.Bool("trustBundle", update.TrustBundle != nil),
	)

	agent.reconcileDirect()
	signal(agent.statusNudge)
}
