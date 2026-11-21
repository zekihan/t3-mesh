package direct

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"time"

	"github.com/zekihan/t3-mesh/internal/pki"
	"github.com/zekihan/t3-mesh/internal/policy"
	"github.com/zekihan/t3-mesh/internal/proto"
)

// sessionConn is the connection Dial returns. Closing it ends the session.
type sessionConn struct {
	net.Conn

	s *session
}

func (c *sessionConn) Close() error { return c.s.close() }

// CloseWrite half-closes the connection when the transport supports it.
func (c *sessionConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite() //nolint:wrapcheck // passthrough
	}

	return nil
}

func (mgr *Manager) failed(key string) bool {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()

	until, ok := mgr.failures[key]
	if !ok {
		return false
	}

	if mgr.now().Before(until) {
		return true
	}

	delete(mgr.failures, key)

	return false
}

func (mgr *Manager) remember(key string) {
	mgr.mu.Lock()
	mgr.failures[key] = mgr.now().Add(FailureMemory)
	mgr.mu.Unlock()
}

// Dial returns a ready byte stream to svc on machine over the direct path, or
// an error meaning the caller should use the tunnel.
func (mgr *Manager) Dial(ctx context.Context, machine, svc, kind string) (net.Conn, error) {
	view := mgr.view()
	if view.Rules.ServiceKinds[policy.Target(svc, machine)] != kind {
		return nil, errServiceKind
	}

	if ok, reason := mgr.active(view, true); !ok {
		return nil, fmt.Errorf("%w: %s", ErrInactive, reason)
	}

	peer := findPeer(view, machine)
	if peer == nil || len(peer.LANAddrs) == 0 || peer.DirectPort == 0 ||
		(view.HubConnected && !peer.Home) {
		return nil, fmt.Errorf("%w: %s", ErrNoPeer, machine)
	}

	failureKey := policy.Target(kind, machine)
	if mgr.failed(failureKey) {
		return nil, fmt.Errorf("%w: %s", ErrRecentFail, machine)
	}

	_, err := leafOf(&view.Identity)
	if err != nil {
		return nil, err
	}

	conn, err := mgr.dialAny(ctx, view, peer, svc, kind)
	if err != nil {
		if ctx.Err() == nil {
			mgr.remember(failureKey)
		}

		return nil, fmt.Errorf("direct dial %s: %w", machine, err)
	}

	return conn, nil
}

func findPeer(view *View, machine string) *proto.Peer {
	for i := range view.Peers {
		if view.Peers[i].Machine == machine {
			return &view.Peers[i]
		}
	}

	return nil
}

// dialAny tries the peer's LAN addresses in turn within SetupTimeout.
func (mgr *Manager) dialAny(
	ctx context.Context,
	view *View,
	peer *proto.Peer,
	svc, kind string,
) (net.Conn, error) {
	deadline := time.Now().Add(SetupTimeout)

	var lastErr error

	for i, addr := range peer.LANAddrs {
		if ctx.Err() != nil {
			lastErr = ctx.Err()

			break
		}

		remaining := time.Until(deadline)
		if remaining <= 0 {
			break
		}

		attempt := time.Now().Add(remaining / time.Duration(len(peer.LANAddrs)-i))

		conn, err := mgr.dialOne(ctx, view, peer, addr, svc, kind, attempt)
		if err == nil {
			return conn, nil
		}

		lastErr = err

		mgr.log.DebugContext(
			ctx,
			"Direct dial failed",
			slog.String("machine", peer.Machine),
			slog.String("addr", addr),
			slog.Any("err", err),
		)
	}

	if lastErr == nil {
		lastErr = errSetupDeadline
	}

	return nil, lastErr
}

func hostPort(addr string, port int) string {
	a, err := netip.ParseAddr(addr)
	if err == nil {
		return netip.AddrPortFrom(a, uint16(port)).String() //nolint:gosec // port from hub table
	}

	return net.JoinHostPort(addr, strconv.Itoa(port))
}

func (mgr *Manager) clientTLS(v *View, machine, alpn string) *tls.Config {
	identity := v.Identity
	want := policy.AgentIdentity(machine)

	return &tls.Config{
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{alpn},
		InsecureSkipVerify: true, //nolint:gosec // verified in VerifyPeerCertificate against the clients CA
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return &identity, nil
		},
		// No client session cache, so there is no resumption to bypass this check.
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error { //nolint:gosec // see above
			cur := mgr.view()
			if cur.Roots == nil {
				return errNoTrustBundle
			}

			leaf, err := pki.VerifyPeer(raw, cur.Roots, x509.ExtKeyUsageServerAuth, mgr.now())
			if err != nil {
				return fmt.Errorf("verify server: %w", err)
			}

			id, err := pki.CertIdentity(leaf)
			if err != nil {
				return fmt.Errorf("server identity: %w", err)
			}

			if id != want {
				return fmt.Errorf("%w: got %q, want %q", errIdentityMismatch, id, want)
			}

			err = policy.Revoked(cur.Revocations, id, pki.Fingerprint(leaf))
			if err != nil {
				return fmt.Errorf("server: %w", err)
			}

			return nil
		},
	}
}

func (mgr *Manager) dialOne(
	ctx context.Context,
	view *View,
	peer *proto.Peer,
	addr, svc, kind string,
	deadline time.Time,
) (net.Conn, error) {
	dctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	raw, err := mgr.opts.Dial(dctx, "tcp", hostPort(addr, peer.DirectPort))
	if err != nil {
		return nil, err
	}

	ok := false

	defer func() {
		if !ok {
			_ = raw.Close()
		}
	}()

	deadline, _ = dctx.Deadline()
	setDeadline(raw.SetDeadline, deadline)

	alpn := proto.ALPNDirect
	if kind == proto.KindTCP {
		alpn = proto.ALPNDirectTCP
	}

	tc := tls.Client(raw, mgr.clientTLS(view, peer.Machine, alpn))

	err = tc.HandshakeContext(dctx)
	if err != nil {
		return nil, fmt.Errorf("handshake: %w", err)
	}

	cs := tc.ConnectionState()
	if cs.NegotiatedProtocol != alpn || len(cs.PeerCertificates) == 0 {
		return nil, errBadALPN
	}

	stop := context.AfterFunc(dctx, func() { _ = raw.Close() })
	err = requestStream(tc, svc)

	stop()

	ctxErr := dctx.Err()
	if ctxErr != nil {
		return nil, fmt.Errorf("request stream: %w", ctxErr)
	}

	if err != nil {
		return nil, err
	}

	setDeadline(raw.SetDeadline, time.Time{})

	peerLeaf := cs.PeerCertificates[0]

	self, err := leafOf(&view.Identity)
	if err != nil {
		return nil, fmt.Errorf("own certificate: %w", err)
	}

	selfID, err := pki.CertIdentity(self)
	if err != nil {
		return nil, fmt.Errorf("own identity: %w", err)
	}

	sess := &session{
		m:            mgr,
		dir:          "out",
		kind:         kind,
		conn:         tc,
		local:        localAddrOf(raw),
		peerID:       policy.AgentIdentity(peer.Machine),
		peerFP:       pki.Fingerprint(peerLeaf),
		peerNotAfter: peerLeaf.NotAfter,
		rule: policy.Session{
			Identity: selfID, Fingerprint: pki.Fingerprint(self), NotAfter: self.NotAfter,
			Svc: svc, Machine: peer.Machine,
		},
	}

	if !mgr.register(sess) {
		return nil, errClosed
	}

	err = mgr.allowed(sess, mgr.view(), mgr.now())
	if err != nil {
		_ = sess.close()
		ok = true // s.close closed raw

		return nil, err
	}

	ok = true

	mgr.log.InfoContext(ctx, "Direct session open", slog.String("dir", "out"),
		slog.String("peer", sess.peerID),
		slog.String("svc", svc),
	)

	return &sessionConn{Conn: tc, s: sess}, nil
}

func requestStream(conn net.Conn, svc string) error {
	err := proto.WriteLine(conn, proto.StreamHeader{Svc: svc})
	if err != nil {
		return fmt.Errorf("write header: %w", err)
	}

	var reply proto.StreamReply

	err = proto.ReadLine(conn, &reply)
	if err != nil {
		return fmt.Errorf("read accept: %w", err)
	}

	if !reply.OK {
		return ErrRefused
	}

	return nil
}
