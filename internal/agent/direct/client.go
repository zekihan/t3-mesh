package direct

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
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

func (m *Manager) failed(machine string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	until, ok := m.failures[machine]
	if !ok {
		return false
	}

	if m.now().Before(until) {
		return true
	}

	delete(m.failures, machine)

	return false
}

func (m *Manager) remember(machine string) {
	m.mu.Lock()
	m.failures[machine] = m.now().Add(FailureMemory)
	m.mu.Unlock()
}

// Dial returns a ready byte stream to svc on machine over the direct path, or
// an error meaning the caller should use the tunnel.
func (m *Manager) Dial(ctx context.Context, machine, svc string) (net.Conn, error) {
	v := m.view()

	if ok, reason := m.active(v, true); !ok {
		return nil, fmt.Errorf("%w: %s", ErrInactive, reason)
	}

	var peer *proto.Peer

	for i := range v.Peers {
		if v.Peers[i].Machine == machine {
			peer = &v.Peers[i]

			break
		}
	}

	if peer == nil || len(peer.LANAddrs) == 0 || peer.DirectPort == 0 ||
		(v.HubConnected && !peer.Home) {
		return nil, fmt.Errorf("%w: %s", ErrNoPeer, machine)
	}

	if m.failed(machine) {
		return nil, fmt.Errorf("%w: %s", ErrRecentFail, machine)
	}

	if _, err := leafOf(v.Identity); err != nil {
		return nil, err
	}

	deadline := time.Now().Add(SetupTimeout)

	var lastErr error

	for i, a := range peer.LANAddrs {
		if ctx.Err() != nil {
			lastErr = ctx.Err()

			break
		}

		remaining := time.Until(deadline)
		if remaining <= 0 {
			break
		}

		attempt := time.Now().Add(remaining / time.Duration(len(peer.LANAddrs)-i))

		conn, err := m.dialOne(ctx, v, peer, a, svc, attempt)
		if err == nil {
			return conn, nil
		}

		lastErr = err

		m.log.Debug("direct dial failed", "machine", machine, "addr", a, "err", err)
	}

	if lastErr == nil {
		lastErr = errors.New("setup deadline exceeded")
	}

	if ctx.Err() == nil {
		m.remember(machine)
	}

	return nil, fmt.Errorf("direct dial %s: %w", machine, lastErr)
}

func hostPort(addr string, port int) string {
	if a, err := netip.ParseAddr(addr); err == nil {
		return netip.AddrPortFrom(a, uint16(port)).String() //nolint:gosec // port from hub table
	}

	return net.JoinHostPort(addr, strconv.Itoa(port))
}

func (m *Manager) clientTLS(v View, machine string) *tls.Config {
	identity := v.Identity
	want := policy.AgentIdentity(machine)

	return &tls.Config{
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{proto.ALPNDirect},
		InsecureSkipVerify: true, //nolint:gosec // verified in VerifyPeerCertificate against the clients CA
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return &identity, nil
		},
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error { //nolint:gosec // no client session cache, so no resumption
			cur := m.view()
			if cur.Roots == nil {
				return errors.New("direct: no trust bundle")
			}

			leaf, err := pki.VerifyPeer(raw, cur.Roots, x509.ExtKeyUsageServerAuth, m.now())
			if err != nil {
				return fmt.Errorf("verify server: %w", err)
			}

			id, err := pki.CertIdentity(leaf)
			if err != nil {
				return fmt.Errorf("server identity: %w", err)
			}

			if id != want {
				return fmt.Errorf("direct: server identity %q, want %q", id, want)
			}

			if err := policy.Revoked(cur.Revocations, id, pki.Fingerprint(leaf)); err != nil {
				return fmt.Errorf("server: %w", err)
			}

			return nil
		},
	}
}

func (m *Manager) dialOne(
	ctx context.Context,
	v View,
	peer *proto.Peer,
	addr, svc string,
	deadline time.Time,
) (net.Conn, error) {
	dctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	raw, err := m.opts.Dial(dctx, "tcp", hostPort(addr, peer.DirectPort))
	if err != nil {
		return nil, err
	}

	ok := false

	defer func() {
		if !ok {
			_ = raw.Close()
		}
	}()

	_ = raw.SetDeadline(deadline)

	tc := tls.Client(raw, m.clientTLS(v, peer.Machine))
	if err := tc.HandshakeContext(dctx); err != nil {
		return nil, fmt.Errorf("handshake: %w", err)
	}

	cs := tc.ConnectionState()
	if cs.NegotiatedProtocol != proto.ALPNDirect || len(cs.PeerCertificates) == 0 {
		return nil, errors.New("direct: bad alpn")
	}

	if err := proto.WriteLine(tc, proto.StreamHeader{Svc: svc}); err != nil {
		return nil, fmt.Errorf("write header: %w", err)
	}

	var reply proto.StreamReply
	if err := proto.ReadLine(tc, &reply); err != nil {
		return nil, fmt.Errorf("read accept: %w", err)
	}

	if !reply.OK {
		return nil, ErrRefused
	}

	_ = raw.SetDeadline(time.Time{})

	peerLeaf := cs.PeerCertificates[0]
	self, _ := leafOf(v.Identity)
	selfID, _ := pki.CertIdentity(self)

	s := &session{
		m:            m,
		dir:          "out",
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

	if !m.register(s) {
		return nil, errors.New("direct: closed")
	}

	if err := m.allowed(s, m.view(), m.now()); err != nil {
		_ = s.close()
		ok = true // s.close closed raw

		return nil, err
	}

	ok = true

	m.log.Info("direct session open", "dir", "out", "peer", s.peerID, "svc", svc)

	return &sessionConn{Conn: tc, s: s}, nil
}
