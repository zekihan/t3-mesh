package direct

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/zekihan/t3-mesh/internal/pki"
	"github.com/zekihan/t3-mesh/internal/policy"
	"github.com/zekihan/t3-mesh/internal/proto"
	"github.com/zekihan/t3-mesh/internal/tunnel"
)

func (m *Manager) serverTLS() *tls.Config {
	return &tls.Config{
		MinVersion:             tls.VersionTLS13,
		NextProtos:             []string{proto.ALPNDirect},
		ClientAuth:             tls.RequireAnyClientCert,
		SessionTicketsDisabled: true,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			v := m.view()
			if len(v.Identity.Certificate) == 0 {
				return nil, errors.New("direct: no identity")
			}

			c := v.Identity

			return &c, nil
		},
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			v := m.view()
			if v.Roots == nil {
				return errors.New("direct: no trust bundle")
			}

			if _, err := pki.VerifyPeer(raw, v.Roots, x509.ExtKeyUsageClientAuth, m.now()); err != nil {
				return fmt.Errorf("verify caller: %w", err)
			}

			return nil
		},
	}
}

func (m *Manager) acceptLoop(ln net.Listener) {
	defer m.wg.Done()

	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}

			m.log.Warn("direct accept", "err", err)

			select {
			case <-m.ctx.Done():
				return
			case <-time.After(50 * time.Millisecond):
			}

			continue
		}

		m.mu.Lock()
		if m.closed {
			m.mu.Unlock()

			_ = c.Close()

			return
		}

		m.pending[c] = struct{}{}
		m.wg.Add(1)
		m.mu.Unlock()

		go m.serve(c)
	}
}

func (m *Manager) refuse(tc net.Conn, why string, args ...any) {
	m.log.Info("direct caller refused", append([]any{"reason", why}, args...)...)

	_ = tc.SetWriteDeadline(time.Now().Add(time.Second))
	_ = proto.WriteLine(tc, proto.StreamReply{OK: false, Error: "refused"})
	_ = tc.Close()
}

func (m *Manager) serve(raw net.Conn) {
	defer m.wg.Done()

	defer func() {
		m.mu.Lock()
		delete(m.pending, raw)
		m.mu.Unlock()
	}()

	if ok, reason := m.Active(); !ok {
		m.log.Debug("direct connection refused", "reason", reason)

		_ = raw.Close()

		return
	}

	_ = raw.SetDeadline(time.Now().Add(serverSetupLimit))

	tc := tls.Server(raw, m.serverTLS())

	ctx, cancel := context.WithTimeout(m.ctx, serverSetupLimit)
	defer cancel()

	if err := tc.HandshakeContext(ctx); err != nil {
		m.log.Info("direct handshake failed", "remote", raw.RemoteAddr().String(), "err", err)

		_ = raw.Close()

		return
	}

	cs := tc.ConnectionState()
	if cs.NegotiatedProtocol != proto.ALPNDirect || len(cs.PeerCertificates) == 0 {
		m.refuse(tc, "bad alpn or no certificate")

		return
	}

	leaf := cs.PeerCertificates[0]

	identity, err := pki.CertIdentity(leaf)
	if err != nil || !policy.IsAgent(identity) {
		m.refuse(tc, "caller is not an agent identity", "err", err)

		return
	}

	var hdr proto.StreamHeader
	if err := proto.ReadLine(tc, &hdr); err != nil {
		m.refuse(tc, "read header", "err", err)

		return
	}

	v := m.view()
	machine := strings.TrimPrefix(identity, policy.AgentPrefix)

	// Authorization comes from the rules checked below. The peer table lists
	// machines this agent may reach, not those that may reach it, so it is not
	// consulted here.
	if !policy.IsAgent(identity) || machine == "" || machine == v.Self {
		m.refuse(tc, "caller is not another agent", "identity", identity)

		return
	}

	target, ok := m.opts.Serve[hdr.Svc]
	if !ok || hdr.Svc == "" {
		m.refuse(tc, "service not served", "identity", identity, "svc", hdr.Svc)

		return
	}

	s := &session{
		m:            m,
		dir:          "in",
		conn:         tc,
		local:        localAddrOf(raw),
		peerID:       identity,
		peerFP:       pki.Fingerprint(leaf),
		peerNotAfter: leaf.NotAfter,
		rule: policy.Session{
			Identity: identity, Fingerprint: pki.Fingerprint(leaf), NotAfter: leaf.NotAfter,
			Svc: hdr.Svc, Machine: v.Self,
		},
	}

	if err := m.allowed(s, v, m.now()); err != nil {
		m.refuse(tc, "policy", "err", err)

		return
	}

	dctx, dcancel := context.WithTimeout(m.ctx, serverSetupLimit)
	backend, err := m.opts.Dial(dctx, "tcp", target)

	dcancel()

	if err != nil {
		m.log.Warn("direct serve target unreachable", "svc", hdr.Svc, "err", err)
		m.refuse(tc, "target unreachable")

		return
	}

	if !m.register(s) {
		_ = backend.Close()
		_ = tc.Close()

		return
	}

	if err := m.allowed(s, m.view(), m.now()); err != nil {
		_ = backend.Close()
		_ = s.close()

		return
	}

	if err := proto.WriteLine(tc, proto.StreamReply{OK: true}); err != nil {
		_ = backend.Close()
		_ = s.close()

		return
	}

	_ = raw.SetDeadline(time.Time{})

	m.log.Info("direct session open", "dir", "in", "peer", identity, "svc", hdr.Svc)

	tunnel.Join(tc, backend)

	_ = s.close()
}
