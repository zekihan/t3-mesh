package direct

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/zekihan/t3-mesh/internal/pki"
	"github.com/zekihan/t3-mesh/internal/policy"
	"github.com/zekihan/t3-mesh/internal/proto"
	"github.com/zekihan/t3-mesh/internal/tunnel"
)

// serverTLS is the TLS configuration of every listener: TLS 1.3, the agent's own
// leaf as the server certificate, and a client certificate that must chain to the
// cached clients CA bundle. What else a caller must be is decided by the listener
// that serves it, through verify.
func (mgr *Manager) serverTLS(alpn string, verify func(raw [][]byte) error) *tls.Config {
	return &tls.Config{
		MinVersion:             tls.VersionTLS13,
		NextProtos:             []string{alpn},
		ClientAuth:             tls.RequireAnyClientCert,
		SessionTicketsDisabled: true,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			v := mgr.view()
			if len(v.Identity.Certificate) == 0 {
				return nil, errNoIdentity
			}

			c := v.Identity

			return &c, nil
		},
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			return verify(raw)
		},
	}
}

// verifyAgent accepts a caller whose certificate chains to the cached bundle with
// client auth usage.
func (mgr *Manager) verifyAgent(raw [][]byte) error {
	v := mgr.view()
	if v.Roots == nil {
		return errNoTrustBundle
	}

	_, err := pki.VerifyPeer(raw, v.Roots, x509.ExtKeyUsageClientAuth, mgr.now())
	if err != nil {
		return fmt.Errorf("verify caller: %w", err)
	}

	return nil
}

func (mgr *Manager) acceptLoop(ln net.Listener, serve func(net.Conn)) {
	defer mgr.wg.Done()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}

			mgr.log.Warn("Direct accept", slog.Any("err", err))

			select {
			case <-mgr.ctx.Done():
				return
			case <-time.After(acceptRetryDelay):
			}

			continue
		}

		mgr.mu.Lock()
		if mgr.closed {
			mgr.mu.Unlock()

			_ = conn.Close()

			return
		}

		mgr.pending[conn] = struct{}{}
		mgr.wg.Add(1)
		mgr.mu.Unlock()

		go serve(conn)
	}
}

func (mgr *Manager) refuse(tc net.Conn, why string, attrs ...slog.Attr) {
	mgr.log.LogAttrs(
		mgr.ctx,
		slog.LevelInfo,
		"Direct caller refused",
		append([]slog.Attr{slog.String("reason", why)}, attrs...)...,
	)

	setDeadline(tc.SetWriteDeadline, time.Now().Add(time.Second))
	replyQuietly(tc, proto.StreamReply{OK: false, Error: "refused"})
	_ = tc.Close()
}

// handshake completes the TLS handshake with a caller and checks that it is an
// agent. It refuses the connection and returns ok=false otherwise.
func (mgr *Manager) handshake(raw net.Conn) (*tls.Conn, string, *x509.Certificate, bool) {
	cfg := mgr.serverTLS(proto.ALPNDirect, mgr.verifyAgent)
	cfg.NextProtos = append(cfg.NextProtos, proto.ALPNDirectTCP)
	tc := tls.Server(raw, cfg)

	ctx, cancel := context.WithTimeout(mgr.ctx, serverSetupLimit)
	defer cancel()

	err := tc.HandshakeContext(ctx)
	if err != nil {
		mgr.log.Info("Direct handshake failed", slog.String("remote", raw.RemoteAddr().String()),
			slog.Any("err", err),
		)

		_ = raw.Close()

		return nil, "", nil, false
	}

	cs := tc.ConnectionState()
	if (cs.NegotiatedProtocol != proto.ALPNDirect && cs.NegotiatedProtocol != proto.ALPNDirectTCP) ||
		len(cs.PeerCertificates) == 0 {
		mgr.refuse(tc, "bad alpn or no certificate")

		return nil, "", nil, false
	}

	leaf := cs.PeerCertificates[0]

	identity, err := pki.CertIdentity(leaf)
	if err != nil || !policy.IsAgent(identity) {
		mgr.refuse(tc, "caller is not an agent identity", slog.Any("err", err))

		return nil, "", nil, false
	}

	return tc, identity, leaf, true
}

func (mgr *Manager) serve(raw net.Conn) {
	defer mgr.wg.Done()

	defer func() {
		mgr.mu.Lock()
		delete(mgr.pending, raw)
		mgr.mu.Unlock()
	}()

	if ok, reason := mgr.Active(); !ok {
		mgr.log.Debug("Direct connection refused", slog.String("reason", reason))

		_ = raw.Close()

		return
	}

	setDeadline(raw.SetDeadline, time.Now().Add(serverSetupLimit))

	tc, identity, leaf, ok := mgr.handshake(raw)
	if !ok {
		return
	}

	var hdr proto.StreamHeader

	err := proto.ReadLine(tc, &hdr)
	if err != nil {
		mgr.refuse(tc, "read header", slog.Any("err", err))

		return
	}

	view := mgr.view()
	machine := strings.TrimPrefix(identity, policy.AgentPrefix)

	// Authorization comes from the rules checked below. The peer table lists
	// machines this agent may reach, not those that may reach it, so it is not
	// consulted here.
	if !policy.IsAgent(identity) || machine == "" || machine == view.Self {
		mgr.refuse(tc, "caller is not another agent", slog.String("identity", identity))

		return
	}

	target, ok := mgr.opts.Serve[hdr.Svc]
	if !ok || hdr.Svc == "" {
		mgr.refuse(
			tc,
			"service not served",
			slog.String("identity", identity),
			slog.String("svc", hdr.Svc),
		)

		return
	}

	kind := proto.KindHTTP
	if tc.ConnectionState().NegotiatedProtocol == proto.ALPNDirectTCP {
		kind = proto.KindTCP
	}

	sess := &session{
		m:            mgr,
		dir:          "in",
		kind:         kind,
		conn:         tc,
		local:        localAddrOf(raw),
		peerID:       identity,
		peerFP:       pki.Fingerprint(leaf),
		peerNotAfter: leaf.NotAfter,
		rule: policy.Session{
			Identity: identity, Fingerprint: pki.Fingerprint(leaf), NotAfter: leaf.NotAfter,
			Svc: hdr.Svc, Machine: view.Self,
		},
	}

	err = mgr.allowed(sess, view, mgr.now())
	if err != nil {
		mgr.refuse(tc, "policy", slog.Any("err", err))

		return
	}

	dctx, dcancel := context.WithTimeout(mgr.ctx, serverSetupLimit)
	backend, err := mgr.opts.Dial(dctx, "tcp", target)

	dcancel()

	if err != nil {
		mgr.log.Warn("Direct serve target unreachable", slog.String("svc", hdr.Svc),
			slog.Any("err", err),
		)
		mgr.refuse(tc, "target unreachable")

		return
	}

	mgr.splice(sess, raw, tc, backend)
}

func (mgr *Manager) splice(sess *session, raw net.Conn, tc *tls.Conn, backend net.Conn) {
	if !mgr.register(sess) {
		_ = backend.Close()
		_ = tc.Close()

		return
	}

	err := mgr.allowed(sess, mgr.view(), mgr.now())
	if err != nil {
		_ = backend.Close()
		_ = sess.close()

		return
	}

	err = proto.WriteLine(tc, proto.StreamReply{OK: true})
	if err != nil {
		_ = backend.Close()
		_ = sess.close()

		return
	}

	setDeadline(raw.SetDeadline, time.Time{})

	mgr.log.Info("Direct session open", slog.String("dir", "in"),
		slog.String("peer", sess.peerID),
		slog.String("svc", sess.rule.Svc),
	)

	if sess.kind == proto.KindTCP {
		tunnel.JoinTCP(backend, tc)
	} else {
		tunnel.Join(tc, backend)
	}

	_ = sess.close()
}

// setDeadline is best effort: a dead connection fails the next I/O call anyway.
func setDeadline(set func(time.Time) error, deadline time.Time) {
	_ = set(deadline) //nolint:errcheck // a dead conn fails the next I/O call anyway
}

// replyQuietly writes a reply nobody is obliged to receive; the peer may be gone.
func replyQuietly(w io.Writer, reply proto.StreamReply) {
	_ = proto.WriteLine(w, reply) //nolint:errcheck // best-effort reply to a dropped peer
}
