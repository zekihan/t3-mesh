// Package hub implements the t3-mesh hub: the agent tunnel listener, the viewer
// reverse proxy, live revocation, certificate renewal and the ops endpoints.
package hub

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zekihan/t3-mesh/internal/hub/enroll"
	"github.com/zekihan/t3-mesh/internal/hub/hubconfig"
	"github.com/zekihan/t3-mesh/internal/hub/issuer"
	"github.com/zekihan/t3-mesh/internal/hub/proxyproto"
	"github.com/zekihan/t3-mesh/internal/pki"
	"github.com/zekihan/t3-mesh/internal/policy"
	"github.com/zekihan/t3-mesh/internal/proto"
)

const (
	handshakeTimeout      = 10 * time.Second
	helloTimeout          = 10 * time.Second
	headerReadTimeout     = 10 * time.Second
	replyTimeout          = 15 * time.Second
	newestTimeout         = 10 * time.Second
	defaultSweepEvery     = time.Second
	maxSessionsPerMachine = 8
	maxWarnings           = 20
)

var (
	errNoEnrollment = errors.New("hub: enrollment is not open")
	errNoSession    = errors.New("hub: machine not connected")
)

// Options configures a Server.
type Options struct {
	Config *hubconfig.Watcher
	Issuer issuer.Issuer
	Tokens *enroll.Tokens
	Log    *slog.Logger
	// Now is the clock used for certificate and policy decisions.
	Now func() time.Time
	// ProxyHeaderTimeout is the PROXY v2 header timeout the caller passes to
	// proxyproto.Listen; the Server exposes it through ProxyHeaderTimeout.
	ProxyHeaderTimeout time.Duration
}

// Server is the hub.
type Server struct {
	cfg      *hubconfig.Watcher
	issuer   issuer.Issuer
	tokens   *enroll.Tokens
	enrollH  *enroll.Handler
	log      *slog.Logger
	now      func() time.Time
	proxyTO  time.Duration
	started  time.Time
	sweepInt time.Duration

	ready atomic.Bool
	wg    sync.WaitGroup

	mu           sync.Mutex
	machines     map[string]*machineState
	nextID       uint64
	releaseRev   string
	releaseSince time.Time

	nmu    sync.Mutex
	newest map[string]string

	tmu     sync.Mutex
	tracked map[*tracked]struct{}
}

// New builds a Server.
func New(opts Options) (*Server, error) {
	if opts.Config == nil {
		return nil, errors.New("hub: Config is required")
	}

	if opts.Issuer == nil {
		return nil, errors.New("hub: Issuer is required")
	}

	s := &Server{
		cfg:      opts.Config,
		issuer:   opts.Issuer,
		tokens:   opts.Tokens,
		log:      opts.Log,
		now:      opts.Now,
		proxyTO:  opts.ProxyHeaderTimeout,
		sweepInt: defaultSweepEvery,
		machines: map[string]*machineState{},
		newest:   map[string]string{},
		tracked:  map[*tracked]struct{}{},
	}
	if s.log == nil {
		s.log = slog.New(slog.DiscardHandler)
	}

	if s.now == nil {
		s.now = time.Now
	}

	if s.tokens == nil {
		s.tokens = enroll.NewTokens(s.now)
	}

	s.started = s.now()
	s.releaseSince = s.started
	s.releaseRev = opts.Config.Current().Release.Revision

	s.enrollH = &enroll.Handler{
		Tokens:  s.tokens,
		Issuer:  s.issuer,
		Allowed: s.EnrollAllowed,
		OnIssued: func(identity, fp string) {
			s.setNewest(identity, fp)
			s.log.Info("certificate issued", "identity", identity, "fingerprint", fp, "via", "enrollment")
		},
		Limiter: enroll.NewLimiter(s.now),
		Log:     s.log,
		Now:     s.now,
	}

	return s, nil
}

// ProxyHeaderTimeout returns the configured PROXY header timeout.
func (s *Server) ProxyHeaderTimeout() time.Duration { return s.proxyTO }

// Ready reports whether the tunnel listener is up and configuration is loaded.
func (s *Server) Ready() bool {
	return s.ready.Load() && s.cfg.Current() != nil
}

// EnrollAllowed reports whether identity may enroll: a configured agent
// identity that is not disabled.
func (s *Server) EnrollAllowed(identity string) error {
	snap := s.cfg.Current()
	if _, ok := snap.MachineForIdentity(identity); !ok {
		return fmt.Errorf("hub: %q is not a configured agent identity", identity)
	}

	if err := policy.Revoked(snap.Revocations, identity, ""); err != nil {
		return fmt.Errorf("hub: %w", err)
	}

	return nil
}

// ServeTunnels accepts agent tunnel and enrollment connections on ln until ctx
// is done.
func (s *Server) ServeTunnels(ctx context.Context, ln net.Listener) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	stop := context.AfterFunc(ctx, func() { _ = ln.Close() })
	defer stop()

	s.ready.Store(true)
	defer s.ready.Store(false)

	s.wg.Go(func() { s.sweepLoop(ctx) })

	var serveErr error

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() == nil && !errors.Is(err, net.ErrClosed) {
				serveErr = fmt.Errorf("hub: accept: %w", err)
			}

			break
		}

		s.wg.Go(func() { s.handleConn(ctx, conn) })
	}

	cancel()
	s.closeAllTracked()
	s.wg.Wait()

	return serveErr
}

// sourceAddr returns the client source address of conn: the PROXY v2 source
// when conn comes from proxyproto, the TCP peer otherwise.
func sourceAddr(conn net.Conn) (netip.Addr, error) {
	if pc, ok := conn.(*proxyproto.Conn); ok {
		ap, err := pc.Source()
		if err != nil {
			return netip.Addr{}, fmt.Errorf("hub: PROXY source: %w", err)
		}

		return ap.Addr().Unmap(), nil
	}

	if ta, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		ap := ta.AddrPort()
		if ap.IsValid() {
			return ap.Addr().Unmap(), nil
		}
	}

	ap, err := netip.ParseAddrPort(conn.RemoteAddr().String())
	if err != nil {
		return netip.Addr{}, fmt.Errorf("hub: peer address: %w", err)
	}

	return ap.Addr().Unmap(), nil
}

func (s *Server) handleConn(ctx context.Context, raw net.Conn) {
	defer func() { _ = raw.Close() }()

	_ = raw.SetDeadline(time.Now().Add(handshakeTimeout))

	source, err := sourceAddr(raw)
	if err != nil {
		s.log.Info("rejected peer", "reason", "no usable source address", "error", err)

		return
	}

	tc := tls.Server(raw, s.tlsConfig(source))

	hctx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	err = tc.HandshakeContext(hctx)

	cancel()

	if err != nil {
		s.log.Debug("tls handshake failed", "source", source.String(), "error", err)

		return
	}

	_ = tc.SetDeadline(time.Time{})

	state := tc.ConnectionState()
	if state.NegotiatedProtocol == proto.ALPNEnroll {
		s.enrollH.Serve(ctx, tc, source)

		return
	}

	s.serveSession(ctx, tc, source, state)
}

func (s *Server) tlsConfig(source netip.Addr) *tls.Config {
	return &tls.Config{
		MinVersion:             tls.VersionTLS13,
		MaxVersion:             tls.VersionTLS13,
		NextProtos:             append(proto.AcceptedTunnelALPNs(), proto.ALPNEnroll),
		ClientAuth:             tls.RequestClientCert,
		SessionTicketsDisabled: true,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return s.cfg.Current().ServingCert, nil
		},
		VerifyConnection: func(cs tls.ConnectionState) error {
			if err := s.verifyPeer(cs); err != nil {
				s.log.Info("rejected peer", "source", source.String(), "alpn", cs.NegotiatedProtocol, "reason", err.Error())

				return err
			}

			return nil
		},
	}
}

func (s *Server) verifyPeer(cs tls.ConnectionState) error {
	switch {
	case cs.NegotiatedProtocol == proto.ALPNEnroll:
		if !s.tokens.Outstanding() {
			return errNoEnrollment
		}

		return nil
	case slices.Contains(proto.AcceptedTunnelALPNs(), cs.NegotiatedProtocol):
		_, err := s.admit(s.cfg.Current(), cs.PeerCertificates, s.now())

		return err
	default:
		return fmt.Errorf("hub: unsupported ALPN %q", cs.NegotiatedProtocol)
	}
}

type admitted struct {
	leaf        *x509.Certificate
	identity    string
	machine     string
	fingerprint string
}

// admit verifies a tunnel client certificate chain against the trust bundle
// and the configured agents. It does not check the newest-leaf rule.
func (s *Server) admit(snap *hubconfig.Snapshot, certs []*x509.Certificate, now time.Time) (admitted, error) {
	if len(certs) == 0 {
		return admitted{}, errors.New("hub: tunnel needs a client certificate")
	}

	raw := make([][]byte, len(certs))
	for i, c := range certs {
		raw[i] = c.Raw
	}

	leaf, err := pki.VerifyPeer(raw, snap.TrustPool, x509.ExtKeyUsageClientAuth, now)
	if err != nil {
		return admitted{}, fmt.Errorf("hub: %w", err)
	}

	identity, err := pki.CertIdentity(leaf)
	if err != nil {
		return admitted{}, fmt.Errorf("hub: %w", err)
	}

	machine, ok := snap.MachineForIdentity(identity)
	if !ok {
		return admitted{}, fmt.Errorf("hub: %q is not a configured agent identity", identity)
	}

	fp := pki.Fingerprint(leaf)
	if err := policy.Revoked(snap.Revocations, identity, fp); err != nil {
		return admitted{}, fmt.Errorf("hub: %w", err)
	}

	return admitted{leaf: leaf, identity: identity, machine: machine, fingerprint: fp}, nil
}

// checkNewest reports whether fp is the newest issued leaf for identity. noRecord
// is true when the issuer has no record at all (the leaf is then admitted).
func (s *Server) checkNewest(ctx context.Context, identity, fp string) (ok, noRecord bool, err error) {
	s.nmu.Lock()
	cached := s.newest[identity]
	s.nmu.Unlock()

	if cached == fp {
		return true, false, nil
	}

	ctx, cancel := context.WithTimeout(ctx, newestTimeout)
	defer cancel()

	got, err := s.issuer.Newest(ctx, identity)
	if err != nil {
		return false, false, fmt.Errorf("hub: newest leaf lookup: %w", err)
	}

	if got == "" {
		if cached != "" {
			return false, false, nil
		}

		return true, true, nil
	}

	s.setNewest(identity, got)

	return got == fp, false, nil
}

func (s *Server) setNewest(identity, fp string) {
	s.nmu.Lock()
	s.newest[identity] = fp
	s.nmu.Unlock()
}

// OnConfigChange applies a new snapshot: it closes what is no longer allowed
// and pushes updates to every session. Pass it to Watcher.Run.
func (s *Server) OnConfigChange(_, next *hubconfig.Snapshot) {
	s.mu.Lock()
	if next.Release.Revision != s.releaseRev {
		s.releaseRev = next.Release.Revision
		s.releaseSince = s.now()
	}
	s.mu.Unlock()

	s.enforce()
	s.kickAll()
}

func (s *Server) sweepLoop(ctx context.Context) {
	t := time.NewTicker(s.sweepInt)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.enforce()
		}
	}
}

// enforce closes sessions and streams that are no longer allowed, including
// those whose certificate has expired.
func (s *Server) enforce() {
	snap := s.cfg.Current()
	now := s.now()

	for _, sess := range s.allSessions() {
		if rej, bad := s.sessionViolation(snap, sess, now); bad {
			s.log.Info("revoke session", "machine", sess.machine, "identity", sess.identity, "reason", rej.Detail)
			go sess.reject(rej)
		}
	}

	var doomed []*tracked

	s.tmu.Lock()
	for t := range s.tracked {
		if err := policy.Check(snap.Rules, snap.Revocations, t.pol, now); err != nil {
			t.err = err
			doomed = append(doomed, t)
		}
	}
	s.tmu.Unlock()

	for _, t := range doomed {
		s.log.Info("revoke stream", "kind", t.kind, "identity", t.pol.Identity,
			"target", policy.Target(t.pol.Svc, t.pol.Machine), "reason", t.err.Error())
		t.close()
	}
}

func (s *Server) sessionViolation(snap *hubconfig.Snapshot, sess *session, now time.Time) (proto.Reject, bool) {
	if m, ok := snap.MachineForIdentity(sess.identity); !ok || m != sess.machine {
		return proto.Reject{Reason: proto.RejectOther, Detail: "machine no longer configured"}, true
	}

	if err := policy.Revoked(snap.Revocations, sess.identity, sess.fingerprint); err != nil {
		return proto.Reject{Reason: proto.RejectIdentityDisabled, Detail: err.Error()}, true
	}

	if !now.Before(sess.notAfter) {
		return proto.Reject{Reason: proto.RejectOther, Detail: "certificate expired"}, true
	}

	return proto.Reject{}, false
}
