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
	errNotAPICaller = errors.New("hub: identity not listed under api.identities")

	errConfigRequired  = errors.New("hub: Config is required")
	errIssuerRequired  = errors.New("hub: Issuer is required")
	errUnknownIdentity = errors.New("hub: not a configured agent identity")
	errUnknownDevice   = errors.New("hub: not a configured enrolled-device identity")
	errNotEnrollable   = errors.New("hub: not a configured agent or enrolled-device identity")
	errUnknownKind     = errors.New("hub: unknown enrollment kind")
	errUnsupportedALPN = errors.New("hub: unsupported ALPN")
	errNeedClientCert  = errors.New("hub: tunnel needs a client certificate")
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
	started      time.Time
	releaseSince time.Time
	issuer       issuer.Issuer
	now          func() time.Time
	cfg          *hubconfig.Watcher
	tracked      map[*tracked]struct{}
	enrollH      *enroll.Handler
	log          *slog.Logger
	newest       map[string]string
	tokens       *enroll.Tokens
	machines     map[string]*machineState
	releaseRev   string
	wg           sync.WaitGroup
	sweepInt     time.Duration
	nextID       uint64
	proxyTO      time.Duration
	mu           sync.Mutex
	nmu          sync.Mutex
	tmu          sync.Mutex
	ready        atomic.Bool
}

// New builds a Server.
func New(opts Options) (*Server, error) {
	if opts.Config == nil {
		return nil, errConfigRequired
	}

	if opts.Issuer == nil {
		return nil, errIssuerRequired
	}

	server := &Server{
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
	if server.log == nil {
		server.log = slog.New(slog.DiscardHandler)
	}

	if server.now == nil {
		server.now = time.Now
	}

	if server.tokens == nil {
		server.tokens = enroll.NewTokens(server.now)
	}

	server.started = server.now()
	server.releaseSince = server.started
	server.releaseRev = opts.Config.Current().Release.Revision

	server.enrollH = &enroll.Handler{
		Tokens:  server.tokens,
		Issuer:  server.issuer,
		Allowed: server.EnrollAllowed,
		OnIssued: func(identity, fp string) {
			server.setNewest(identity, fp)
			server.pruneAsync(identity)
			server.log.Info(
				"Certificate issued",
				slog.Any("identity", identity),
				slog.Any("fingerprint", fp),
				slog.String("via", "enrollment"),
			)
		},
		Trust:   func() proto.TrustBundle { return server.cfg.Current().TrustBundle },
		Limiter: enroll.NewLimiter(server.now),
		Log:     server.log,
		Now:     server.now,
	}

	return server, nil
}

// ProxyHeaderTimeout returns the configured PROXY header timeout.
func (server *Server) ProxyHeaderTimeout() time.Duration { return server.proxyTO }

// Ready reports whether the tunnel listener is up and configuration is loaded.
func (server *Server) Ready() bool {
	return server.ready.Load() && server.cfg.Current() != nil
}

// EnrollAllowed reports whether identity may enroll: a configured agent
// identity or a configured enrolled device, that is not disabled.
func (server *Server) EnrollAllowed(identity string) error {
	snap := server.cfg.Current()
	if _, agent := snap.MachineForIdentity(identity); !agent && !snap.Device(identity) {
		return fmt.Errorf("%w: %q", errNotEnrollable, identity)
	}

	err := policy.Revoked(snap.Revocations, identity, "")
	if err != nil {
		return fmt.Errorf("hub: %w", err)
	}

	return nil
}

// EnrollTokenAllowed reports whether the operator may mint an enrollment token
// for identity as the given kind (enroll.KindAgent or enroll.KindDevice). The
// kinds do not overlap: an agent name is refused as a device and the other way
// round, so a token is never minted for an identity of the wrong kind.
func (server *Server) EnrollTokenAllowed(kind, identity string) error {
	snap := server.cfg.Current()

	switch kind {
	case enroll.KindAgent:
		if _, ok := snap.MachineForIdentity(identity); !ok {
			return fmt.Errorf("%w: %q", errUnknownIdentity, identity)
		}
	case enroll.KindDevice:
		if !snap.Device(identity) {
			return fmt.Errorf("%w: %q", errUnknownDevice, identity)
		}
	default:
		return fmt.Errorf("%w: %q", errUnknownKind, kind)
	}

	err := policy.Revoked(snap.Revocations, identity, "")
	if err != nil {
		return fmt.Errorf("hub: %w", err)
	}

	return nil
}

// ServeTunnels accepts agent tunnel and enrollment connections on ln until ctx
// is done.
func (server *Server) ServeTunnels(ctx context.Context, ln net.Listener) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	stop := context.AfterFunc(ctx, func() { _ = ln.Close() })
	defer stop()

	server.ready.Store(true)
	defer server.ready.Store(false)

	server.wg.Go(func() { server.sweepLoop(ctx) })

	var serveErr error

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() == nil && !errors.Is(err, net.ErrClosed) {
				serveErr = fmt.Errorf("hub: accept: %w", err)
			}

			break
		}

		server.wg.Go(func() { server.handleConn(ctx, conn) })
	}

	cancel()
	server.closeAllTracked()
	server.wg.Wait()

	return serveErr
}

// OnConfigChange applies a new snapshot: it closes what is no longer allowed
// and pushes updates to every session. Pass it to Watcher.Run.
func (server *Server) OnConfigChange(_, next *hubconfig.Snapshot) {
	server.mu.Lock()
	if next.Release.Revision != server.releaseRev {
		server.releaseRev = next.Release.Revision
		server.releaseSince = server.now()
	}
	server.mu.Unlock()

	server.enforce()
	server.kickAll()
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

func (server *Server) handleConn(ctx context.Context, raw net.Conn) {
	defer func() { _ = raw.Close() }()

	//nolint:errcheck // best-effort deadline; a dead connection fails the next read or write
	_ = raw.SetDeadline(time.Now().Add(handshakeTimeout))

	source, err := sourceAddr(raw)
	if err != nil {
		server.log.InfoContext(
			ctx,
			"Rejected peer",
			slog.String("reason", "no usable source address"),
			slog.Any("error", err),
		)

		return
	}

	tc := tls.Server(raw, server.tlsConfig(source))

	hctx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	err = tc.HandshakeContext(hctx)

	cancel()

	if err != nil {
		server.log.DebugContext(
			ctx,
			"TLS handshake failed",
			slog.String("source", source.String()),
			slog.Any("error", err),
		)

		return
	}

	//nolint:errcheck // best-effort deadline; a dead connection fails the next read or write
	_ = tc.SetDeadline(time.Time{})

	state := tc.ConnectionState()
	if state.NegotiatedProtocol == "" {
		// A plain TLS probe (Gatus) that offered no ALPN: it has seen the serving
		// certificate, and nothing is read from or served to it.
		server.log.DebugContext(ctx, "TLS probe closed", slog.String("source", source.String()))

		return
	}

	if state.NegotiatedProtocol == proto.ALPNEnroll {
		server.enrollH.Serve(ctx, tc, source)

		return
	}

	server.serveSession(ctx, tc, source, &state)
}

func (server *Server) tlsConfig(source netip.Addr) *tls.Config {
	return &tls.Config{
		MinVersion:             tls.VersionTLS13,
		MaxVersion:             tls.VersionTLS13,
		NextProtos:             append(proto.AcceptedTunnelALPNs(), proto.ALPNEnroll),
		ClientAuth:             tls.RequestClientCert,
		SessionTicketsDisabled: true,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return server.cfg.Current().ServingCert, nil
		},
		VerifyConnection: func(cs tls.ConnectionState) error {
			err := server.verifyPeer(&cs)
			if err != nil {
				server.log.Info(
					"Rejected peer",
					slog.String("source", source.String()),
					slog.Any("alpn", cs.NegotiatedProtocol),
					slog.String("reason", err.Error()),
				)

				return err
			}

			return nil
		},
	}
}

func (server *Server) verifyPeer(cs *tls.ConnectionState) error {
	switch {
	case cs.NegotiatedProtocol == "":
		// The client offered no ALPN; handleConn closes it after the handshake.
		// A client offering only other protocols fails the handshake in crypto/tls.
		return nil
	case cs.NegotiatedProtocol == proto.ALPNEnroll:
		if !server.tokens.Outstanding() {
			return errNoEnrollment
		}

		return nil
	case slices.Contains(proto.AcceptedTunnelALPNs(), cs.NegotiatedProtocol):
		_, err := server.admit(server.cfg.Current(), cs.PeerCertificates, server.now())

		return err
	default:
		return fmt.Errorf("%w: %q", errUnsupportedALPN, cs.NegotiatedProtocol)
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
func (server *Server) admit(
	snap *hubconfig.Snapshot,
	certs []*x509.Certificate,
	now time.Time,
) (admitted, error) {
	if len(certs) == 0 {
		return admitted{}, errNeedClientCert
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
		return admitted{}, fmt.Errorf("%w: %q", errUnknownIdentity, identity)
	}

	fp := pki.Fingerprint(leaf)

	err = policy.Revoked(snap.Revocations, identity, fp)
	if err != nil {
		return admitted{}, fmt.Errorf("hub: %w", err)
	}

	return admitted{leaf: leaf, identity: identity, machine: machine, fingerprint: fp}, nil
}

// checkNewest reports whether fp is the newest issued leaf for identity. NoRecord
// is true when the issuer has no record at all (the leaf is then admitted).
func (server *Server) checkNewest(
	ctx context.Context,
	identity, fp string,
) (bool, bool, error) {
	server.nmu.Lock()
	cached := server.newest[identity]
	server.nmu.Unlock()

	if cached == fp {
		return true, false, nil
	}

	ctx, cancel := context.WithTimeout(ctx, newestTimeout)
	defer cancel()

	got, err := server.issuer.Newest(ctx, identity)
	if err != nil {
		return false, false, fmt.Errorf("hub: newest leaf lookup: %w", err)
	}

	if got == "" {
		if cached != "" {
			return false, false, nil
		}

		return true, true, nil
	}

	server.setNewest(identity, got)

	return got == fp, false, nil
}

func (server *Server) setNewest(identity, fp string) {
	server.nmu.Lock()
	server.newest[identity] = fp
	server.nmu.Unlock()
}

func (server *Server) sweepLoop(ctx context.Context) {
	ticker := time.NewTicker(server.sweepInt)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			server.enforce()
		}
	}
}

// enforce closes sessions and streams that are no longer allowed, including
// those whose certificate has expired.
func (server *Server) enforce() {
	snap := server.cfg.Current()
	now := server.now()

	for _, sess := range server.allSessions() {
		if rej, bad := server.sessionViolation(snap, sess, now); bad {
			server.log.Info(
				"Revoke session",
				slog.Any("machine", sess.machine),
				slog.Any("identity", sess.identity),
				slog.Any("reason", rej.Detail),
			)
			go sess.reject(rej)
		}
	}

	// Enforcement runs from both the sweep and config changes, so the reasons stay
	// local rather than on the shared tracked entries.
	type revoked struct {
		track *tracked
		err   error
	}

	var doomed []revoked

	server.tmu.Lock()
	for t := range server.tracked {
		err := policy.Check(snap.Rules, snap.Revocations, t.pol, now)
		if err != nil {
			doomed = append(doomed, revoked{track: t, err: err})
		}
	}
	server.tmu.Unlock()

	for _, item := range doomed {
		server.log.Info(
			"Revoke stream",
			slog.Any("kind", item.track.kind),
			slog.Any("identity", item.track.pol.Identity),
			slog.String("target", policy.Target(item.track.pol.Svc, item.track.pol.Machine)),
			slog.String("reason", item.err.Error()),
		)
		item.track.close()
	}
}

func (server *Server) sessionViolation(
	snap *hubconfig.Snapshot,
	sess *session,
	now time.Time,
) (proto.Reject, bool) {
	if m, ok := snap.MachineForIdentity(sess.identity); !ok || m != sess.machine {
		return proto.Reject{Reason: proto.RejectOther, Detail: "machine no longer configured"}, true
	}

	err := policy.Revoked(snap.Revocations, sess.identity, sess.fingerprint)
	if err != nil {
		return proto.Reject{Reason: proto.RejectIdentityDisabled, Detail: err.Error()}, true
	}

	if !now.Before(sess.notAfter) {
		return proto.Reject{Reason: proto.RejectOther, Detail: "certificate expired"}, true
	}

	return proto.Reject{}, false
}
