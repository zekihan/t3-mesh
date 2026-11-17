package enroll

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"time"

	"github.com/zekihan/t3-mesh/internal/hub/issuer"
	"github.com/zekihan/t3-mesh/internal/pki"
	"github.com/zekihan/t3-mesh/internal/proto"
)

// exchangeTimeout bounds a whole enrollment exchange.
const exchangeTimeout = 30 * time.Second

// Handler serves enrollment connections (ALPN t3-mesh-enroll/1).
type Handler struct {
	Tokens   *Tokens
	Issuer   issuer.Issuer
	Allowed  func(identity string) error
	OnIssued func(identity, fingerprint string)
	Limiter  *Limiter
	Log      *slog.Logger
	Now      func() time.Time
}

// errRejected carries a short, non-sensitive detail for the client.
type errRejected struct {
	detail string
	cause  error
}

func (e *errRejected) Error() string {
	if e.cause != nil {
		return e.detail + ": " + e.cause.Error()
	}

	return e.detail
}

func (e *errRejected) Unwrap() error { return e.cause }

func reject(detail string, cause error) error { return &errRejected{detail: detail, cause: cause} }

// Serve runs one enrollment exchange on conn and closes it.
//
// Token redemption order: the request is read and the CSR validated first, so
// a garbage request cannot burn a stolen or valid token. Once the CSR is
// valid, the token is redeemed (consumed) before the identity, policy and
// issuance checks, so a valid token presented with a mismatched identity or
// for a disabled identity is burned.
func (h *Handler) Serve(ctx context.Context, conn net.Conn, source netip.Addr) {
	defer func() { _ = conn.Close() }()

	log := h.Log
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}

	log = log.With("source", source.String())

	_ = conn.SetDeadline(time.Now().Add(exchangeTimeout))

	if h.Limiter != nil && !h.Limiter.Allow(source) {
		log.Warn("enrollment rate limited")
		h.writeReject(conn, "too many attempts")

		return
	}

	ctx, cancel := context.WithTimeout(ctx, exchangeTimeout)
	defer cancel()

	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	identity, fp, resp, err := h.exchange(ctx, conn)
	if identity != "" {
		log = log.With("identity", identity)
	}

	if err != nil {
		log.Warn("enrollment failed", "error", err)

		detail := "enrollment failed"

		var rj *errRejected
		if errors.As(err, &rj) {
			detail = rj.detail
		}

		h.writeReject(conn, detail)

		return
	}

	if err = proto.WriteMessage(conn, resp); err != nil {
		log.Warn("enrollment reply failed", "error", err, "fingerprint", fp)

		return
	}

	log.Info("enrollment succeeded", "fingerprint", fp)
}

func (h *Handler) writeReject(conn net.Conn, detail string) {
	_ = proto.WriteMessage(conn, proto.Reject{Reason: proto.RejectEnrollFailed, Detail: detail})
}

func (h *Handler) exchange(ctx context.Context, conn net.Conn) (identity, fp string, resp proto.Enrolled, err error) {
	msg, err := proto.ReadMessage(conn, proto.MaxEnrollSize)
	if err != nil {
		return "", "", resp, reject("bad request", err)
	}

	req, ok := msg.(proto.Enroll)
	if !ok {
		return "", "", resp, reject("unexpected message", fmt.Errorf("got %s", msg.MessageType()))
	}

	csr, csrIdentity, err := pki.ValidateCSR([]byte(req.CSR))
	if err != nil {
		return "", "", resp, reject("invalid CSR", err)
	}

	tokenIdentity, err := h.Tokens.Redeem(req.Token)
	if err != nil {
		return csrIdentity, "", resp, reject("invalid token", err)
	}

	if tokenIdentity != csrIdentity {
		return csrIdentity, "", resp, reject("identity mismatch", fmt.Errorf("token bound to %q", tokenIdentity))
	}

	identity = csrIdentity

	if h.Allowed != nil {
		if err = h.Allowed(identity); err != nil {
			return identity, "", resp, reject("identity not allowed", err)
		}
	}

	certPEM, chainPEM, err := h.Issuer.Issue(ctx, identity, []byte(req.CSR))
	if err != nil {
		return identity, "", resp, reject("issuance failed", err)
	}

	leaf, err := verifyLeaf(certPEM, identity, csr)
	if err != nil {
		return identity, "", resp, reject("issuance failed", err)
	}

	fp = pki.Fingerprint(leaf)

	if h.OnIssued != nil {
		h.OnIssued(identity, fp)
	}

	return identity, fp, proto.Enrolled{Certificate: string(certPEM), Chain: string(chainPEM)}, nil
}

func verifyLeaf(certPEM []byte, identity string, csr *x509.CertificateRequest) (*x509.Certificate, error) {
	certs, err := pki.ParseCertsPEM(certPEM)
	if err != nil {
		return nil, fmt.Errorf("parse issued certificate: %w", err)
	}

	if len(certs) != 1 {
		return nil, fmt.Errorf("issued PEM holds %d certificates, want 1", len(certs))
	}

	leaf := certs[0]

	got, err := pki.CertIdentity(leaf)
	if err != nil {
		return nil, fmt.Errorf("issued certificate identity: %w", err)
	}

	if got != identity {
		return nil, fmt.Errorf("issued certificate identity %q, want %q", got, identity)
	}

	if !samePublicKey(leaf.PublicKey, csr.PublicKey) {
		return nil, errors.New("issued certificate key differs from CSR key")
	}

	return leaf, nil
}

func samePublicKey(a, b any) bool {
	ka, ok := a.(*ecdsa.PublicKey)
	if !ok {
		return false
	}

	kb, ok := b.(*ecdsa.PublicKey)
	if !ok {
		return false
	}

	return ka.Equal(kb)
}
