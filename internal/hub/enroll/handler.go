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

var (
	errUnexpectedMessage   = errors.New("unexpected message")
	errTokenBoundElsewhere = errors.New("token bound to a different identity")
	errCertCount           = errors.New("issued PEM holds the wrong number of certificates")
	errIdentityMismatch    = errors.New("issued certificate identity differs")
	errKeyMismatch         = errors.New("issued certificate key differs from CSR key")
)

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

// rejectedError carries a short, non-sensitive detail for the client.
type rejectedError struct {
	cause  error
	detail string
}

func (e *rejectedError) Error() string {
	if e.cause != nil {
		return e.detail + ": " + e.cause.Error()
	}

	return e.detail
}

func (e *rejectedError) Unwrap() error { return e.cause }

func reject(
	detail string,
	cause error,
) error {
	return &rejectedError{detail: detail, cause: cause}
}

// Serve runs one enrollment exchange on conn and closes it.
//
// Token redemption order: the request is read and the CSR validated first, so
// a garbage request cannot burn a stolen or valid token. Once the CSR is
// valid, the token is redeemed (consumed) before the identity, policy and
// issuance checks, so a valid token presented with a mismatched identity or
// for a disabled identity is burned.
func (handler *Handler) Serve(ctx context.Context, conn net.Conn, source netip.Addr) {
	defer func() { _ = conn.Close() }()

	log := handler.Log
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}

	log = log.With(slog.String("source", source.String()))

	//nolint:errcheck // best-effort deadline; a dead connection fails the next read or write
	_ = conn.SetDeadline(
		time.Now().Add(exchangeTimeout),
	)

	if handler.Limiter != nil && !handler.Limiter.Allow(source) {
		log.WarnContext(
			ctx,
			"Enrollment rate limited",
		)
		handler.writeReject(conn, "too many attempts")

		return
	}

	ctx, cancel := context.WithTimeout(ctx, exchangeTimeout)
	defer cancel()

	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	identity, fp, resp, err := handler.exchange(ctx, conn)
	if identity != "" {
		log = log.With(slog.Any("identity", identity))
	}

	if err != nil {
		log.WarnContext(
			ctx,
			"Enrollment failed",
			slog.Any("error", err),
		)

		detail := "enrollment failed"

		if rj, ok := errors.AsType[*rejectedError](err); ok {
			detail = rj.detail
		}

		handler.writeReject(conn, detail)

		return
	}

	err = proto.WriteMessage(conn, resp)
	if err != nil {
		log.WarnContext(
			ctx,
			"Enrollment reply failed",
			slog.Any("error", err),
			slog.Any("fingerprint", fp),
		)

		return
	}

	log.InfoContext(
		ctx,
		"Enrollment succeeded",
		slog.Any("fingerprint", fp),
	)
}

func (handler *Handler) writeReject(conn net.Conn, detail string) {
	//nolint:errcheck // best-effort notice; the peer may already be gone
	_ = proto.WriteMessage(
		conn,
		proto.Reject{Reason: proto.RejectEnrollFailed, Detail: detail},
	)
}

func (handler *Handler) exchange(
	ctx context.Context,
	conn net.Conn,
) (string, string, proto.Enrolled, error) {
	msg, err := proto.ReadMessage(conn, proto.MaxEnrollSize)
	if err != nil {
		return "", "", proto.Enrolled{}, reject("bad request", err)
	}

	req, ok := msg.(proto.Enroll)
	if !ok {
		return "", "", proto.Enrolled{}, reject(
			"unexpected message",
			fmt.Errorf("%w: got %s", errUnexpectedMessage, msg.MessageType()),
		)
	}

	csr, csrIdentity, err := pki.ValidateCSR([]byte(req.CSR))
	if err != nil {
		return "", "", proto.Enrolled{}, reject("invalid CSR", err)
	}

	tokenIdentity, err := handler.Tokens.Redeem(req.Token)
	if err != nil {
		return csrIdentity, "", proto.Enrolled{}, reject("invalid token", err)
	}

	if tokenIdentity != csrIdentity {
		return csrIdentity, "", proto.Enrolled{}, reject(
			"identity mismatch",
			fmt.Errorf("%w: %q", errTokenBoundElsewhere, tokenIdentity),
		)
	}

	identity := csrIdentity

	if handler.Allowed != nil {
		err = handler.Allowed(identity)
		if err != nil {
			return identity, "", proto.Enrolled{}, reject("identity not allowed", err)
		}
	}

	certPEM, chainPEM, err := handler.Issuer.Issue(ctx, identity, []byte(req.CSR))
	if err != nil {
		return identity, "", proto.Enrolled{}, reject("issuance failed", err)
	}

	leaf, err := verifyLeaf(certPEM, identity, csr)
	if err != nil {
		return identity, "", proto.Enrolled{}, reject("issuance failed", err)
	}

	fp := pki.Fingerprint(leaf)

	if handler.OnIssued != nil {
		handler.OnIssued(identity, fp)
	}

	return identity, fp, proto.Enrolled{Certificate: string(certPEM), Chain: string(chainPEM)}, nil
}

func verifyLeaf(
	certPEM []byte,
	identity string,
	csr *x509.CertificateRequest,
) (*x509.Certificate, error) {
	certs, err := pki.ParseCertsPEM(certPEM)
	if err != nil {
		return nil, fmt.Errorf("parse issued certificate: %w", err)
	}

	if len(certs) != 1 {
		return nil, fmt.Errorf("%w: got %d, want 1", errCertCount, len(certs))
	}

	leaf := certs[0]

	got, err := pki.CertIdentity(leaf)
	if err != nil {
		return nil, fmt.Errorf("issued certificate identity: %w", err)
	}

	if got != identity {
		return nil, fmt.Errorf("%w: got %q, want %q", errIdentityMismatch, got, identity)
	}

	if !samePublicKey(leaf.PublicKey, csr.PublicKey) {
		return nil, errKeyMismatch
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
