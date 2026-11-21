package hub

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/zekihan/t3-mesh/internal/pki"
	"github.com/zekihan/t3-mesh/internal/policy"
	"github.com/zekihan/t3-mesh/internal/proto"
)

const (
	renewTimeout = 2 * time.Minute

	// The newest pruneKeep CertificateRequests per identity survive pruning.
	pruneKeep    = 2
	pruneTimeout = 30 * time.Second

	// Maximum length of error detail text sent to agents.
	maxDetailLen = 200
)

var (
	errIssuedIdentity = errors.New("issued certificate identity differs")
	errIssuedKey      = errors.New("issued certificate key differs from CSR key")
)

func (sess *session) handleRenew(req proto.Renew) {
	resp, err := sess.renew(req)
	if err != nil {
		sess.log.Warn(
			"Renewal failed",
			slog.String("error", err.Error()),
		)
		sess.s.warn(sess.machine, "renewal failed: "+err.Error())

		detail := err.Error()

		if _, ok := errors.AsType[*publicError](err); !ok {
			detail = "issuance failed"
		}

		//nolint:errcheck // best-effort notice; the peer may already be gone
		_ = sess.ctrl.Send(
			proto.Reject{Reason: proto.RejectRenewFailed, Detail: truncate(detail, maxDetailLen)},
		)

		return
	}

	err = sess.ctrl.Send(resp)
	if err != nil {
		sess.log.Warn(
			"Renewal reply failed",
			slog.String("error", err.Error()),
		)
	}
}

// publicError marks errors whose text is safe to show to the agent.
type publicError struct{ msg string }

func (e *publicError) Error() string { return e.msg }

func pubErr(format string, args ...any) error {
	return &publicError{msg: fmt.Sprintf(format, args...)}
}

// validateRenewRequest checks the CSR against the session and policy and
// returns the CSR's public key and identity.
func (sess *session) validateRenewRequest(req proto.Renew) (*ecdsa.PublicKey, string, error) {
	csr, identity, err := pki.ValidateCSR([]byte(req.CSR))
	if err != nil {
		return nil, "", pubErr("invalid CSR: %v", err)
	}

	if identity != sess.identity {
		return nil, "", pubErr(
			"CSR identity %q does not match the session identity",
			identity,
		)
	}

	csrKey, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, "", pubErr("CSR key is not ECDSA")
	}

	if cur, ok := sess.leaf.PublicKey.(*ecdsa.PublicKey); ok && cur.Equal(csrKey) {
		return nil, "", pubErr("CSR key must differ from the current key")
	}

	snap := sess.s.cfg.Current()
	if m, ok := snap.MachineForIdentity(identity); !ok || m != sess.machine {
		return nil, "", pubErr("identity is not configured")
	}

	err = policy.Revoked(snap.Revocations, identity, sess.fingerprint)
	if err != nil {
		return nil, "", pubErr("%v", err)
	}

	return csrKey, identity, nil
}

// verifyIssuedLeaf checks that the issuer returned a single certificate for the
// requested identity and key.
func verifyIssuedLeaf(
	certPEM []byte,
	identity string,
	csrKey *ecdsa.PublicKey,
) (*x509.Certificate, error) {
	certs, err := pki.ParseCertsPEM(certPEM)
	if err != nil || len(certs) != 1 {
		return nil, fmt.Errorf("issued certificate is unusable: %w", err)
	}

	leaf := certs[0]

	got, err := pki.CertIdentity(leaf)
	if err != nil || got != identity {
		return nil, fmt.Errorf("%w: got %q, want %q", errIssuedIdentity, got, identity)
	}

	if k, ok := leaf.PublicKey.(*ecdsa.PublicKey); !ok || !k.Equal(csrKey) {
		return nil, errIssuedKey
	}

	return leaf, nil
}

func (sess *session) renew(req proto.Renew) (proto.Renewed, error) {
	csrKey, identity, err := sess.validateRenewRequest(req)
	if err != nil {
		return proto.Renewed{}, err
	}

	ctx, cancel := context.WithTimeout(sess.ctx, renewTimeout)
	defer cancel()

	unlock, _ := sess.s.issuance.begin(identity)
	if unlock == nil {
		return proto.Renewed{}, pubErr("issuance in progress")
	}
	defer unlock()

	current, _, err := sess.s.checkNewest(ctx, identity, sess.fingerprint)
	if err != nil {
		return proto.Renewed{}, err
	}

	if !current {
		return proto.Renewed{}, pubErr("leaf is not the newest issued")
	}

	certPEM, chainPEM, err := sess.s.issuer.Issue(ctx, identity, []byte(req.CSR))
	if err != nil {
		return proto.Renewed{}, fmt.Errorf("issue: %w", err)
	}

	leaf, err := verifyIssuedLeaf(certPEM, identity, csrKey)
	if err != nil {
		return proto.Renewed{}, err
	}

	fp := pki.Fingerprint(leaf)
	sess.s.setNewest(identity, fp)
	sess.s.pruneAsync(identity)

	sess.s.mu.Lock()
	if m := sess.s.machines[sess.machine]; m != nil && leaf.NotAfter.After(m.certNotAfter) {
		m.certNotAfter = leaf.NotAfter
	}
	sess.s.mu.Unlock()

	sess.log.Info(
		"Certificate issued",
		slog.Any("identity", identity),
		slog.Any("fingerprint", fp),
		slog.String("via", "renewal"),
		slog.String("notAfter", leaf.NotAfter.UTC().Format(time.RFC3339)),
	)
	sess.log.Info(
		"Renewal",
		slog.Any("newFingerprint", fp),
		slog.Any("oldFingerprint", sess.fingerprint),
	)

	return proto.Renewed{Certificate: string(certPEM), Chain: string(chainPEM)}, nil
}

// pruneAsync deletes older CertificateRequests for identity in the background.
// Failures are logged and never affect issuance.
func (server *Server) pruneAsync(identity string) {
	server.wg.Go(func() {
		ctx, cancel := context.WithTimeout(context.Background(), pruneTimeout)
		defer cancel()

		err := server.issuer.Prune(ctx, identity, pruneKeep)
		if err != nil {
			server.log.Warn(
				"Prune certificate requests failed",
				slog.Any("identity", identity),
				slog.Any("error", err),
			)
		}
	})
}
