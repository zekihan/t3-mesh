package hub

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"time"

	"github.com/zekihan/t3-mesh/internal/pki"
	"github.com/zekihan/t3-mesh/internal/policy"
	"github.com/zekihan/t3-mesh/internal/proto"
)

const renewTimeout = 2 * time.Minute

func (c *session) handleRenew(req proto.Renew) {
	resp, err := c.renew(req)
	if err != nil {
		c.log.Warn("renewal failed", "error", err.Error())
		c.s.warn(c.machine, "renewal failed: "+err.Error())

		detail := err.Error()

		var pub *publicError
		if !errors.As(err, &pub) {
			detail = "issuance failed"
		}

		_ = c.ctrl.Send(proto.Reject{Reason: proto.RejectRenewFailed, Detail: truncate(detail, 200)})

		return
	}

	if err := c.ctrl.Send(resp); err != nil {
		c.log.Warn("renewal reply failed", "error", err.Error())
	}
}

// publicError marks errors whose text is safe to show to the agent.
type publicError struct{ msg string }

func (e *publicError) Error() string { return e.msg }

func pubErr(format string, args ...any) error {
	return &publicError{msg: fmt.Sprintf(format, args...)}
}

func (c *session) renew(req proto.Renew) (proto.Renewed, error) {
	csr, identity, err := pki.ValidateCSR([]byte(req.CSR))
	if err != nil {
		return proto.Renewed{}, pubErr("invalid CSR: %v", err)
	}

	if identity != c.identity {
		return proto.Renewed{}, pubErr("CSR identity %q does not match the session identity", identity)
	}

	csrKey, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return proto.Renewed{}, pubErr("CSR key is not ECDSA")
	}

	if cur, ok := c.leaf.PublicKey.(*ecdsa.PublicKey); ok && cur.Equal(csrKey) {
		return proto.Renewed{}, pubErr("CSR key must differ from the current key")
	}

	snap := c.s.cfg.Current()
	if m, ok := snap.MachineForIdentity(identity); !ok || m != c.machine {
		return proto.Renewed{}, pubErr("identity is not configured")
	}

	if err := policy.Revoked(snap.Revocations, identity, c.fingerprint); err != nil {
		return proto.Renewed{}, pubErr("%v", err)
	}

	ctx, cancel := context.WithTimeout(c.ctx, renewTimeout)
	defer cancel()

	certPEM, chainPEM, err := c.s.issuer.Issue(ctx, identity, []byte(req.CSR))
	if err != nil {
		return proto.Renewed{}, fmt.Errorf("issue: %w", err)
	}

	certs, err := pki.ParseCertsPEM(certPEM)
	if err != nil || len(certs) != 1 {
		return proto.Renewed{}, fmt.Errorf("issued certificate is unusable: %v", err)
	}

	leaf := certs[0]

	if got, err := pki.CertIdentity(leaf); err != nil || got != identity {
		return proto.Renewed{}, fmt.Errorf("issued certificate identity %q, want %q", got, identity)
	}

	if k, ok := leaf.PublicKey.(*ecdsa.PublicKey); !ok || !k.Equal(csrKey) {
		return proto.Renewed{}, errors.New("issued certificate key differs from CSR key")
	}

	fp := pki.Fingerprint(leaf)
	c.s.setNewest(identity, fp)

	c.s.mu.Lock()
	if m := c.s.machines[c.machine]; m != nil && leaf.NotAfter.After(m.certNotAfter) {
		m.certNotAfter = leaf.NotAfter
	}
	c.s.mu.Unlock()

	c.log.Info("certificate issued", "identity", identity, "fingerprint", fp, "via", "renewal", "notAfter", leaf.NotAfter.UTC().Format(time.RFC3339))
	c.log.Info("renewal", "newFingerprint", fp, "oldFingerprint", c.fingerprint)

	return proto.Renewed{Certificate: string(certPEM), Chain: string(chainPEM)}, nil
}
