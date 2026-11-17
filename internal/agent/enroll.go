package agent

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/zekihan/t3-mesh/internal/agent/agentconfig"
	"github.com/zekihan/t3-mesh/internal/pki"
	"github.com/zekihan/t3-mesh/internal/proto"
)

const enrollTimeout = 30 * time.Second

// Enroll obtains a first certificate from the hub with a single-use token.
//
// It always generates a fresh key. With no existing identity the key is saved
// first (SaveKey) and the certificate afterwards. When an identity already
// exists (re-enrollment after expiry), the new pair is staged with SaveNext and
// promoted only after the hub answered, so a failed enrollment never leaves the
// old certificate without its key.
//
// hubTLS overrides trust for tests; production passes nil and the hub is
// verified with system roots and the exact host name.
func Enroll(ctx context.Context, cfg *agentconfig.Config, token string, hubTLS *tls.Config) error {
	if token == "" {
		return errors.New("enroll: token is required")
	}

	store := pki.Store{Dir: cfg.Identity.Dir}

	key, err := pki.GenerateKey()
	if err != nil {
		return fmt.Errorf("enroll: generate key: %w", err)
	}

	csr, err := pki.CreateCSR(key, cfg.Identity.Name)
	if err != nil {
		return fmt.Errorf("enroll: %w", err)
	}

	existing := store.Exists()
	if !existing {
		if err = store.SaveKey(key); err != nil {
			return fmt.Errorf("enroll: save key: %w", err)
		}
	}

	reply, err := enrollExchange(ctx, cfg, hubTLS, proto.Enroll{Token: token, CSR: string(csr)})
	if err != nil {
		return err
	}

	if err = checkEnrolledIdentity(reply, cfg.Identity.Name); err != nil {
		return err
	}

	return saveEnrolled(store, key, reply, existing)
}

func saveEnrolled(store pki.Store, key *ecdsa.PrivateKey, reply proto.Enrolled, existing bool) error {
	if existing {
		if err := store.SaveNext(key, []byte(reply.Certificate), []byte(reply.Chain)); err != nil {
			return fmt.Errorf("enroll: save certificate: %w", err)
		}

		if err := store.PromoteNext(); err != nil {
			return fmt.Errorf("enroll: promote certificate: %w", err)
		}

		return nil
	}

	if err := store.SaveCert([]byte(reply.Certificate), []byte(reply.Chain)); err != nil {
		return fmt.Errorf("enroll: save certificate: %w", err)
	}

	return nil
}

func checkEnrolledIdentity(reply proto.Enrolled, name string) error {
	certs, err := pki.ParseCertsPEM([]byte(reply.Certificate))
	if err != nil {
		return fmt.Errorf("enroll: hub certificate: %w", err)
	}

	got, err := pki.CertIdentity(certs[0])
	if err != nil {
		return fmt.Errorf("enroll: hub certificate: %w", err)
	}

	if got != name {
		return fmt.Errorf("enroll: hub issued identity %q, want %q", got, name)
	}

	return nil
}

func enrollExchange(ctx context.Context, cfg *agentconfig.Config, hubTLS *tls.Config, req proto.Enroll) (proto.Enrolled, error) {
	ctx, cancel := context.WithTimeout(ctx, enrollTimeout)
	defer cancel()

	tlsCfg := &tls.Config{}
	if hubTLS != nil {
		tlsCfg = hubTLS.Clone()
	}

	tlsCfg.MinVersion = tls.VersionTLS13
	tlsCfg.NextProtos = []string{proto.ALPNEnroll}
	tlsCfg.Certificates = nil

	if tlsCfg.ServerName == "" {
		tlsCfg.ServerName = cfg.HubHost()
	}

	d := net.Dialer{}

	raw, err := d.DialContext(ctx, "tcp", cfg.HubAddr())
	if err != nil {
		return proto.Enrolled{}, fmt.Errorf("enroll: dial hub: %w", err)
	}

	defer func() { _ = raw.Close() }()

	if dl, ok := ctx.Deadline(); ok {
		_ = raw.SetDeadline(dl)
	}

	stop := context.AfterFunc(ctx, func() { _ = raw.Close() })
	defer stop()

	conn := tls.Client(raw, tlsCfg)
	if err = conn.HandshakeContext(ctx); err != nil {
		return proto.Enrolled{}, fmt.Errorf("enroll: tls handshake: %w", err)
	}

	if err = proto.WriteMessage(conn, req); err != nil {
		return proto.Enrolled{}, fmt.Errorf("enroll: send request: %w", err)
	}

	msg, err := proto.ReadMessage(conn, proto.MaxMessageSize)
	if err != nil {
		return proto.Enrolled{}, fmt.Errorf("enroll: read reply: %w", err)
	}

	switch m := msg.(type) {
	case proto.Enrolled:
		return m, nil
	case proto.Reject:
		return proto.Enrolled{}, fmt.Errorf("enroll: hub rejected (%s): %s", m.Reason, m.Detail)
	default:
		return proto.Enrolled{}, fmt.Errorf("enroll: unexpected %s reply", msg.MessageType())
	}
}
