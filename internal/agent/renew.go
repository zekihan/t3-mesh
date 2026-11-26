package agent

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/zekihan/t3-mesh/internal/pki"
	"github.com/zekihan/t3-mesh/internal/proto"
)

const renewReplyTimeout = 2 * time.Minute

// renewLoop renews the certificate when less than renewWindow remains. It checks
// hourly and whenever a session is adopted; a failed attempt waits renewRetry.
func (agent *Agent) renewLoop(ctx context.Context) {
	ticker := time.NewTicker(agent.renewEvery)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-agent.renewKick:
		}

		agent.renewOnce(ctx)
	}
}

func (agent *Agent) renewOnce(ctx context.Context) {
	if !agent.renewing.CompareAndSwap(false, true) {
		return
	}

	defer agent.renewing.Store(false)

	agent.mu.Lock()
	leaf := agent.ident.Leaf
	notBefore := agent.renewAfter
	agent.mu.Unlock()

	now := agent.now()
	forced := agent.renewRequested()

	if leaf == nil {
		return
	}

	if !forced && (leaf.NotAfter.Sub(now) >= agent.renewWindow || now.Before(notBefore)) {
		return
	}

	if agent.upd != nil && agent.upd.ReleaseUnconfirmed() {
		agent.log.InfoContext(
			ctx,
			"Renewal deferred",
			slog.String("reason", "release awaiting promotion or rollback"),
		)

		return
	}

	cur := agent.current()
	if cur == nil {
		return
	}

	agent.log.InfoContext(
		ctx,
		"Renewal starting",
		slog.String("notAfter", leaf.NotAfter.Format(time.RFC3339)),
		slog.Bool("forced", forced),
	)

	err := agent.renew(ctx, cur)
	if err == nil && forced {
		agent.clearRenewRequest(ctx)
	}

	if err != nil {
		agent.log.WarnContext(ctx, "Renewal failed", slog.Any("err", err))
		agent.warn("certificate renewal failed")

		agent.mu.Lock()
		agent.renewAfter = agent.now().Add(agent.renewRetry)
		agent.mu.Unlock()
	}
}

// RenewNowFile in the state directory asks for a renewal regardless of the
// renewal window. The agent checks for it hourly and on every new session, and
// deletes it after a successful renewal.
const RenewNowFile = "renew-now"

func (agent *Agent) renewRequested() bool {
	if agent.cfg.StateDir == "" {
		return false
	}

	_, err := os.Stat(filepath.Join(agent.cfg.StateDir, RenewNowFile))

	return err == nil
}

func (agent *Agent) clearRenewRequest(ctx context.Context) {
	err := os.Remove(filepath.Join(agent.cfg.StateDir, RenewNowFile))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		agent.log.WarnContext(ctx, "Clear renewal request", slog.Any("err", err))
	}
}

// renew gets a new certificate over cur's control stream, proves it with a new
// tunnel session, then promotes it. The old key and certificate stay until the
// new session's HelloAck arrived.
func (agent *Agent) renew(ctx context.Context, cur *session) error {
	key, err := pki.GenerateKey()
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}

	csr, err := pki.CreateCSR(key, agent.cfg.Identity.Name)
	if err != nil {
		return fmt.Errorf("create csr: %w", err)
	}

	select {
	case <-cur.renewCh:
	default:
	}

	err = cur.ctrl.Send(proto.Renew{CSR: string(csr)})
	if err != nil {
		return fmt.Errorf("send renew: %w", err)
	}

	timer := time.NewTimer(renewReplyTimeout)
	defer timer.Stop()

	var renewed proto.Renewed

	select {
	case msg := <-cur.renewCh:
		switch m := msg.(type) {
		case proto.Renewed:
			renewed = m
		case proto.Reject:
			return fmt.Errorf("%w (%s): %s", errRenewRefused, m.Reason, m.Detail)
		}
	case <-cur.done:
		return errRenewSessionDone
	case <-timer.C:
		return errNoRenewReply
	case <-ctx.Done():
		return fmt.Errorf("renewal: %w", ctx.Err())
	}

	err = agent.store.SaveNext(key, []byte(renewed.Certificate), []byte(renewed.Chain))
	if err != nil {
		agent.discardNext()

		return fmt.Errorf("save next identity: %w", err)
	}

	next, _, err := agent.store.LoadNext()
	if err != nil {
		agent.discardNext()

		return fmt.Errorf("load next identity: %w", err)
	}

	return agent.switchIdentity(ctx, &next)
}

func (agent *Agent) switchIdentity(ctx context.Context, next *tls.Certificate) error {
	agent.dialMu.Lock()
	defer agent.dialMu.Unlock()

	sess, err := agent.connect(ctx, next)
	if err != nil {
		agent.handleConnectErr(err)

		// Keep next-* on disk: the hub already treats the new leaf as the
		// newest, so later connects (connectNewest) must try it first.
		return fmt.Errorf("tunnel with new certificate: %w", err)
	}

	agent.promote(next)

	old := agent.adopt(sess)

	agent.log.InfoContext(
		ctx,
		"Renewal complete",
		slog.String("fingerprint", pki.Fingerprint(next.Leaf)),
		slog.String("notAfter", next.Leaf.NotAfter.Format(time.RFC3339)),
	)

	if old != nil {
		agent.wg.Go(func() { agent.retire(old) })
	}

	return nil
}

// promote makes next the current identity on disk and in memory.
func (agent *Agent) promote(next *tls.Certificate) {
	err := agent.store.PromoteNext()
	if err != nil {
		// Keep using it in memory; next-* stays on disk and connectNewest
		// retries the promotion on the next connect.
		agent.log.Error("Promote next identity failed", slog.Any("err", err))
	}

	agent.mu.Lock()
	agent.ident = *next
	agent.mu.Unlock()
}

func (agent *Agent) discardNext() {
	err := agent.store.DiscardNext()
	if err != nil {
		agent.log.Warn("Discard next identity failed", slog.Any("err", err))
	}
}
