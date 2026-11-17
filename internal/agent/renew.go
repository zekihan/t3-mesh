package agent

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"time"

	"github.com/zekihan/t3-mesh/internal/pki"
	"github.com/zekihan/t3-mesh/internal/proto"
)

const renewReplyTimeout = 2 * time.Minute

// renewLoop renews the certificate when less than renewWindow remains. It checks
// hourly and whenever a session is adopted; a failed attempt waits renewRetry.
func (a *Agent) renewLoop(ctx context.Context) {
	t := time.NewTicker(a.renewEvery)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-a.renewKick:
		}

		a.renewOnce(ctx)
	}
}

func (a *Agent) renewOnce(ctx context.Context) {
	if !a.renewing.CompareAndSwap(false, true) {
		return
	}

	defer a.renewing.Store(false)

	a.mu.Lock()
	leaf := a.ident.Leaf
	notBefore := a.renewAfter
	a.mu.Unlock()

	now := a.now()

	if leaf == nil || leaf.NotAfter.Sub(now) >= a.renewWindow || now.Before(notBefore) {
		return
	}

	if a.upd != nil && a.upd.OnProbation() {
		a.log.Info("renewal deferred", "reason", "release on probation")

		return
	}

	cur := a.current()
	if cur == nil {
		return
	}

	a.log.Info("renewal starting", "not_after", leaf.NotAfter.Format(time.RFC3339))

	if err := a.renew(ctx, cur); err != nil {
		a.log.Warn("renewal failed", "err", err)
		a.warn("certificate renewal failed")

		a.mu.Lock()
		a.renewAfter = a.now().Add(a.renewRetry)
		a.mu.Unlock()
	}
}

// renew gets a new certificate over cur's control stream, proves it with a new
// tunnel session, then promotes it. The old key and certificate stay until the
// new session's HelloAck arrived.
func (a *Agent) renew(ctx context.Context, cur *session) error {
	key, err := pki.GenerateKey()
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}

	csr, err := pki.CreateCSR(key, a.cfg.Identity.Name)
	if err != nil {
		return fmt.Errorf("create csr: %w", err)
	}

	select {
	case <-cur.renewCh:
	default:
	}

	if err = cur.ctrl.Send(proto.Renew{CSR: string(csr)}); err != nil {
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
			return fmt.Errorf("hub refused renewal (%s): %s", m.Reason, m.Detail)
		}
	case <-cur.done:
		return errors.New("session closed during renewal")
	case <-timer.C:
		return errors.New("no renewal reply from hub")
	case <-ctx.Done():
		return fmt.Errorf("renewal: %w", ctx.Err())
	}

	if err = a.store.SaveNext(key, []byte(renewed.Certificate), []byte(renewed.Chain)); err != nil {
		a.discardNext()

		return fmt.Errorf("save next identity: %w", err)
	}

	next, _, err := a.store.LoadNext()
	if err != nil {
		a.discardNext()

		return fmt.Errorf("load next identity: %w", err)
	}

	return a.switchIdentity(ctx, next)
}

func (a *Agent) switchIdentity(ctx context.Context, next tls.Certificate) error {
	a.dialMu.Lock()
	defer a.dialMu.Unlock()

	s, err := a.connect(ctx, next)
	if err != nil {
		a.handleConnectErr(err)

		// Keep next-* on disk: the hub already treats the new leaf as the
		// newest, so later connects (connectNewest) must try it first.
		return fmt.Errorf("tunnel with new certificate: %w", err)
	}

	a.promote(next)

	old := a.adopt(s)

	a.log.Info("renewal complete", "fingerprint", pki.Fingerprint(next.Leaf),
		"not_after", next.Leaf.NotAfter.Format(time.RFC3339))

	if old != nil {
		a.wg.Go(func() { a.retire(old) })
	}

	return nil
}

// promote makes next the current identity on disk and in memory.
func (a *Agent) promote(next tls.Certificate) {
	if err := a.store.PromoteNext(); err != nil {
		// Keep using it in memory; next-* stays on disk and connectNewest
		// retries the promotion on the next connect.
		a.log.Error("promote next identity failed", "err", err)
	}

	a.mu.Lock()
	a.ident = next
	a.mu.Unlock()
}

func (a *Agent) discardNext() {
	if err := a.store.DiscardNext(); err != nil {
		a.log.Warn("discard next identity failed", "err", err)
	}
}
