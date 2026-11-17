package agent

import (
	"context"
	"time"

	"github.com/zekihan/t3-mesh/internal/proto"
)

func (a *Agent) statusLoop(ctx context.Context) {
	t := time.NewTicker(a.statusEvery)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-a.statusNudge:
		}

		a.sendStatus()
	}
}

func (a *Agent) sendStatus() {
	s := a.current()
	if s == nil {
		return
	}

	if err := s.ctrl.Send(a.buildStatus()); err != nil {
		a.log.Debug("status send failed", "err", err)
	}
}

func (a *Agent) buildStatus() proto.Status {
	a.mu.Lock()
	st := proto.Status{
		Version:             a.version,
		Warnings:            append([]string(nil), a.warnings...),
		ReleaseRevision:     a.cache.Release.Revision,
		RulesRevision:       a.cache.Rules.Revision,
		RevocationRevision:  a.cache.Revocations.Revision,
		TrustBundleRevision: a.cache.TrustBundle.Revision,
	}

	if a.ident.Leaf != nil {
		st.CertNotAfter = a.ident.Leaf.NotAfter.UTC().Format(time.RFC3339)
	}
	a.mu.Unlock()

	if a.direct != nil {
		st.DirectSessions = a.direct.Sessions()
	}

	if a.upd != nil {
		st.FailedUpdates = a.upd.FailedUpdates()

		if rev := a.upd.LastAppliedRelease(); rev != "" {
			st.ReleaseRevision = rev
		}
	}

	return st
}
