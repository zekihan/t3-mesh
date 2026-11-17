package agent

import (
	"context"
	"log/slog"
	"time"

	"github.com/zekihan/t3-mesh/internal/proto"
)

func (agent *Agent) statusLoop(ctx context.Context) {
	ticker := time.NewTicker(agent.statusEvery)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-agent.statusNudge:
		}

		agent.sendStatus()
	}
}

func (agent *Agent) sendStatus() {
	s := agent.current()
	if s == nil {
		return
	}

	err := s.ctrl.Send(agent.buildStatus())
	if err != nil {
		agent.log.Debug("Status send failed", slog.Any("err", err))
	}
}

func (agent *Agent) buildStatus() proto.Status {
	agent.mu.Lock()
	st := proto.Status{
		Version:             agent.version,
		Warnings:            append([]string(nil), agent.warnings...),
		ReleaseRevision:     agent.cache.Release.Revision,
		RulesRevision:       agent.cache.Rules.Revision,
		RevocationRevision:  agent.cache.Revocations.Revision,
		TrustBundleRevision: agent.cache.TrustBundle.Revision,
	}

	if agent.ident.Leaf != nil {
		st.CertNotAfter = agent.ident.Leaf.NotAfter.UTC().Format(time.RFC3339)
	}
	agent.mu.Unlock()

	if agent.direct != nil {
		st.DirectSessions = agent.direct.Sessions()
	}

	if agent.upd != nil {
		st.FailedUpdates = agent.upd.FailedUpdates()

		if rev := agent.upd.LastAppliedRelease(); rev != "" {
			st.ReleaseRevision = rev
		}
	}

	return st
}
