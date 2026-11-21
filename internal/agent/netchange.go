package agent

import (
	"context"
	"log/slog"
	"net/netip"
	"time"

	"github.com/zekihan/t3-mesh/internal/netwatch"
)

// netLoop reacts to network changes, wake from sleep and a 30 s DNS backstop.
func (agent *Agent) netLoop(ctx context.Context) {
	events := agent.netEvents
	if events == nil {
		events = netwatch.Watch(ctx, agent.log)
	}

	tick := time.NewTicker(agent.dnsEvery)

	defer tick.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-events:
			if !ok {
				events = nil

				continue
			}

			signal(agent.exposureNudge)

			agent.log.DebugContext(ctx, "Network event", slog.String("kind", ev.Kind.String()))
			agent.pathCheck(ctx, ev.Kind.String())
		case <-tick.C:
			agent.pathCheck(ctx, "dns-recheck")
		}
	}
}

// pathCheck decides whether the tunnel must move to a new session. An event
// alone never replaces it: only a vanished local address, a failed ping, or a
// successful non-empty lookup that no longer contains the current peer does. A
// failed or empty lookup never does.
func (agent *Agent) pathCheck(ctx context.Context, reason string) {
	agent.reconcileDirect()

	cur := agent.current()
	if cur == nil {
		signal(agent.kick)

		return
	}

	if why := agent.pathProblem(ctx, cur); why != "" {
		agent.log.InfoContext(ctx, "Tunnel path changed", slog.String("trigger", reason),
			slog.String("why", why),
		)

		if agent.current() == cur {
			agent.replaceSession(ctx, why)
		}
	}
}

func (agent *Agent) pathProblem(ctx context.Context, cur *session) string {
	if cur.local.IsValid() && !agent.addrPresent(cur.local) {
		return "local address gone"
	}

	pctx, cancel := context.WithTimeout(ctx, pingProbeTimeout)
	_, err := cur.ctrl.PingNow(pctx)

	cancel()

	if err != nil {
		return "ping failed"
	}

	host := agent.cfg.HubHost()

	_, perr := netip.ParseAddr(host)
	if perr == nil {
		return ""
	}

	lctx, lcancel := context.WithTimeout(ctx, lookupTimeout)
	addrs, err := agent.lookupHost(lctx, host)

	lcancel()

	if err != nil {
		agent.log.DebugContext(ctx, "Hub lookup failed, keeping session", slog.Any("err", err))

		return ""
	}

	if len(addrs) == 0 {
		return ""
	}

	for _, ad := range addrs {
		if ad.Unmap() == cur.peer {
			return ""
		}
	}

	return "hub address changed"
}
