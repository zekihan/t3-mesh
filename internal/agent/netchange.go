package agent

import (
	"context"
	"net/netip"
	"time"

	"github.com/zekihan/t3-mesh/internal/netwatch"
)

// netLoop reacts to network changes, wake from sleep and a 30 s DNS backstop.
func (a *Agent) netLoop(ctx context.Context) {
	events := netwatch.Watch(ctx, a.log)
	tick := time.NewTicker(dnsRecheckInterval)

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

			a.log.Debug("network event", "kind", ev.Kind.String())
			a.pathCheck(ctx, ev.Kind.String())
		case <-tick.C:
			a.pathCheck(ctx, "dns-recheck")
		}
	}
}

// pathCheck decides whether the tunnel must move to a new session. An event
// alone never replaces it: only a vanished local address, a failed ping, or a
// successful non-empty lookup that no longer contains the current peer does. A
// failed or empty lookup never does.
func (a *Agent) pathCheck(ctx context.Context, reason string) {
	a.reconcileDirect()

	cur := a.current()
	if cur == nil {
		signal(a.kick)

		return
	}

	if why := a.pathProblem(ctx, cur); why != "" {
		a.log.Info("tunnel path changed", "trigger", reason, "why", why)

		if a.current() == cur {
			a.replaceSession(ctx, why)
		}
	}
}

func (a *Agent) pathProblem(ctx context.Context, cur *session) string {
	if cur.local.IsValid() && !a.addrPresent(cur.local) {
		return "local address gone"
	}

	pctx, cancel := context.WithTimeout(ctx, pingProbeTimeout)
	_, err := cur.ctrl.PingNow(pctx)

	cancel()

	if err != nil {
		return "ping failed"
	}

	host := a.cfg.HubHost()
	if _, perr := netip.ParseAddr(host); perr == nil {
		return ""
	}

	lctx, lcancel := context.WithTimeout(ctx, lookupTimeout)
	addrs, err := a.lookupHost(lctx, host)

	lcancel()

	if err != nil {
		a.log.Debug("hub lookup failed, keeping session", "err", err)

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
