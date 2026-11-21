package agent

import (
	"context"
	"fmt"
	"log/slog"
	"maps"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/zekihan/t3-mesh/internal/proto"
)

const (
	exposureInterval = 5 * time.Minute
	exposureTimeout  = time.Second
)

func (agent *Agent) exposureLoop(ctx context.Context) {
	ticker := time.NewTicker(exposureInterval)
	defer ticker.Stop()

	for {
		agent.checkExposure(ctx)

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-agent.exposureNudge:
		}
	}
}

func (agent *Agent) checkExposure(ctx context.Context) {
	addrs, err := agent.localAddrs()
	if err != nil {
		agent.log.DebugContext(ctx, "Exposure interface enumeration failed", slog.Any("err", err))

		return
	}

	warnings := exposureWarnings(ctx, agent.cfg.Serve, addrs)
	if ctx.Err() != nil {
		return
	}

	agent.mu.Lock()
	changed := !slices.Equal(agent.exposureWarnings, warnings)
	agent.exposureWarnings = warnings
	agent.mu.Unlock()

	if changed {
		signal(agent.statusNudge)
	}
}

func exposureWarnings(
	ctx context.Context,
	services map[string]string,
	addrs []netip.Addr,
) []string {
	var warnings []string

	for _, name := range slices.Sorted(maps.Keys(services)) {
		host, port, err := net.SplitHostPort(services[name])
		if err != nil {
			continue
		}

		addr, err := netip.ParseAddr(host)
		if !strings.EqualFold(host, "localhost") && (err != nil || !addr.Unmap().IsLoopback()) {
			continue
		}

		for _, ip := range addrs {
			ip = ip.Unmap()

			if !ip.IsGlobalUnicast() || ip.IsLoopback() {
				continue
			}

			target := net.JoinHostPort(ip.String(), port)
			if probeTCP(ctx, target, exposureTimeout) == nil {
				warnings = append(warnings, fmt.Sprintf(
					"%s%s port %s accepts TCP on %s", proto.ExposureWarningPrefix, name, port, ip,
				))

				break
			}
		}
	}

	return warnings
}
