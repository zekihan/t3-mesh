package agent

import (
	"context"
	"fmt"
	"log/slog"
	"maps"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/zekihan/t3-mesh/internal/policy"
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

	var owned []netip.AddrPort
	if agent.direct != nil {
		owned = agent.direct.Listening()

		port, deviceAddrs := agent.direct.DeviceListener()
		for _, raw := range deviceAddrs {
			addr, parseErr := netip.ParseAddr(raw)
			if parseErr == nil && port > 0 && port <= 65535 {
				owned = append(owned, netip.AddrPortFrom(addr.Unmap(), uint16(port)))
			}
		}
	}

	var (
		machine string
		kinds   map[string]string
	)

	agent.mu.Lock()

	if agent.cache != nil {
		machine = agent.cache.Machine
		kinds = maps.Clone(agent.cache.Rules.ServiceKinds)
	}
	agent.mu.Unlock()

	warnings := exposureWarnings(ctx, agent.cfg.Serve, machine, kinds, addrs, owned)
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
	machine string,
	kinds map[string]string,
	addrs []netip.Addr,
	owned []netip.AddrPort,
) []string {
	var warnings []string

	for _, name := range slices.Sorted(maps.Keys(services)) {
		if kinds[policy.Target(name, machine)] == proto.KindTCP {
			continue
		}

		host, port, err := net.SplitHostPort(services[name])
		if err != nil {
			continue
		}

		addr, err := netip.ParseAddr(host)
		if !strings.EqualFold(host, "localhost") && (err != nil || !addr.Unmap().IsLoopback()) {
			continue
		}

		portNum, err := strconv.ParseUint(port, 10, 16)
		if err != nil {
			continue
		}

		for _, ip := range addrs {
			ip = ip.Unmap()

			if !ip.IsGlobalUnicast() || ip.IsLoopback() ||
				slices.Contains(owned, netip.AddrPortFrom(ip, uint16(portNum))) {
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
