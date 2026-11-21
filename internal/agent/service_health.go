package agent

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/http"
	"net/url"
	"slices"
	"sync"
	"time"

	"github.com/zekihan/t3-mesh/internal/proto"
)

const (
	serviceInterval = 30 * time.Second
	serviceTimeout  = 2 * time.Second
)

var serviceHTTP = http.Transport{DisableKeepAlives: true}

// ProbeService checks the configured local target without following HTTP redirects.
func ProbeService(ctx context.Context, name, target string) error {
	if name != "t3" {
		return probeTCP(ctx, target, serviceTimeout)
	}

	address := url.URL{Scheme: "http", Host: target, Path: "/"}

	httpCtx, cancel := context.WithTimeout(ctx, serviceTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(httpCtx, http.MethodGet, address.String(), http.NoBody)
	if err != nil {
		return fmt.Errorf("build service probe: %w", err)
	}

	resp, err := serviceHTTP.RoundTrip(req)
	if err == nil {
		_ = resp.Body.Close()

		return nil
	}

	tcpErr := probeTCP(ctx, target, serviceTimeout)
	if tcpErr != nil {
		return errors.Join(err, tcpErr)
	}

	return fmt.Errorf("TCP accepts but HTTP failed: %w", err)
}

func probeTCP(ctx context.Context, target string, timeout time.Duration) error {
	dialer := net.Dialer{Timeout: timeout}

	conn, err := dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		return fmt.Errorf("service TCP probe: %w", err)
	}

	_ = conn.Close()

	return nil
}

func (agent *Agent) serviceLoop(ctx context.Context) {
	ticker := time.NewTicker(serviceInterval)
	defer ticker.Stop()

	names := slices.Sorted(maps.Keys(agent.cfg.Serve))
	for {
		agent.checkServices(ctx, names)

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (agent *Agent) checkServices(ctx context.Context, names []string) {
	results := make([]proto.ServiceHealth, len(names))

	var probes sync.WaitGroup

	for idx, name := range names {
		probes.Go(func() {
			status := proto.ServiceReachable
			if ProbeService(ctx, name, agent.cfg.Serve[name]) != nil {
				status = proto.ServiceUnreachable
			}

			results[idx] = proto.ServiceHealth{
				Name: name, State: status, CheckedAt: agent.now().UTC().Format(time.RFC3339),
			}
		})
	}

	probes.Wait()

	agent.mu.Lock()
	changed := !slices.EqualFunc(agent.services, results, func(a, b proto.ServiceHealth) bool {
		return a.Name == b.Name && a.State == b.State
	})
	agent.services = results
	agent.mu.Unlock()

	if changed {
		signal(agent.statusNudge)
	}
}
