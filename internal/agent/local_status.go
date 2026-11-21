package agent

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"runtime"
	"slices"
	"sync"
	"syscall"
	"time"

	"github.com/zekihan/t3-mesh/internal/proto"
)

const (
	localStatusTimeout = 2 * time.Second
	socketRetry        = 5 * time.Second
	maxLocalStatus     = 1 << 20
	maxStatusClients   = 8
	statusSocketMode   = 0o660
)

var (
	errSocketOccupied = errors.New("status socket path is occupied")
	errStatusRequest  = errors.New("expected a status request")
)

// DefaultStatusSocket returns the installed agent's local socket path.
func DefaultStatusSocket() string {
	if runtime.GOOS == "darwin" {
		return "/var/run/t3-mesh/agent.sock"
	}

	return "/run/t3-mesh/agent.sock"
}

type LocalStatus struct {
	Revisions         CachedRevisions  `json:"cachedRevisions"`
	Links             []LinkStatus     `json:"links"`
	DirectListeners   []netip.AddrPort `json:"directListeners"`
	ConnectedSince    *time.Time       `json:"connectedSince"`
	TunnelPath        string           `json:"tunnelPath"`
	DirectReason      string           `json:"directReason"`
	GatewayMACVerdict string           `json:"gatewayMacVerdict"`
	ProbationVersion  string           `json:"probationVersion"`
	Identity          string           `json:"identity"`
	CacheRemaining    string           `json:"cacheRemaining"`
	Report            proto.Status     `json:"report"`
	TunnelConnected   bool             `json:"tunnelConnected"`
	DirectActive      bool             `json:"directActive"`
}

type CachedRevisions struct {
	Release      string `json:"release"`
	Rules        string `json:"rules"`
	Revocations  string `json:"revocations"`
	TrustBundle  string `json:"trustBundle"`
	DeviceLeaves string `json:"deviceLeaves"`
	Peers        string `json:"peers"`
}

type LinkStatus struct {
	Name    string `json:"name"`
	Address string `json:"address"`
	Port    int    `json:"port"`
	Bound   bool   `json:"bound"`
}

type localRequest struct {
	Op string `json:"op"`
}

type localReply struct {
	Status *LocalStatus `json:"status,omitempty"`
	Error  string       `json:"error,omitempty"`
}

// ReadLocalStatus requests a snapshot from the local agent.
func ReadLocalStatus(ctx context.Context, path string) (*LocalStatus, error) {
	ctx, cancel := context.WithTimeout(ctx, localStatusTimeout)
	defer cancel()

	dialer := net.Dialer{}

	conn, err := dialer.DialContext(ctx, "unix", path)
	if err != nil {
		return nil, fmt.Errorf("dial status socket: %w", err)
	}

	defer conn.Close()

	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	err = proto.WriteLine(conn, localRequest{Op: "status"})
	if err != nil {
		return nil, fmt.Errorf("write status request: %w", err)
	}

	var reply localReply

	err = json.NewDecoder(io.LimitReader(conn, maxLocalStatus)).Decode(&reply)
	if err != nil {
		return nil, fmt.Errorf("read status socket: %w", err)
	}

	if reply.Status == nil {
		return nil, fmt.Errorf("%w: %s", errStatusRequest, reply.Error)
	}

	return reply.Status, nil
}

func listenStatus(ctx context.Context, path string) (net.Listener, error) {
	info, err := os.Lstat(path)
	switch {
	case err == nil:
		err = removeStaleSocket(ctx, path, info)
	case errors.Is(err, os.ErrNotExist):
		err = nil
	}

	if err != nil {
		return nil, fmt.Errorf("prepare status socket: %w", err)
	}

	var listen net.ListenConfig

	ln, err := listen.Listen(ctx, "unix", path)
	if err != nil {
		return nil, fmt.Errorf("listen on status socket: %w", err)
	}

	err = os.Chown(path, -1, os.Getegid())
	if err == nil {
		err = os.Chmod(path, statusSocketMode)
	}

	if err != nil {
		_ = ln.Close()

		return nil, fmt.Errorf("set status socket permissions: %w", err)
	}

	return ln, nil
}

func removeStaleSocket(ctx context.Context, path string, info os.FileInfo) error {
	if info.Mode()&os.ModeSocket == 0 {
		return errSocketOccupied
	}

	dialer := net.Dialer{Timeout: localStatusTimeout}

	conn, err := dialer.DialContext(ctx, "unix", path)
	if err == nil {
		_ = conn.Close()

		return errSocketOccupied
	}

	if !errors.Is(err, syscall.ECONNREFUSED) {
		return fmt.Errorf("check existing socket: %w", err)
	}

	err = os.Remove(path)
	if err != nil {
		return fmt.Errorf("remove stale status socket: %w", err)
	}

	return nil
}

func serveLocalStatus(ctx context.Context, ln net.Listener, snapshot func() *LocalStatus) error {
	defer ln.Close()

	stop := context.AfterFunc(ctx, func() { _ = ln.Close() })
	defer stop()

	var workers sync.WaitGroup
	defer workers.Wait()

	sem := make(chan struct{}, maxStatusClients)

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}

			return fmt.Errorf("accept status socket: %w", err)
		}

		select {
		case sem <- struct{}{}:
			workers.Go(func() {
				defer func() { <-sem }()

				replyLocalStatus(conn, snapshot)
			})
		default:
			_ = conn.Close()
		}
	}
}

func replyLocalStatus(conn net.Conn, snapshot func() *LocalStatus) {
	defer conn.Close()

	err := conn.SetDeadline(time.Now().Add(localStatusTimeout))
	if err != nil {
		return
	}

	var request localRequest

	err = proto.ReadLine(conn, &request)

	reply := localReply{Error: errStatusRequest.Error()}
	if err == nil && request.Op == "status" {
		reply = localReply{Status: snapshot()}
	}

	//nolint:errcheck,errchkjson // a local client can close the connection at any time
	_ = json.NewEncoder(conn).Encode(reply)
}

func (agent *Agent) localStatusLoop(ctx context.Context, links []*linkServer) {
	logged := false

	for {
		ln, err := listenStatus(ctx, agent.statusSocket)
		if err == nil {
			logged = false

			err = serveLocalStatus(ctx, ln, func() *LocalStatus {
				return agent.localStatus(links)
			})
		}

		if ctx.Err() != nil {
			return
		}

		if !logged {
			agent.log.WarnContext(ctx, "Local status socket unavailable",
				slog.String("path", agent.statusSocket),
				slog.Any("err", err),
			)

			logged = true
		}

		timer := time.NewTimer(socketRetry)

		select {
		case <-ctx.Done():
			timer.Stop()

			return
		case <-timer.C:
		}
	}
}

func (agent *Agent) localStatus(links []*linkServer) *LocalStatus {
	out := &LocalStatus{
		Report:            agent.buildStatus(),
		Links:             make([]LinkStatus, 0, len(links)),
		Identity:          agent.cfg.Identity.Name,
		DirectReason:      "disabled in config",
		GatewayMACVerdict: "direct disabled",
	}

	agent.fillLocalCacheStatus(out)

	if agent.direct != nil {
		out.DirectActive, out.DirectReason, out.GatewayMACVerdict = agent.direct.DiagnosticGate()
		out.DirectListeners = agent.direct.Listening()
		slices.SortFunc(out.DirectListeners, netip.AddrPort.Compare)
	}

	for _, link := range links {
		out.Links = append(out.Links, LinkStatus{
			Name:    link.key,
			Address: link.ln.Addr().String(),
			Port:    link.port,
			Bound:   link.bound.Load(),
		})
	}

	slices.SortFunc(out.Links, func(a, b LinkStatus) int {
		return cmp.Compare(a.Name, b.Name)
	})

	if agent.upd != nil && agent.upd.OnProbation() {
		out.ProbationVersion = agent.version
	}

	return out
}

func (agent *Agent) fillLocalCacheStatus(out *LocalStatus) {
	agent.mu.Lock()
	defer agent.mu.Unlock()

	cache := agent.cache
	out.Revisions = CachedRevisions{
		Release: cache.Release.Revision, Rules: cache.Rules.Revision,
		Revocations: cache.Revocations.Revision, TrustBundle: cache.TrustBundle.Revision,
		DeviceLeaves: cache.DeviceLeaves.Revision, Peers: cache.Peers.Revision,
	}

	var remaining time.Duration

	if now := agent.now(); cache.WithinWindow(now, agent.cfg.Direct.CacheTTL) {
		remaining = agent.cfg.Direct.CacheTTL - max(0, now.Sub(cache.LastHubContact))
	}

	out.CacheRemaining = remaining.Truncate(time.Second).String()

	if agent.cur != nil {
		since := agent.lastHelloAck.UTC()
		out.ConnectedSince = &since
		out.TunnelConnected = true
		out.TunnelPath = "WAN"

		if cache.Home {
			out.TunnelPath = "LAN"
		}
	}
}
