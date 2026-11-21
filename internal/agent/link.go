package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/zekihan/t3-mesh/internal/agent/linkguard"
	"github.com/zekihan/t3-mesh/internal/proto"
	"github.com/zekihan/t3-mesh/internal/tunnel"
)

const (
	linkHeaderTimeout = 10 * time.Second
	streamReplyWait   = 15 * time.Second
)

var (
	errNoTunnel = errors.New("hub not connected")
	errRefused  = errors.New("refused by hub")
	errLinkKind = errors.New("link kind changed or unavailable")
)

// linkServer is one loopback link port.
type linkServer struct {
	ln          net.Listener
	a           *Agent
	srv         *http.Server
	key         string
	svc         string
	machine     string
	hostRewrite string
	port        int
	bound       atomic.Bool
}

// bindLinks binds every configured link port. A failure is a startup failure,
// so the launcher's local startup check catches a port that cannot be bound.
func (agent *Agent) bindLinks(ctx context.Context) ([]*linkServer, error) {
	keys := make([]string, 0, len(agent.cfg.Links))
	for k := range agent.cfg.Links {
		keys = append(keys, k)
	}

	var out []*linkServer

	for _, key := range keys {
		svc, machine, _ := strings.Cut(key, ".")

		addr := agent.cfg.Links[key]

		_, portStr, err := net.SplitHostPort(addr)
		if err != nil {
			agent.closeLinks(out)

			return nil, fmt.Errorf("agent: link %s: %w", key, err)
		}

		port, err := strconv.Atoi(portStr)
		if err != nil {
			agent.closeLinks(out)

			return nil, fmt.Errorf("agent: link %s: bad port: %w", key, err)
		}

		var lc net.ListenConfig

		ln, err := lc.Listen(ctx, "tcp", addr)
		if err != nil {
			agent.closeLinks(out)

			return nil, fmt.Errorf("agent: bind link %s on %s: %w", key, addr, err)
		}

		srv := &linkServer{a: agent, key: key, svc: svc, machine: machine, port: port, ln: ln}
		srv.bound.Store(true)
		srv.srv = &http.Server{
			Handler: linkguard.Middleware(
				port,
				agent.cfg.LinkOrigins,
				svc,
				agent.log,
				srv.proxy(),
			),
			ReadHeaderTimeout: linkHeaderTimeout,
		}

		agent.log.InfoContext(ctx, "Link port bound", slog.String("link", key),
			slog.String("addr", ln.Addr().String()),
		)

		out = append(out, srv)
	}

	return out, nil
}

func (agent *Agent) closeLinks(ls []*linkServer) {
	for _, l := range ls {
		l.close()
	}
}

func (srv *linkServer) serve() {
	defer srv.bound.Store(false)

	err := srv.srv.Serve(linkListener{Listener: srv.ln, srv: srv})
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		srv.a.log.Error("Link server stopped", slog.String("link", srv.key),
			slog.Any("err", err),
		)
	}
}

func (srv *linkServer) close() {
	srv.bound.Store(false)
	_ = srv.srv.Close()
	_ = srv.ln.Close()
}

// linkListener sends only known HTTP connections to net/http. The same socket
// stays bound when a hub update changes the service kind.
type linkListener struct {
	net.Listener

	srv *linkServer
}

func (ln linkListener) Accept() (net.Conn, error) {
	for {
		conn, err := ln.Listener.Accept()
		if err != nil {
			return nil, fmt.Errorf("accept link: %w", err)
		}

		srv := ln.srv
		switch srv.a.linkKind(srv.key) {
		case proto.KindHTTP:
			return conn, nil
		case proto.KindTCP:
			srv.a.wg.Go(func() { srv.serveTCP(conn) })
		default:
			_ = conn.Close()
		}
	}
}

func (agent *Agent) linkKind(key string) string {
	agent.mu.Lock()
	defer agent.mu.Unlock()

	return agent.cache.Rules.ServiceKinds[key]
}

func (srv *linkServer) serveTCP(conn net.Conn) {
	defer func() { _ = conn.Close() }()

	peer, err := srv.a.dialLink(srv.a.ctx, srv.machine, srv.svc, proto.KindTCP)
	if err != nil {
		srv.a.log.Debug("TCP link failed",
			slog.String("link", srv.key),
			slog.Any("err", err),
		)

		return
	}

	tunnel.JoinTCP(srv.a.ctx, conn, peer)
}

// proxy returns the reverse proxy for the link. Keep-alives are off, so every
// request dials afresh and takes the current path (direct or tunnel); nothing
// pooled can outlive a path switch. Host, Origin and paths pass unchanged;
// httputil.ReverseProxy carries WebSocket upgrades.
func (srv *linkServer) proxy() http.Handler {
	tr := &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return srv.a.dialLink(ctx, srv.machine, srv.svc, proto.KindHTTP)
		},
	}

	return &httputil.ReverseProxy{
		Transport:      tr,
		ModifyResponse: linkguard.GuardAssetResponse,
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme = "http"
			pr.Out.URL.Host = srv.key

			if srv.hostRewrite != "" {
				pr.Out.Host = srv.hostRewrite
			}
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			srv.a.log.WarnContext(r.Context(), "Link request failed", slog.String("link", srv.key),
				slog.Any("err", err),
			)
			http.Error(w, "mesh: "+srv.key+" unreachable", http.StatusBadGateway)
		},
	}
}

// dialLink opens a byte stream to svc on machine: direct when the manager can,
// otherwise through the hub tunnel.
func (agent *Agent) dialLink(ctx context.Context, machine, svc, kind string) (net.Conn, error) {
	if agent.linkKind(svc+"."+machine) != kind {
		return nil, errLinkKind
	}

	if agent.direct != nil {
		c, err := agent.direct.Dial(ctx, machine, svc, kind)
		if err == nil {
			return c, nil
		}

		agent.log.DebugContext(ctx,
			"Direct dial unavailable, using tunnel",
			slog.String("machine", machine),
			slog.String("svc", svc),
			slog.Any("err", err),
		)
	}

	return agent.dialTunnel(ctx, machine, svc, kind)
}

func (agent *Agent) dialTunnel(ctx context.Context, machine, svc, kind string) (net.Conn, error) {
	sess := agent.current()
	if sess == nil {
		return nil, errNoTunnel
	}

	if kind == proto.KindTCP && !sess.tcpLinks {
		return nil, errLinkKind
	}

	err := ctx.Err()
	if err != nil {
		return nil, fmt.Errorf("open stream: %w", err)
	}

	st, err := sess.ymx.OpenStream()
	if err != nil {
		return nil, fmt.Errorf("open stream: %w", err)
	}

	stop := context.AfterFunc(ctx, func() {
		setDeadline(st.SetDeadline, time.Unix(1, 0))
	})
	defer stop()

	setDeadline(st.SetDeadline, time.Now().Add(streamReplyWait))

	hdr := proto.StreamHeader{To: svc + "." + machine}
	if kind == proto.KindTCP {
		hdr.Kind = kind
	}

	err = proto.WriteLine(st, hdr)
	if err != nil {
		_ = st.Close()

		return nil, fmt.Errorf("write stream header: %w", err)
	}

	var reply proto.StreamReply

	err = proto.ReadLine(st, &reply)
	if err != nil {
		_ = st.Close()

		return nil, fmt.Errorf("read stream reply: %w", err)
	}

	if !reply.OK {
		_ = st.Close()

		return nil, fmt.Errorf("%w: %s", errRefused, reply.Error)
	}

	if !stop() {
		_ = st.Close()

		return nil, fmt.Errorf("open stream: %w", ctx.Err())
	}

	setDeadline(st.SetDeadline, time.Time{})

	return st, nil
}
