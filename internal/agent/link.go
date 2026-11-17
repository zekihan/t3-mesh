package agent

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"strconv"
	"strings"
	"time"

	"github.com/zekihan/t3-mesh/internal/agent/linkguard"
	"github.com/zekihan/t3-mesh/internal/proto"
)

const (
	linkHeaderTimeout = 10 * time.Second
	streamReplyWait   = 15 * time.Second
)

var (
	errNoTunnel = errors.New("hub not connected")
	errRefused  = errors.New("refused by hub")
)

// linkServer is one loopback link port.
type linkServer struct {
	a       *Agent
	key     string
	svc     string
	machine string
	port    int
	ln      net.Listener
	srv     *http.Server

	// hostRewrite, when set, replaces the Host header sent upstream. It is
	// unused today: T3 gets the link port's own Host (open item in the design).
	hostRewrite string
}

// bindLinks binds every configured link port. A failure is a startup failure,
// so the launcher's local startup check catches a port that cannot be bound.
func (a *Agent) bindLinks() ([]*linkServer, error) {
	keys := make([]string, 0, len(a.cfg.Links))
	for k := range a.cfg.Links {
		keys = append(keys, k)
	}

	var out []*linkServer

	for _, key := range keys {
		svc, machine, _ := strings.Cut(key, ".")

		addr := a.cfg.Links[key]

		_, portStr, err := net.SplitHostPort(addr)
		if err != nil {
			a.closeLinks(out)

			return nil, fmt.Errorf("agent: link %s: %w", key, err)
		}

		port, err := strconv.Atoi(portStr)
		if err != nil {
			a.closeLinks(out)

			return nil, fmt.Errorf("agent: link %s: bad port: %w", key, err)
		}

		var lc net.ListenConfig

		ln, err := lc.Listen(context.Background(), "tcp", addr)
		if err != nil {
			a.closeLinks(out)

			return nil, fmt.Errorf("agent: bind link %s on %s: %w", key, addr, err)
		}

		l := &linkServer{a: a, key: key, svc: svc, machine: machine, port: port, ln: ln}
		l.srv = &http.Server{
			Handler:           linkguard.Middleware(port, l.proxy()),
			ReadHeaderTimeout: linkHeaderTimeout,
		}

		a.log.Info("link port bound", "link", key, "addr", ln.Addr().String())

		out = append(out, l)
	}

	return out, nil
}

func (a *Agent) closeLinks(ls []*linkServer) {
	for _, l := range ls {
		l.close()
	}
}

func (l *linkServer) serve() {
	if err := l.srv.Serve(l.ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		l.a.log.Error("link server stopped", "link", l.key, "err", err)
	}
}

func (l *linkServer) close() {
	_ = l.srv.Close()
	_ = l.ln.Close()
}

// proxy returns the reverse proxy for the link. Keep-alives are off, so every
// request dials afresh and takes the current path (direct or tunnel); nothing
// pooled can outlive a path switch. Host, Origin and paths pass unchanged;
// httputil.ReverseProxy carries WebSocket upgrades.
func (l *linkServer) proxy() http.Handler {
	tr := &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return l.a.dialLink(ctx, l.machine, l.svc)
		},
	}

	return &httputil.ReverseProxy{
		Transport: tr,
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme = "http"
			pr.Out.URL.Host = l.key

			if l.hostRewrite != "" {
				pr.Out.Host = l.hostRewrite
			}
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			l.a.log.Warn("link request failed", "link", l.key, "err", err)
			http.Error(w, "mesh: "+l.key+" unreachable", http.StatusBadGateway)
		},
	}
}

// dialLink opens a byte stream to svc on machine: direct when the manager can,
// otherwise through the hub tunnel.
func (a *Agent) dialLink(ctx context.Context, machine, svc string) (net.Conn, error) {
	if a.direct != nil {
		c, err := a.direct.Dial(ctx, machine, svc)
		if err == nil {
			return c, nil
		}

		a.log.Debug("direct dial unavailable, using tunnel", "machine", machine, "svc", svc, "err", err)
	}

	return a.dialTunnel(ctx, machine, svc)
}

func (a *Agent) dialTunnel(ctx context.Context, machine, svc string) (net.Conn, error) {
	s := a.current()
	if s == nil {
		return nil, errNoTunnel
	}

	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("open stream: %w", err)
	}

	st, err := s.ymx.OpenStream()
	if err != nil {
		return nil, fmt.Errorf("open stream: %w", err)
	}

	stop := context.AfterFunc(ctx, func() { _ = st.SetDeadline(time.Unix(1, 0)) })
	defer stop()

	_ = st.SetDeadline(time.Now().Add(streamReplyWait))

	if err = proto.WriteLine(st, proto.StreamHeader{To: svc + "." + machine}); err != nil {
		_ = st.Close()

		return nil, fmt.Errorf("write stream header: %w", err)
	}

	var reply proto.StreamReply
	if err = proto.ReadLine(st, &reply); err != nil {
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

	_ = st.SetDeadline(time.Time{})

	return st, nil
}
