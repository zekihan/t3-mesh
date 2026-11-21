package agent

import (
	"context"
	"io"
	"log/slog"
	"net"
	"time"

	"github.com/hashicorp/yamux"

	"github.com/zekihan/t3-mesh/internal/proto"
	"github.com/zekihan/t3-mesh/internal/tunnel"
)

const (
	hubHeaderTimeout = 10 * time.Second
	localDialTimeout = 5 * time.Second
)

// handleHubStream serves a stream the hub opened: viewer traffic or a relayed
// agent-to-agent stream. The agent trusts the hub's authorization. Relayed
// streams get a StreamReply once the local dial settles; viewer streams carry
// raw HTTP straight away and get none.
func (agent *Agent) handleHubStream(ctx context.Context, st *yamux.Stream) {
	setDeadline(st.SetReadDeadline, time.Now().Add(hubHeaderTimeout))

	var hdr proto.StreamHeader

	err := proto.ReadLine(st, &hdr)
	if err != nil {
		agent.log.DebugContext(ctx, "Hub stream header unreadable", slog.Any("err", err))

		_ = st.Close()

		return
	}

	setDeadline(st.SetReadDeadline, time.Time{})

	relayed := hdr.From != ""
	if hdr.ServiceKind() != proto.KindHTTP {
		agent.replyIf(relayed, st, proto.StreamReply{Error: "service kind unavailable"})
		_ = st.Close()

		return
	}

	if !relayed && hdr.Viewer == "" {
		agent.log.WarnContext(
			ctx,
			"Hub stream refused",
			slog.String("reason", "no viewer or source"),
			slog.String("svc", hdr.Svc),
		)

		_ = st.Close()

		return
	}

	target, ok := agent.cfg.Serve[hdr.Svc]
	if !ok {
		agent.log.WarnContext(
			ctx,
			"Hub stream refused",
			slog.String("reason", "service not served"),
			slog.String("svc", hdr.Svc),
			slog.String("viewer", hdr.Viewer),
			slog.String("from", hdr.From),
		)
		agent.replyIf(relayed, st, proto.StreamReply{OK: false, Error: "service not served"})
		_ = st.Close()

		return
	}

	dialCtx, cancel := context.WithTimeout(ctx, localDialTimeout)
	d := net.Dialer{}

	conn, err := d.DialContext(dialCtx, "tcp", target)

	cancel()

	if err != nil {
		agent.log.WarnContext(ctx, "Local dial failed", slog.String("svc", hdr.Svc),
			slog.String("target", target),
			slog.Any("err", err),
		)
		agent.replyIf(relayed, st, proto.StreamReply{OK: false, Error: "service unavailable"})
		_ = st.Close()

		return
	}

	// A dropped tunnel must also unblock the copy that reads from the backend.
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	if relayed {
		err = proto.WriteLine(st, proto.StreamReply{OK: true})
		if err != nil {
			_ = conn.Close()
			_ = st.Close()

			return
		}
	}

	tunnel.Join(st, conn)
}

func (agent *Agent) replyIf(cond bool, st *yamux.Stream, r proto.StreamReply) {
	if cond {
		replyQuietly(st, r)
	}
}

// setDeadline is best effort: a dead connection fails the next I/O call anyway.
func setDeadline(set func(time.Time) error, deadline time.Time) {
	_ = set(deadline) //nolint:errcheck // a dead conn fails the next I/O call anyway
}

// replyQuietly writes a reply nobody is obliged to receive; the peer may be gone.
func replyQuietly(w io.Writer, reply proto.StreamReply) {
	_ = proto.WriteLine(w, reply) //nolint:errcheck // best-effort reply to a dropped peer
}
