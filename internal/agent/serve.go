package agent

import (
	"context"
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
func (a *Agent) handleHubStream(st *yamux.Stream) {
	_ = st.SetReadDeadline(time.Now().Add(hubHeaderTimeout))

	var hdr proto.StreamHeader
	if err := proto.ReadLine(st, &hdr); err != nil {
		a.log.Debug("hub stream header unreadable", "err", err)
		_ = st.Close()

		return
	}

	_ = st.SetReadDeadline(time.Time{})

	relayed := hdr.From != ""

	if !relayed && hdr.Viewer == "" {
		a.log.Warn("hub stream refused", "reason", "no viewer or source", "svc", hdr.Svc)
		_ = st.Close()

		return
	}

	target, ok := a.cfg.Serve[hdr.Svc]
	if !ok {
		a.log.Warn("hub stream refused", "reason", "service not served", "svc", hdr.Svc,
			"viewer", hdr.Viewer, "from", hdr.From)
		a.replyIf(relayed, st, proto.StreamReply{OK: false, Error: "service not served"})
		_ = st.Close()

		return
	}

	ctx, cancel := context.WithTimeout(a.ctx, localDialTimeout)
	defer cancel()

	d := net.Dialer{}

	conn, err := d.DialContext(ctx, "tcp", target)
	if err != nil {
		a.log.Warn("local dial failed", "svc", hdr.Svc, "target", target, "err", err)
		a.replyIf(relayed, st, proto.StreamReply{OK: false, Error: "service unavailable"})
		_ = st.Close()

		return
	}

	if relayed {
		if err = proto.WriteLine(st, proto.StreamReply{OK: true}); err != nil {
			_ = conn.Close()
			_ = st.Close()

			return
		}
	}

	tunnel.Join(st, conn)
}

func (a *Agent) replyIf(cond bool, st *yamux.Stream, r proto.StreamReply) {
	if cond {
		_ = proto.WriteLine(st, r)
	}
}
