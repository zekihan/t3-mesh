package hub

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/hashicorp/yamux"

	"github.com/zekihan/t3-mesh/internal/hub/hubconfig"
	"github.com/zekihan/t3-mesh/internal/policy"
	"github.com/zekihan/t3-mesh/internal/proto"
	"github.com/zekihan/t3-mesh/internal/tunnel"
)

// tracked is a relayed or viewer stream that is re-checked on every
// configuration change and at its certificate's NotAfter.
type tracked struct {
	target  *session
	source  *session
	closeFn func()
	pol     policy.Session
	kind    string
	once    sync.Once
}

func (track *tracked) close() { track.once.Do(track.closeFn) }

func (server *Server) track(entry *tracked) {
	server.tmu.Lock()
	server.tracked[entry] = struct{}{}
	server.tmu.Unlock()

	if entry.target != nil {
		entry.target.streams.Add(1)
	}

	if entry.source != nil {
		entry.source.linkStream.Add(1)
	}
}

func (server *Server) untrack(entry *tracked) {
	server.tmu.Lock()
	_, ok := server.tracked[entry]
	delete(server.tracked, entry)
	server.tmu.Unlock()

	if !ok {
		return
	}

	if entry.target != nil {
		entry.target.streams.Add(-1)
	}

	if entry.source != nil {
		entry.source.linkStream.Add(-1)
	}
}

func (server *Server) closeTrackedFor(c *session) {
	var doomed []*tracked

	server.tmu.Lock()
	for t := range server.tracked {
		if t.target == c || t.source == c {
			doomed = append(doomed, t)
		}
	}
	server.tmu.Unlock()

	for _, t := range doomed {
		t.close()
	}
}

func (server *Server) closeAllTracked() {
	server.tmu.Lock()

	all := make([]*tracked, 0, len(server.tracked))
	for t := range server.tracked {
		all = append(all, t)
	}
	server.tmu.Unlock()

	for _, t := range all {
		t.close()
	}
}

// checkNow reports whether a stream is still allowed: by the rules and
// revocations, and, for an enrolled device, by what the hub knows of its
// configuration and newest leaf.
func (server *Server) checkNow(pol *policy.Session) error {
	return server.checkSession(server.cfg.Current(), pol, server.now())
}

func (server *Server) checkSession(
	snap *hubconfig.Snapshot,
	pol *policy.Session,
	now time.Time,
) error {
	err := policy.Check(snap.Rules, snap.Revocations, *pol, now)
	if err != nil {
		//nolint:wrapcheck // policy errors are returned verbatim; callers send them as reject reasons
		return err
	}

	return server.deviceCurrent(snap, pol.Identity, pol.Fingerprint)
}

// checkRules is the rules and revocations half of checkNow, for a request that
// has not yet been through the device check.
func (server *Server) checkRules(pol *policy.Session) error {
	snap := server.cfg.Current()

	//nolint:wrapcheck // policy errors are returned verbatim; callers send them as reject reasons
	return policy.Check(snap.Rules, snap.Revocations, *pol, server.now())
}

// handleAgentStream serves one agent-opened link stream: it relays to the
// target machine's newest session after the policy check. The hub never reads
// the payload bytes.
func (server *Server) handleAgentStream(src *session, st *yamux.Stream) {
	fail := func(msg string) {
		//nolint:errcheck // best-effort deadline; a dead connection fails the next read or write
		_ = st.SetWriteDeadline(time.Now().Add(headerReadTimeout))
		//nolint:errcheck // best-effort notice; the peer may already be gone
		_ = proto.WriteLine(st, proto.StreamReply{OK: false, Error: msg})
		_ = st.Close()
	}

	//nolint:errcheck // best-effort deadline; a dead connection fails the next read or write
	_ = st.SetReadDeadline(time.Now().Add(headerReadTimeout))

	var hdr proto.StreamHeader

	err := proto.ReadLine(st, &hdr)
	if err != nil || hdr.To == "" {
		_ = st.Close()

		return
	}

	//nolint:errcheck // best-effort deadline; a dead connection fails the next read or write
	_ = st.SetReadDeadline(time.Time{})

	svc, machine, ok := policy.SplitTarget(hdr.To)
	if !ok {
		fail("bad target")

		return
	}

	pol := policy.Session{
		Identity:    src.identity,
		Fingerprint: src.fingerprint,
		NotAfter:    src.notAfter,
		Svc:         svc,
		Machine:     machine,
	}
	log := src.log.With(slog.Any("target", hdr.To))

	err = server.checkNow(&pol)
	if err != nil {
		log.Info(
			"Reject",
			slog.String("kind", "relay"),
			slog.String("reason", err.Error()),
		)
		fail("not allowed")

		return
	}

	if _, ok := server.cfg.Current().Machines[machine].Services[svc]; !ok {
		fail("unknown target")

		return
	}

	tgt := server.liveSession(machine)
	if tgt == nil {
		fail("target not connected")

		return
	}

	out, err := tgt.ymx.OpenStream()
	if err != nil {
		fail("target unreachable")

		return
	}

	tr := &tracked{kind: "relay", pol: pol, target: tgt, source: src}
	tr.closeFn = func() { abortConn(st); abortConn(out) }

	server.track(tr)
	defer server.untrack(tr)

	err = server.checkNow(&pol)
	if err != nil {
		_ = out.Close()

		fail("not allowed")

		return
	}

	reply, err := openRelay(out, proto.StreamHeader{Svc: svc, From: src.identity})
	if err != nil || !reply.OK {
		msg := "target error"
		if err == nil {
			msg = "target refused: " + truncate(reply.Error, maxDetailLen)
		}

		log.Info(
			"Relay failed",
			slog.Any("error", err),
			slog.String("reply", reply.Error),
		)

		_ = out.Close()

		fail(msg)

		return
	}

	//nolint:errcheck // best-effort deadline; a dead connection fails the next read or write
	_ = st.SetWriteDeadline(time.Now().Add(headerReadTimeout))

	err = proto.WriteLine(st, proto.StreamReply{OK: true})
	if err != nil {
		_ = out.Close()
		_ = st.Close()

		return
	}

	//nolint:errcheck // best-effort deadline; a dead connection fails the next read or write
	_ = st.SetWriteDeadline(time.Time{})

	log.Debug("Relay open")
	tunnel.Join(st, out)
}

func openRelay(out *yamux.Stream, hdr proto.StreamHeader) (proto.StreamReply, error) {
	var reply proto.StreamReply

	//nolint:errcheck // best-effort deadline; a dead connection fails the next read or write
	_ = out.SetDeadline(time.Now().Add(replyTimeout))

	err := proto.WriteLine(out, hdr)
	if err != nil {
		return reply, fmt.Errorf("write header: %w", err)
	}

	err = proto.ReadLine(out, &reply)
	if err != nil {
		return reply, fmt.Errorf("read reply: %w", err)
	}

	//nolint:errcheck // best-effort deadline; a dead connection fails the next read or write
	_ = out.SetDeadline(time.Time{})

	return reply, nil
}

// The abortConn helper ends a stream at once. A yamux Close only half-closes, so reads
// would wait for the other end to hang up; a deadline in the past fails every
// pending and later read and write first.
func abortConn(c net.Conn) {
	//nolint:errcheck // best-effort: the Close below ends the stream either way
	_ = c.SetDeadline(time.Now())
	_ = c.Close()
}

// trackedConn untracks its stream when closed.
type trackedConn struct {
	net.Conn

	onClose func()
	once    sync.Once
}

func (c *trackedConn) Close() error {
	var err error

	c.once.Do(func() {
		c.onClose()

		err = c.Conn.Close()
	})

	if err != nil && !errors.Is(err, net.ErrClosed) {
		return fmt.Errorf("hub: close stream: %w", err)
	}

	return nil
}
