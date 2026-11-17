package hub

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/hashicorp/yamux"

	"github.com/zekihan/t3-mesh/internal/policy"
	"github.com/zekihan/t3-mesh/internal/proto"
	"github.com/zekihan/t3-mesh/internal/tunnel"
)

// tracked is a relayed or viewer stream that is re-checked on every
// configuration change and at its certificate's NotAfter.
type tracked struct {
	kind    string // "relay" or "viewer"
	pol     policy.Session
	target  *session
	source  *session // relay only
	closeFn func()
	once    sync.Once
	err     error
}

func (t *tracked) close() { t.once.Do(t.closeFn) }

func (s *Server) track(t *tracked) {
	s.tmu.Lock()
	s.tracked[t] = struct{}{}
	s.tmu.Unlock()

	if t.target != nil {
		t.target.streams.Add(1)
	}

	if t.source != nil {
		t.source.linkStream.Add(1)
	}
}

func (s *Server) untrack(t *tracked) {
	s.tmu.Lock()
	_, ok := s.tracked[t]
	delete(s.tracked, t)
	s.tmu.Unlock()

	if !ok {
		return
	}

	if t.target != nil {
		t.target.streams.Add(-1)
	}

	if t.source != nil {
		t.source.linkStream.Add(-1)
	}
}

func (s *Server) closeTrackedFor(c *session) {
	var doomed []*tracked

	s.tmu.Lock()
	for t := range s.tracked {
		if t.target == c || t.source == c {
			doomed = append(doomed, t)
		}
	}
	s.tmu.Unlock()

	for _, t := range doomed {
		t.close()
	}
}

func (s *Server) closeAllTracked() {
	var all []*tracked

	s.tmu.Lock()
	for t := range s.tracked {
		all = append(all, t)
	}
	s.tmu.Unlock()

	for _, t := range all {
		t.close()
	}
}

func (s *Server) checkNow(t policy.Session) error {
	snap := s.cfg.Current()

	return policy.Check(snap.Rules, snap.Revocations, t, s.now())
}

// handleAgentStream serves one agent-opened link stream: it relays to the
// target machine's newest session after the policy check. The hub never reads
// the payload bytes.
func (s *Server) handleAgentStream(src *session, st *yamux.Stream) {
	fail := func(msg string) {
		_ = st.SetWriteDeadline(time.Now().Add(headerReadTimeout))
		_ = proto.WriteLine(st, proto.StreamReply{OK: false, Error: msg})
		_ = st.Close()
	}

	_ = st.SetReadDeadline(time.Now().Add(headerReadTimeout))

	var hdr proto.StreamHeader
	if err := proto.ReadLine(st, &hdr); err != nil || hdr.To == "" {
		_ = st.Close()

		return
	}

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
	log := src.log.With("target", hdr.To)

	if err := s.checkNow(pol); err != nil {
		log.Info("reject", "kind", "relay", "reason", err.Error())
		fail("not allowed")

		return
	}

	if _, ok := s.cfg.Current().Machines[machine].Services[svc]; !ok {
		fail("unknown target")

		return
	}

	tgt := s.liveSession(machine)
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
	tr.closeFn = func() { _ = st.Close(); _ = out.Close() }

	s.track(tr)
	defer s.untrack(tr)

	if err := s.checkNow(pol); err != nil {
		_ = out.Close()
		fail("not allowed")

		return
	}

	reply, err := openRelay(out, proto.StreamHeader{Svc: svc, From: src.identity})
	if err != nil || !reply.OK {
		msg := "target error"
		if err == nil {
			msg = "target refused: " + truncate(reply.Error, 200)
		}

		log.Info("relay failed", "error", fmt.Sprint(err), "reply", reply.Error)
		_ = out.Close()
		fail(msg)

		return
	}

	_ = st.SetWriteDeadline(time.Now().Add(headerReadTimeout))
	if err := proto.WriteLine(st, proto.StreamReply{OK: true}); err != nil {
		_ = out.Close()
		_ = st.Close()

		return
	}

	_ = st.SetWriteDeadline(time.Time{})

	log.Debug("relay open")
	tunnel.Join(st, out)
}

func openRelay(out *yamux.Stream, hdr proto.StreamHeader) (proto.StreamReply, error) {
	var reply proto.StreamReply

	_ = out.SetDeadline(time.Now().Add(replyTimeout))

	if err := proto.WriteLine(out, hdr); err != nil {
		return reply, fmt.Errorf("write header: %w", err)
	}

	if err := proto.ReadLine(out, &reply); err != nil {
		return reply, fmt.Errorf("read reply: %w", err)
	}

	_ = out.SetDeadline(time.Time{})

	return reply, nil
}

// trackedConn untracks its stream when closed.
type trackedConn struct {
	net.Conn
	once    sync.Once
	onClose func()
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
