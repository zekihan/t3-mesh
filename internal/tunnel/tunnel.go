// Package tunnel holds the pieces of the tunnel shared by hub and agent: yamux
// settings, the control stream with liveness, and byte splicing.
package tunnel

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/yamux"

	"github.com/zekihan/t3-mesh/internal/proto"
)

const (
	defaultStreamOpenTimeout  = 15 * time.Second
	defaultStreamCloseTimeout = 30 * time.Second
	messageBuffer             = 16
	joinDirections            = 2
)

// Liveness defaults from the design: ping every 10 s, three missed replies
// close the session.
const (
	PingInterval = 10 * time.Second
	MaxMissed    = 3
)

// ErrDead is returned when the peer missed too many pings.
var ErrDead = errors.New("tunnel: peer missed pings")

// ErrClosed is returned by Send and PingNow on a closed control stream.
var ErrClosed = errors.New("tunnel: control stream closed")

// YamuxConfig returns the yamux configuration for both sides. Yamux's own
// keepalive is disabled; liveness runs on the control stream.
func YamuxConfig() *yamux.Config {
	cfg := yamux.DefaultConfig()
	cfg.EnableKeepAlive = false
	cfg.LogOutput = io.Discard
	cfg.StreamOpenTimeout = defaultStreamOpenTimeout
	cfg.StreamCloseTimeout = defaultStreamCloseTimeout

	return cfg
}

// Control is the control stream of a session. A reader goroutine answers
// Ping, records Pong, and delivers every other message on Messages.
type Control struct {
	conn     net.Conn
	err      error
	msgs     chan proto.Message
	done     chan struct{}
	sending  chan struct{}
	waiters  map[uint64]chan time.Duration
	now      func() time.Time
	limit    int
	seq      atomic.Uint64
	lastPong atomic.Int64
	errOnce  sync.Once
	waitMu   sync.Mutex
}

// NewControl starts reading conn.
func NewControl(conn net.Conn) *Control {
	ctl := &Control{
		conn:    conn,
		limit:   proto.MaxMessageSize,
		msgs:    make(chan proto.Message, messageBuffer),
		done:    make(chan struct{}),
		sending: make(chan struct{}, 1),
		waiters: make(map[uint64]chan time.Duration),
		now:     time.Now,
	}
	ctl.lastPong.Store(ctl.now().UnixNano())

	go ctl.read()

	return ctl
}

// Messages delivers non-liveness messages. It is closed when the stream ends.
func (ctl *Control) Messages() <-chan proto.Message {
	return ctl.msgs
}

// Done is closed when the control stream has failed or been closed.
func (ctl *Control) Done() <-chan struct{} {
	return ctl.done
}

// Err returns why the control stream ended.
func (ctl *Control) Err() error {
	select {
	case <-ctl.done:
		return ctl.err
	default:
		return nil
	}
}

// Send writes one message. Safe for concurrent use.
func (ctl *Control) Send(msg proto.Message) error {
	if !ctl.acquireSend(nil) {
		return ErrClosed
	}

	return ctl.write(msg)
}

// Close closes the control stream.
func (ctl *Control) Close() error {
	ctl.fail(ErrClosed)

	return nil
}

// PingNow sends a ping and waits for its Pong, returning the round-trip time.
// The context bounds the wait for both the send and the reply.
func (ctl *Control) PingNow(ctx context.Context) (time.Duration, error) {
	if !ctl.acquireSend(ctx.Done()) {
		if ctx.Err() != nil {
			return 0, fmt.Errorf("tunnel: ping: %w", ctx.Err())
		}

		return 0, ErrClosed
	}

	seq := ctl.seq.Add(1)
	ch := make(chan time.Duration, 1)

	ctl.waitMu.Lock()
	ctl.waiters[seq] = ch
	ctl.waitMu.Unlock()

	defer func() {
		ctl.waitMu.Lock()
		delete(ctl.waiters, seq)
		ctl.waitMu.Unlock()
	}()

	ping := proto.Ping{Seq: seq, SentUnixNano: ctl.now().UnixNano()}
	sendErr := make(chan error, 1)
	// A yamux stream deadline cannot interrupt every kind of transport write.
	go func() {
		if ctx.Err() != nil {
			<-ctl.sending

			return
		}

		err := ctl.write(ping)
		if err != nil {
			sendErr <- err
		}
	}()

	select {
	case rtt := <-ch:
		return rtt, nil
	case err := <-sendErr:
		return 0, err
	case <-ctl.done:
		return 0, ErrClosed
	case <-ctx.Done():
		return 0, fmt.Errorf("tunnel: ping: %w", ctx.Err())
	}
}

// RunLiveness pings every interval and closes the control stream with ErrDead
// after maxMissed consecutive pings without a reply. It returns when the
// stream ends or ctx is done.
func (ctl *Control) RunLiveness(ctx context.Context, interval time.Duration, maxMissed int) error {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	missed := 0

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("tunnel: liveness: %w", ctx.Err())
		case <-ctl.done:
			return ctl.err
		case <-ticker.C:
		}

		pctx, cancel := context.WithTimeout(ctx, interval)
		_, err := ctl.PingNow(pctx)

		cancel()

		if err == nil {
			missed = 0

			continue
		}

		if errors.Is(err, ErrClosed) {
			return ctl.Err()
		}

		missed++
		if missed >= maxMissed {
			ctl.fail(ErrDead)

			return ErrDead
		}
	}
}

// LastPong returns when the last Pong arrived.
func (ctl *Control) LastPong() time.Time {
	return time.Unix(0, ctl.lastPong.Load())
}

func (ctl *Control) acquireSend(canceled <-chan struct{}) bool {
	select {
	case <-canceled:
		return false
	case <-ctl.done:
		return false
	case ctl.sending <- struct{}{}:
		return true
	}
}

// write releases the send slot after the transport returns, even if the caller stops waiting.
func (ctl *Control) write(msg proto.Message) error {
	defer func() { <-ctl.sending }()

	select {
	case <-ctl.done:
		return ErrClosed
	default:
	}

	err := ctl.conn.SetWriteDeadline(ctl.now().Add(PingInterval))
	if err != nil {
		return fmt.Errorf("tunnel: set deadline: %w", err)
	}

	err = proto.WriteMessage(ctl.conn, msg)
	if err != nil {
		ctl.fail(err)

		return fmt.Errorf("tunnel: write message: %w", err)
	}

	return nil
}

func (ctl *Control) read() {
	defer close(ctl.msgs)

	for {
		msg, err := proto.ReadMessage(ctl.conn, ctl.limit)
		if err != nil {
			ctl.fail(err)

			return
		}

		switch typed := msg.(type) {
		case proto.Ping:
			go func() { _ = ctl.Send(proto.Pong(typed)) }() //nolint:errcheck // best-effort pong
		case proto.Pong:
			ctl.lastPong.Store(ctl.now().UnixNano())
			ctl.waitMu.Lock()
			ch, ok := ctl.waiters[typed.Seq]
			ctl.waitMu.Unlock()

			if ok {
				select {
				case ch <- ctl.now().Sub(time.Unix(0, typed.SentUnixNano)):
				default:
				}
			}
		default:
			select {
			case ctl.msgs <- msg:
			case <-ctl.done:
				return
			}
		}
	}
}

func (ctl *Control) fail(err error) {
	ctl.errOnce.Do(func() {
		ctl.err = err
		close(ctl.done)
		_ = ctl.conn.Close()
	})
}

// Join copies bytes both ways between left and right until both directions finish,
// then closes both. Half-close is propagated when supported.
func Join(left, right io.ReadWriteCloser) {
	var wg sync.WaitGroup

	wg.Add(joinDirections)

	go func() {
		defer wg.Done()

		copyHalf(left, right)
	}()
	go func() {
		defer wg.Done()

		copyHalf(right, left)
	}()

	wg.Wait()

	_ = left.Close()
	_ = right.Close()
}

type closeWriter interface {
	CloseWrite() error
}

func copyHalf(dst io.WriteCloser, src io.Reader) {
	_, _ = io.Copy(dst, src) //nolint:errcheck // copy errors end the relay, which is closed below

	if cw, ok := dst.(closeWriter); ok {
		_ = cw.CloseWrite() //nolint:errcheck // half-close is best-effort

		return
	}

	_ = dst.Close()
}
