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

// YamuxConfig returns the yamux configuration for both sides. yamux's own
// keepalive is disabled; liveness runs on the control stream.
func YamuxConfig() *yamux.Config {
	cfg := yamux.DefaultConfig()
	cfg.EnableKeepAlive = false
	cfg.LogOutput = io.Discard
	cfg.StreamOpenTimeout = 15 * time.Second
	cfg.StreamCloseTimeout = 30 * time.Second

	return cfg
}

// Control is the control stream of a session. A reader goroutine answers
// Ping, records Pong, and delivers every other message on Messages.
type Control struct {
	conn     net.Conn
	limit    int
	mu       sync.Mutex
	msgs     chan proto.Message
	done     chan struct{}
	err      error
	errOnce  sync.Once
	seq      atomic.Uint64
	lastPong atomic.Int64
	waitMu   sync.Mutex
	waiters  map[uint64]chan time.Duration
	now      func() time.Time
}

// NewControl starts reading conn.
func NewControl(conn net.Conn) *Control {
	c := &Control{
		conn:    conn,
		limit:   proto.MaxMessageSize,
		msgs:    make(chan proto.Message, 16),
		done:    make(chan struct{}),
		waiters: make(map[uint64]chan time.Duration),
		now:     time.Now,
	}
	c.lastPong.Store(c.now().UnixNano())

	go c.read()

	return c
}

// Messages delivers non-liveness messages. It is closed when the stream ends.
func (c *Control) Messages() <-chan proto.Message {
	return c.msgs
}

// Done is closed when the control stream has failed or been closed.
func (c *Control) Done() <-chan struct{} {
	return c.done
}

// Err returns why the control stream ended.
func (c *Control) Err() error {
	select {
	case <-c.done:
		return c.err
	default:
		return nil
	}
}

// Send writes one message. Safe for concurrent use.
func (c *Control) Send(msg proto.Message) error {
	select {
	case <-c.done:
		return ErrClosed
	default:
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if err := c.conn.SetWriteDeadline(c.now().Add(PingInterval)); err != nil {
		return fmt.Errorf("tunnel: set deadline: %w", err)
	}

	if err := proto.WriteMessage(c.conn, msg); err != nil {
		c.fail(err)

		return err
	}

	return nil
}

// Close closes the control stream.
func (c *Control) Close() error {
	c.fail(ErrClosed)

	return nil
}

// PingNow sends a ping and waits for its Pong, returning the round-trip time.
func (c *Control) PingNow(ctx context.Context) (time.Duration, error) {
	seq := c.seq.Add(1)
	ch := make(chan time.Duration, 1)

	c.waitMu.Lock()
	c.waiters[seq] = ch
	c.waitMu.Unlock()

	defer func() {
		c.waitMu.Lock()
		delete(c.waiters, seq)
		c.waitMu.Unlock()
	}()

	if err := c.Send(proto.Ping{Seq: seq, SentUnixNano: c.now().UnixNano()}); err != nil {
		return 0, err
	}

	select {
	case rtt := <-ch:
		return rtt, nil
	case <-c.done:
		return 0, ErrClosed
	case <-ctx.Done():
		return 0, fmt.Errorf("tunnel: ping: %w", ctx.Err())
	}
}

// RunLiveness pings every interval and closes the control stream with ErrDead
// after maxMissed consecutive pings without a reply. It returns when the
// stream ends or ctx is done.
func (c *Control) RunLiveness(ctx context.Context, interval time.Duration, maxMissed int) error {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	missed := 0

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("tunnel: liveness: %w", ctx.Err())
		case <-c.done:
			return c.err
		case <-ticker.C:
		}

		pctx, cancel := context.WithTimeout(ctx, interval)
		_, err := c.PingNow(pctx)

		cancel()

		if err == nil {
			missed = 0

			continue
		}

		if errors.Is(err, ErrClosed) {
			return c.Err()
		}

		missed++
		if missed >= maxMissed {
			c.fail(ErrDead)

			return ErrDead
		}
	}
}

// LastPong returns when the last Pong arrived.
func (c *Control) LastPong() time.Time {
	return time.Unix(0, c.lastPong.Load())
}

func (c *Control) read() {
	defer close(c.msgs)

	for {
		msg, err := proto.ReadMessage(c.conn, c.limit)
		if err != nil {
			c.fail(err)

			return
		}

		switch m := msg.(type) {
		case proto.Ping:
			go func() { _ = c.Send(proto.Pong(m)) }()
		case proto.Pong:
			c.lastPong.Store(c.now().UnixNano())
			c.waitMu.Lock()
			ch, ok := c.waiters[m.Seq]
			c.waitMu.Unlock()

			if ok {
				select {
				case ch <- c.now().Sub(time.Unix(0, m.SentUnixNano)):
				default:
				}
			}
		default:
			select {
			case c.msgs <- msg:
			case <-c.done:
				return
			}
		}
	}
}

func (c *Control) fail(err error) {
	c.errOnce.Do(func() {
		c.err = err
		close(c.done)
		_ = c.conn.Close()
	})
}

// Join copies bytes both ways between a and b until both directions finish,
// then closes both. Half-close is propagated when supported.
func Join(a, b io.ReadWriteCloser) {
	var wg sync.WaitGroup

	wg.Add(2)

	go func() {
		defer wg.Done()
		copyHalf(a, b)
	}()
	go func() {
		defer wg.Done()
		copyHalf(b, a)
	}()

	wg.Wait()

	_ = a.Close()
	_ = b.Close()
}

type closeWriter interface {
	CloseWrite() error
}

func copyHalf(dst io.WriteCloser, src io.Reader) {
	_, _ = io.Copy(dst, src)

	if cw, ok := dst.(closeWriter); ok {
		_ = cw.CloseWrite()

		return
	}

	_ = dst.Close()
}
