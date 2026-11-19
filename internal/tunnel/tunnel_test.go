package tunnel

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"testing/synctest"
	"time"

	"github.com/zekihan/t3-mesh/internal/proto"
)

func TestControlPingAndMessages(t *testing.T) {
	a, b := net.Pipe()

	ca, cb := NewControl(a), NewControl(b)
	defer ca.Close()
	defer cb.Close()

	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()

	_, err := ca.PingNow(ctx)
	if err != nil {
		t.Fatal(err)
	}

	err = ca.Send(proto.Status{Version: "v1.0.0"})
	if err != nil {
		t.Fatal(err)
	}

	select {
	case m := <-cb.Messages():
		if s, ok := m.(proto.Status); !ok || s.Version != "v1.0.0" {
			t.Fatalf("got %#v", m)
		}
	case <-ctx.Done():
		t.Fatal("timeout")
	}
}

func TestPingNowDeadlineIncludesWrite(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		client, peer := net.Pipe()
		defer peer.Close()

		ctl := NewControl(client)
		defer ctl.Close()

		const timeout = 2 * time.Second

		ctx, cancel := context.WithTimeout(t.Context(), timeout)
		defer cancel()

		start := time.Now()

		// The peer never reads, so the probe cannot write its ping.
		_, err := ctl.PingNow(ctx)
		elapsed := time.Since(start)

		if elapsed != timeout || !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf(
				"PingNow returned %v after %v, want context deadline exceeded after %v",
				err,
				elapsed,
				timeout,
			)
		}
	})
}

func TestPingNowDeadlineWhileWaitingToWrite(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		client, peer := net.Pipe()
		defer peer.Close()

		ctl := NewControl(client)
		defer ctl.Close()

		statusSent := make(chan error, 1)
		go func() { statusSent <- ctl.Send(proto.Status{Version: "v1.0.0"}) }()

		synctest.Wait() // The status write is blocked by the peer.

		ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
		defer cancel()

		_, err := ctl.PingNow(ctx)
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("PingNow error = %v, want context deadline exceeded", err)
		}

		msg, err := proto.ReadMessage(peer, proto.MaxMessageSize)
		if err != nil {
			t.Fatal(err)
		}

		if _, ok := msg.(proto.Status); !ok {
			t.Fatalf("message = %T, want Status", msg)
		}

		err = <-statusSent
		if err != nil {
			t.Fatal(err)
		}

		err = peer.SetReadDeadline(time.Now().Add(time.Second))
		if err != nil {
			t.Fatal(err)
		}

		var netErr net.Error

		msg, err = proto.ReadMessage(peer, proto.MaxMessageSize)
		if !errors.As(err, &netErr) || !netErr.Timeout() {
			t.Fatalf(
				"read message %T, error = %v, want timeout without sending the expired ping",
				msg,
				err,
			)
		}
	})
}

func TestLivenessDetectsDeadPeer(t *testing.T) {
	a, b := net.Pipe()
	ca := NewControl(a)
	// b never reads: drain nothing so pings block, then time out.
	go func() { _, _ = io.Copy(io.Discard, b) }()

	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()

	err := ca.RunLiveness(ctx, 20*time.Millisecond, 3)
	if !errors.Is(err, ErrDead) {
		t.Fatalf("err = %v, want ErrDead", err)
	}

	select {
	case <-ca.Done():
	default:
		t.Fatal("control not closed")
	}
}

func TestJoin(t *testing.T) {
	a1, a2 := net.Pipe()

	b1, b2 := net.Pipe()
	go Join(a2, b1)
	go func() {
		_, _ = a1.Write([]byte("hello"))
		_ = a1.Close()
	}()

	got, err := io.ReadAll(b2)
	if err != nil {
		t.Fatal(err)
	}

	if string(got) != "hello" {
		t.Fatalf("got %q", got)
	}
}
