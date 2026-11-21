package tunnel

import (
	"context"
	"net"
	"testing"
	"testing/synctest"
	"time"
)

func TestJoinTCPStopsWithBlockedBackend(t *testing.T) {
	t.Run("transport close", func(t *testing.T) {
		testJoinTCPStopsWithBlockedBackend(t, false)
	})
	t.Run("context cancel", func(t *testing.T) {
		testJoinTCPStopsWithBlockedBackend(t, true)
	})
}

func testJoinTCPStopsWithBlockedBackend(t *testing.T, cancelContext bool) {
	t.Helper()

	synctest.Test(t, func(t *testing.T) {
		local, backend := net.Pipe()
		defer backend.Close()

		stream, peer := net.Pipe()
		defer peer.Close()

		done := make(chan struct{})

		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()

		go func() {
			JoinTCP(ctx, local, stream)
			close(done)
		}()

		// Send enough records to leave bytes pending in the mesh stream as
		// well as in the local write. The backend never reads or writes.
		go func() {
			for range 2 {
				_, err := peer.Write([]byte{0, 1, 'x'})
				if err != nil {
					return
				}
			}
		}()

		synctest.Wait()

		if cancelContext {
			cancel()
		} else {
			_ = peer.Close()
		}

		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("splice workers still running after shutdown")
		}
	})
}
