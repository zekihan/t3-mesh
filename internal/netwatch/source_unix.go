//go:build linux || darwin

package netwatch

import (
	"context"
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

const (
	readBufferSize = 64 << 10
)

// pumpSocket turns a raw routing socket into a channel of notifications. The
// message contents are ignored: any message means "something changed".
func pumpSocket(ctx context.Context, fd int, name string) (<-chan struct{}, error) {
	err := unix.SetNonblock(fd, true)
	if err != nil {
		_ = unix.Close(fd)

		return nil, fmt.Errorf("set nonblocking: %w", err)
	}

	file := os.NewFile(uintptr(fd), name) // registers with the poller, so Close unblocks Read
	out := make(chan struct{}, 1)

	go func() {
		<-ctx.Done()

		_ = file.Close()
	}()
	go func() {
		defer close(out)

		buf := make([]byte, readBufferSize)
		for {
			_, err := file.Read(buf)
			// ENOBUFS means events were dropped, which is still a change.
			if err != nil && !errors.Is(err, unix.ENOBUFS) && !errors.Is(err, unix.EINTR) {
				return
			}

			select {
			case out <- struct{}{}:
			default:
			}
		}
	}()

	return out, nil
}
