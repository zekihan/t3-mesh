package netwatch

import (
	"context"
	"fmt"

	"golang.org/x/sys/unix"
)

// openSource opens an AF_ROUTE socket, which reports address, route and
// interface changes.
func openSource(ctx context.Context) (<-chan struct{}, error) {
	fd, err := unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW, unix.AF_UNSPEC)
	if err != nil {
		return nil, fmt.Errorf("open route socket: %w", err)
	}
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_SETFD, unix.FD_CLOEXEC); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("set close-on-exec: %w", err)
	}
	return pumpSocket(ctx, fd, "route")
}
