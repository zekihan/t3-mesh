package netwatch

import (
	"context"
	"fmt"

	"golang.org/x/sys/unix"
)

// openSource subscribes to NETLINK_ROUTE address, route and link events.
func openSource(ctx context.Context) (<-chan struct{}, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return nil, fmt.Errorf("open netlink socket: %w", err)
	}

	sa := &unix.SockaddrNetlink{
		Family: unix.AF_NETLINK,
		Groups: unix.RTMGRP_LINK | unix.RTMGRP_IPV4_IFADDR | unix.RTMGRP_IPV4_ROUTE |
			unix.RTMGRP_IPV6_IFADDR | unix.RTMGRP_IPV6_ROUTE,
	}

	err = unix.Bind(fd, sa)
	if err != nil {
		_ = unix.Close(fd)

		return nil, fmt.Errorf("bind netlink socket: %w", err)
	}

	return pumpSocket(ctx, fd, "netlink")
}
