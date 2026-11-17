//go:build !linux && !darwin

package netwatch

import (
	"context"
	"errors"
	"net"
	"net/netip"
)

func openSource(context.Context) (<-chan struct{}, error) {
	return nil, errors.New(
		"netwatch: network change notifications are not supported on this platform",
	)
}

// DefaultGatewayMAC is not supported on this platform.
func DefaultGatewayMAC() (netip.Addr, net.HardwareAddr, error) {
	return netip.Addr{}, nil, ErrNoGateway
}
