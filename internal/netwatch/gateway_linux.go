package netwatch

import (
	"fmt"
	"net"
	"net/netip"
	"os"
)

var (
	procRoutePath = "/proc/net/route"
	procARPPath   = "/proc/net/arp"
)

// DefaultGatewayMAC returns the IPv4 default gateway and its MAC address from
// the ARP table. It returns ErrNoGateway when there is no default route and
// ErrNoMAC (with the gateway address) when the neighbor entry is missing.
func DefaultGatewayMAC() (netip.Addr, net.HardwareAddr, error) {
	rf, err := os.Open(procRoutePath)
	if err != nil {
		return netip.Addr{}, nil, fmt.Errorf("open route table: %w", err)
	}
	defer rf.Close()
	gw, err := parseProcRoute(rf)
	if err != nil {
		return netip.Addr{}, nil, err
	}
	af, err := os.Open(procARPPath)
	if err != nil {
		return gw.addr, nil, fmt.Errorf("open arp table: %w", err)
	}
	defer af.Close()
	mac, err := parseProcARP(af, gw.addr, gw.iface)
	if err != nil {
		return gw.addr, nil, err
	}
	return gw.addr, mac, nil
}
