package netwatch

import (
	"fmt"
	"net"
	"net/netip"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

// DefaultGatewayMAC returns the IPv4 default gateway and its MAC address from
// the routing and ARP tables. It returns ErrNoGateway when there is no default
// route and ErrNoMAC (with the gateway address) when the ARP entry is missing.
func DefaultGatewayMAC() (netip.Addr, net.HardwareAddr, error) {
	rib, err := route.FetchRIB(unix.AF_INET, route.RIBTypeRoute, 0)
	if err != nil {
		return netip.Addr{}, nil, fmt.Errorf("fetch routing table: %w", err)
	}

	msgs, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		return netip.Addr{}, nil, fmt.Errorf("parse routing table: %w", err)
	}

	gw, ok := defaultGateway(msgs)
	if !ok {
		return netip.Addr{}, nil, ErrNoGateway
	}

	arp, err := route.FetchRIB(unix.AF_INET, route.RIBType(unix.NET_RT_FLAGS), unix.RTF_LLINFO)
	if err != nil {
		return gw, nil, fmt.Errorf("fetch arp table: %w", err)
	}

	amsgs, err := route.ParseRIB(route.RIBTypeRoute, arp)
	if err != nil {
		return gw, nil, fmt.Errorf("parse arp table: %w", err)
	}

	mac, ok := neighborMAC(amsgs, gw)
	if !ok {
		return gw, nil, ErrNoMAC
	}

	return gw, mac, nil
}

func defaultGateway(msgs []route.Message) (netip.Addr, bool) {
	var scoped netip.Addr

	for _, msg := range msgs {
		rm, ok := msg.(*route.RouteMessage)
		if !ok {
			continue
		}

		addr, ok := defaultRouteGateway(rm)
		if !ok {
			continue
		}

		if rm.Flags&unix.RTF_IFSCOPE != 0 {
			if !scoped.IsValid() {
				scoped = addr
			}

			continue
		}

		return addr, true
	}

	return scoped, scoped.IsValid()
}

// defaultRouteGateway returns the gateway of an up IPv4 default route message.
func defaultRouteGateway(rm *route.RouteMessage) (netip.Addr, bool) {
	if len(rm.Addrs) <= unix.RTAX_GATEWAY {
		return netip.Addr{}, false
	}

	if rm.Flags&unix.RTF_UP == 0 || rm.Flags&unix.RTF_GATEWAY == 0 {
		return netip.Addr{}, false
	}

	dst, ok := rm.Addrs[unix.RTAX_DST].(*route.Inet4Addr)
	if !ok || dst.IP != [4]byte{} {
		return netip.Addr{}, false
	}

	if len(rm.Addrs) > unix.RTAX_NETMASK {
		mask, isInet := rm.Addrs[unix.RTAX_NETMASK].(*route.Inet4Addr)
		if isInet && mask.IP != [4]byte{} {
			return netip.Addr{}, false
		}
	}

	gw, ok := rm.Addrs[unix.RTAX_GATEWAY].(*route.Inet4Addr)
	if !ok || gw.IP == [4]byte{} {
		return netip.Addr{}, false
	}

	return netip.AddrFrom4(gw.IP), true
}

func neighborMAC(msgs []route.Message, gw netip.Addr) (net.HardwareAddr, bool) {
	for _, m := range msgs {
		rm, ok := m.(*route.RouteMessage)
		if !ok || len(rm.Addrs) <= unix.RTAX_GATEWAY {
			continue
		}

		dst, ok := rm.Addrs[unix.RTAX_DST].(*route.Inet4Addr)
		if !ok || netip.AddrFrom4(dst.IP) != gw {
			continue
		}

		ll, ok := rm.Addrs[unix.RTAX_GATEWAY].(*route.LinkAddr)
		if !ok || len(ll.Addr) != 6 || isZeroMAC(ll.Addr) {
			continue
		}

		return net.HardwareAddr(append([]byte(nil), ll.Addr...)), true
	}

	return nil, false
}
