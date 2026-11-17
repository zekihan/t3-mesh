package netwatch

import (
	"fmt"
	"net"
	"net/netip"
	"slices"
)

// LocalAddrs returns the unicast addresses configured on up interfaces.
// Loopback, multicast and unspecified addresses are excluded; zones are dropped
// and IPv4-mapped addresses are unmapped.
func LocalAddrs() ([]netip.Addr, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("list interfaces: %w", err)
	}

	var out []netip.Addr

	for _, ifi := range ifs {
		if ifi.Flags&net.FlagUp == 0 {
			continue
		}

		addrs, err := ifi.Addrs()
		if err != nil {
			return nil, fmt.Errorf("addresses of %s: %w", ifi.Name, err)
		}

		for _, a := range addrs {
			var ip net.IP

			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			default:
				continue
			}

			addr, ok := netip.AddrFromSlice(ip)
			if !ok {
				continue
			}

			addr = addr.Unmap().WithZone("")
			if addr.IsLoopback() || addr.IsMulticast() || addr.IsUnspecified() {
				continue
			}

			out = append(out, addr)
		}
	}

	return out, nil
}

// AddrPresent reports whether a is currently a local address.
func AddrPresent(a netip.Addr) bool {
	addrs, err := LocalAddrs()
	if err != nil {
		return false
	}

	return addrPresentIn(addrs, a)
}

func addrPresentIn(addrs []netip.Addr, a netip.Addr) bool {
	a = a.Unmap().WithZone("")

	return slices.Contains(addrs, a)
}

// AddrsIn returns the addresses of addrs that lie inside any of prefixes.
func AddrsIn(addrs []netip.Addr, prefixes []netip.Prefix) []netip.Addr {
	var out []netip.Addr

	for _, a := range addrs {
		a = a.Unmap()
		for _, p := range prefixes {
			if p.Contains(a.WithZone("")) {
				out = append(out, a)

				break
			}
		}
	}

	return out
}
