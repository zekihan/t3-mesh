package main

import (
	"errors"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"slices"
	"strconv"

	"golang.org/x/sys/unix"

	"github.com/zekihan/t3-mesh/internal/agent"
	"github.com/zekihan/t3-mesh/internal/agent/agentconfig"
	"github.com/zekihan/t3-mesh/internal/netwatch"
)

func checkPorts(cfg *agentconfig.Config, status *agent.LocalStatus) []doctorCheck {
	checks := make([]doctorCheck, 0, len(cfg.Links))
	for _, name := range slices.Sorted(maps.Keys(cfg.Links)) {
		checks = append(checks, checkLinkPort(name, cfg.Links[name], status))
	}

	if !cfg.Direct.Enabled {
		return checks
	}

	addrs, err := netwatch.LocalAddrs()
	if err != nil {
		return append(checks, checkResult("direct/device ports", "", err))
	}

	var ips []net.IP

	for _, addr := range addrs {
		if addr.IsGlobalUnicast() && !addr.IsLoopback() {
			ips = append(ips, addr.Unmap().AsSlice())
		}
	}

	var directOwned []netip.AddrPort
	if status != nil {
		directOwned = status.DirectListeners
	}

	checks = append(checks, listenerPortResult("direct", cfg.Direct.Port, directOwned, ips))

	if cfg.Direct.Devices.Enabled {
		checks = append(
			checks,
			listenerPortResult("device", cfg.Direct.Devices.Port, deviceEndpoints(status), ips),
		)
	}

	return checks
}

func deviceEndpoints(status *agent.LocalStatus) []netip.AddrPort {
	if status == nil || status.Report.DeviceListener == nil {
		return nil
	}

	listener := status.Report.DeviceListener
	if listener.Port <= 0 || listener.Port > 65535 {
		return nil
	}

	var endpoints []netip.AddrPort

	for _, raw := range listener.Addrs {
		addr, err := netip.ParseAddr(raw)
		if err == nil {
			endpoints = append(endpoints, netip.AddrPortFrom(addr.Unmap(), uint16(listener.Port)))
		}
	}

	return endpoints
}

func checkLinkPort(name, target string, status *agent.LocalStatus) doctorCheck {
	_, rawPort, err := net.SplitHostPort(target)
	if err != nil {
		return checkResult("link "+name, "", err)
	}

	port, err := strconv.Atoi(rawPort)
	if err != nil {
		return checkResult("link "+name, "", err)
	}

	owned := status != nil && slices.ContainsFunc(status.Links, func(link agent.LinkStatus) bool {
		return link.Name == name && link.Port == port && link.Bound
	})

	return portResult("link "+name, port, owned, []net.IP{net.ParseIP("127.0.0.1")})
}

func portResult(name string, port int, owned bool, addrs []net.IP) doctorCheck {
	if owned {
		return checkResult(name, fmt.Sprintf("port %d bound by the agent", port), nil)
	}

	for _, addr := range addrs {
		err := testPort(addr, port)
		if err != nil {
			return checkResult(name, "", fmt.Errorf("port %d on %s: %w", port, addr, err))
		}
	}

	return checkResult(name, fmt.Sprintf("port %d available", port), nil)
}

func listenerPortResult(name string, port int, owned []netip.AddrPort, addrs []net.IP) doctorCheck {
	for _, ip := range addrs {
		addr, ok := netip.AddrFromSlice(ip)
		if ok && slices.ContainsFunc(owned, func(endpoint netip.AddrPort) bool {
			return endpoint.Addr().Unmap() == addr.Unmap() && int(endpoint.Port()) == port
		}) {
			continue
		}

		err := testPort(ip, port)
		if err != nil {
			return checkResult(name, "", fmt.Errorf("port %d on %s: %w", port, ip, err))
		}
	}

	return checkResult(name, fmt.Sprintf("port %d available or bound by the agent", port), nil)
}

func testPort(addr net.IP, port int) error {
	var endpoint unix.Sockaddr

	family := unix.AF_INET6
	if ipv4 := addr.To4(); ipv4 != nil {
		family = unix.AF_INET
		endpoint = &unix.SockaddrInet4{Port: port, Addr: [4]byte(ipv4)}
	} else {
		endpoint = &unix.SockaddrInet6{Port: port, Addr: [16]byte(addr.To16())}
	}

	fd, err := unix.Socket(family, unix.SOCK_STREAM, unix.IPPROTO_TCP)
	if family == unix.AF_INET6 && errors.Is(err, unix.EAFNOSUPPORT) {
		return nil
	}

	if err != nil {
		return fmt.Errorf("inspect TCP port: %w", err)
	}

	defer unix.Close(fd)

	err = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
	if err != nil {
		return fmt.Errorf("set TCP probe options: %w", err)
	}

	err = unix.Bind(fd, endpoint)
	if family == unix.AF_INET6 && errors.Is(err, unix.EADDRNOTAVAIL) {
		return nil
	}

	if err != nil {
		return fmt.Errorf("bind TCP probe: %w", err)
	}

	return nil
}
