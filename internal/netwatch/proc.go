package netwatch

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

const (
	procRouteFields = 8
	procARPFields   = 6
)

const (
	rtfUp      = 0x1
	rtfGateway = 0x2
	atfCom     = 0x2
)

type procGateway struct {
	addr   netip.Addr
	iface  string
	metric uint64
}

// parseProcRoute returns the IPv4 default route with the lowest metric from
// /proc/net/route content.
func parseProcRoute(r io.Reader) (procGateway, error) {
	sc := bufio.NewScanner(r)

	var best procGateway

	found := false

	first := true
	for sc.Scan() {
		if first {
			first = false

			continue
		}

		cand, ok := parseRouteLine(strings.Fields(sc.Text()))
		if !ok || (found && cand.metric >= best.metric) {
			continue
		}

		best = cand
		found = true
	}

	err := sc.Err()
	if err != nil {
		return procGateway{}, fmt.Errorf("read route table: %w", err)
	}

	if !found {
		return procGateway{}, ErrNoGateway
	}

	return best, nil
}

// parseRouteLine returns the gateway of a usable IPv4 default route line.
func parseRouteLine(fields []string) (procGateway, bool) {
	if len(fields) < procRouteFields {
		return procGateway{}, false
	}

	dst, err1 := strconv.ParseUint(fields[1], 16, 32)
	gw, err2 := strconv.ParseUint(fields[2], 16, 32)
	flags, err3 := strconv.ParseUint(fields[3], 16, 32)
	metric, err4 := strconv.ParseUint(fields[6], 10, 64)

	mask, err5 := strconv.ParseUint(fields[7], 16, 32)
	if err1 != nil || err2 != nil || err3 != nil || err4 != nil || err5 != nil {
		return procGateway{}, false
	}

	if dst != 0 || mask != 0 || flags&rtfUp == 0 || flags&rtfGateway == 0 || gw == 0 {
		return procGateway{}, false
	}

	// The kernel prints the big-endian address as a host-order integer.
	var b [4]byte
	binary.NativeEndian.PutUint32(b[:], uint32(gw))

	return procGateway{addr: netip.AddrFrom4(b), iface: fields[0], metric: metric}, true
}

// parseProcARP finds the complete entry for ip in /proc/net/arp content. When
// iface is non-empty an entry on another device is only used as a fallback.
func parseProcARP(r io.Reader, ip netip.Addr, iface string) (net.HardwareAddr, error) {
	sc := bufio.NewScanner(r)

	var fallback net.HardwareAddr

	first := true
	for sc.Scan() {
		if first {
			first = false

			continue
		}

		fields := strings.Fields(sc.Text())

		mac, ok := arpEntry(fields, ip)
		if !ok {
			continue
		}

		if iface == "" || fields[5] == iface {
			return mac, nil
		}

		if fallback == nil {
			fallback = mac
		}
	}

	err := sc.Err()
	if err != nil {
		return nil, fmt.Errorf("read arp table: %w", err)
	}

	if fallback != nil {
		return fallback, nil
	}

	return nil, ErrNoMAC
}

func isZeroMAC(m net.HardwareAddr) bool {
	for _, b := range m {
		if b != 0 {
			return false
		}
	}

	return true
}

// arpEntry returns the MAC of a complete ARP line for ip.
func arpEntry(fields []string, ip netip.Addr) (net.HardwareAddr, bool) {
	if len(fields) < procARPFields {
		return nil, false
	}

	a, err := netip.ParseAddr(fields[0])
	if err != nil || a != ip {
		return nil, false
	}

	flags, err := strconv.ParseUint(strings.TrimPrefix(fields[2], "0x"), 16, 32)
	if err != nil || flags&atfCom == 0 {
		return nil, false
	}

	mac, err := net.ParseMAC(fields[3])
	if err != nil || isZeroMAC(mac) {
		return nil, false
	}

	return mac, true
}
