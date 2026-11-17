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
		f := strings.Fields(sc.Text())
		if len(f) < 8 {
			continue
		}
		dst, err1 := strconv.ParseUint(f[1], 16, 32)
		gw, err2 := strconv.ParseUint(f[2], 16, 32)
		flags, err3 := strconv.ParseUint(f[3], 16, 32)
		metric, err4 := strconv.ParseUint(f[6], 10, 64)
		mask, err5 := strconv.ParseUint(f[7], 16, 32)
		if err1 != nil || err2 != nil || err3 != nil || err4 != nil || err5 != nil {
			continue
		}
		if dst != 0 || mask != 0 || flags&rtfUp == 0 || flags&rtfGateway == 0 || gw == 0 {
			continue
		}
		if found && metric >= best.metric {
			continue
		}
		// The kernel prints the big-endian address as a host-order integer.
		var b [4]byte
		binary.NativeEndian.PutUint32(b[:], uint32(gw))
		best = procGateway{addr: netip.AddrFrom4(b), iface: f[0], metric: metric}
		found = true
	}
	if err := sc.Err(); err != nil {
		return procGateway{}, fmt.Errorf("read route table: %w", err)
	}
	if !found {
		return procGateway{}, ErrNoGateway
	}
	return best, nil
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
		f := strings.Fields(sc.Text())
		if len(f) < 6 {
			continue
		}
		a, err := netip.ParseAddr(f[0])
		if err != nil || a != ip {
			continue
		}
		flags, err := strconv.ParseUint(strings.TrimPrefix(f[2], "0x"), 16, 32)
		if err != nil || flags&atfCom == 0 {
			continue
		}
		mac, err := net.ParseMAC(f[3])
		if err != nil || isZeroMAC(mac) {
			continue
		}
		if iface == "" || f[5] == iface {
			return mac, nil
		}
		if fallback == nil {
			fallback = mac
		}
	}
	if err := sc.Err(); err != nil {
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
