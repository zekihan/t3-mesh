package netwatch

import (
	"context"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

const routeSample = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n" +
	"wlan0\t00000000\t0100A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0\n" +
	"eth0\t00000000\t0200A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n" +
	"eth0\t0000A8C0\t00000000\t0001\t0\t0\t100\t0000FFFF\t0\t0\t0\n"

const arpSample = "IP address       HW type     Flags       HW address            Mask     Device\n" +
	"192.168.0.1      0x1         0x2         aa:bb:cc:dd:ee:01     *        wlan0\n" +
	"192.168.0.2      0x1         0x2         aa:bb:cc:dd:ee:02     *        eth0\n" +
	"192.168.0.3      0x1         0x0         00:00:00:00:00:00     *        eth0\n"

func TestParseProcRoute(t *testing.T) {
	gw, err := parseProcRoute(strings.NewReader(routeSample))
	if err != nil {
		t.Fatal(err)
	}
	if gw.addr != netip.MustParseAddr("192.168.0.2") || gw.iface != "eth0" {
		t.Fatalf("got %+v", gw)
	}
	_, err = parseProcRoute(strings.NewReader("Iface\tDestination\n"))
	if err != ErrNoGateway {
		t.Fatalf("err = %v", err)
	}
}

func TestParseProcARP(t *testing.T) {
	mac, err := parseProcARP(
		strings.NewReader(arpSample),
		netip.MustParseAddr("192.168.0.2"),
		"eth0",
	)
	if err != nil || mac.String() != "aa:bb:cc:dd:ee:02" {
		t.Fatalf("mac=%v err=%v", mac, err)
	}
	mac, err = parseProcARP(
		strings.NewReader(arpSample),
		netip.MustParseAddr("192.168.0.1"),
		"eth0",
	)
	if err != nil || mac.String() != "aa:bb:cc:dd:ee:01" {
		t.Fatalf("fallback mac=%v err=%v", mac, err)
	}
	if _, err = parseProcARP(
		strings.NewReader(arpSample),
		netip.MustParseAddr("192.168.0.3"),
		"",
	); err != ErrNoMAC {
		t.Fatalf("incomplete entry err = %v", err)
	}
	if _, err = parseProcARP(
		strings.NewReader(arpSample),
		netip.MustParseAddr("10.0.0.1"),
		"",
	); err != ErrNoMAC {
		t.Fatalf("missing entry err = %v", err)
	}
}

func TestAddrsIn(t *testing.T) {
	addrs := []netip.Addr{
		netip.MustParseAddr("192.168.1.5"),
		netip.MustParseAddr("10.0.0.5"),
		netip.MustParseAddr("fd12:3456:789a:1::7"),
		netip.MustParseAddr("::ffff:192.168.2.9"),
		netip.MustParseAddr("2001:db8::1"),
	}
	pfx := []netip.Prefix{
		netip.MustParsePrefix("192.168.0.0/22"),
		netip.MustParsePrefix("fd12:3456:789a:1::/64"),
	}
	got := AddrsIn(addrs, pfx)
	want := []string{"192.168.1.5", "fd12:3456:789a:1::7", "192.168.2.9"}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for i := range want {
		if got[i].String() != want[i] {
			t.Fatalf("got %v want %v", got, want)
		}
	}
}

func TestAddrPresentIn(t *testing.T) {
	addrs := []netip.Addr{netip.MustParseAddr("192.168.1.5")}
	if !addrPresentIn(addrs, netip.MustParseAddr("::ffff:192.168.1.5")) {
		t.Fatal("mapped address should match")
	}
	if addrPresentIn(addrs, netip.MustParseAddr("192.168.1.6")) {
		t.Fatal("unexpected match")
	}
}

func TestLocalAddrs(t *testing.T) {
	addrs, err := LocalAddrs()
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range addrs {
		if a.Is4In6() || a.IsLoopback() || a.Zone() != "" {
			t.Fatalf("bad address %v", a)
		}
	}
}

type fakeClock struct {
	mu sync.Mutex
	r  reading
}

func (f *fakeClock) Read() reading {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.r
}

func (f *fakeClock) set(r reading) {
	f.mu.Lock()
	f.r = r
	f.mu.Unlock()
}

func TestSlept(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	prev := reading{Wall: base, Mono: 0}
	if slept(prev, reading{Wall: base.Add(5 * time.Second), Mono: 5 * time.Second}, 5*time.Second) {
		t.Fatal("normal tick flagged")
	}
	if slept(prev, reading{Wall: base.Add(-time.Hour), Mono: 5 * time.Second}, 5*time.Second) {
		t.Fatal("backward jump flagged")
	}
	if !slept(prev, reading{Wall: base.Add(time.Hour), Mono: 5 * time.Second}, 5*time.Second) {
		t.Fatal("sleep not flagged")
	}
}

func recv(t *testing.T, ch <-chan Event, d time.Duration) (Event, bool) {
	t.Helper()
	select {
	case e, ok := <-ch:
		if !ok {
			t.Fatal("channel closed")
		}
		return e, true
	case <-time.After(d):
		return Event{}, false
	}
}

func TestWakeDetectionFakeClock(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	fc := &fakeClock{}
	fc.set(reading{Wall: base})
	tick := make(chan time.Time)
	out := watch(
		ctx,
		nil,
		config{clock: fc, tick: tick, slack: 5 * time.Second, debounce: time.Millisecond},
	)

	step := func(wall, mono time.Duration) {
		fc.set(reading{Wall: base.Add(wall), Mono: mono})
		tick <- time.Time{}
	}
	step(5*time.Second, 5*time.Second)
	if _, ok := recv(t, out, 50*time.Millisecond); ok {
		t.Fatal("unexpected event on normal tick")
	}
	step(3600*time.Second, 10*time.Second)
	e, ok := recv(t, out, time.Second)
	if !ok || e.Kind != EventWake {
		t.Fatalf("want wake, got %+v ok=%v", e, ok)
	}
	step(3605*time.Second, 15*time.Second)
	if _, ok := recv(t, out, 50*time.Millisecond); ok {
		t.Fatal("wake repeated")
	}
}

func TestCoalescing(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	raw := make(chan struct{}, 1)
	out := watch(ctx, nil, config{
		open:     func(context.Context) (<-chan struct{}, error) { return raw, nil },
		clock:    &fakeClock{},
		tick:     make(chan time.Time),
		slack:    time.Second,
		debounce: 50 * time.Millisecond,
	})
	for range 100 {
		raw <- struct{}{}
	}
	e, ok := recv(t, out, time.Second)
	if !ok || e.Kind != EventNetwork {
		t.Fatalf("want network event, got %+v", e)
	}
	if _, ok := recv(t, out, 150*time.Millisecond); ok {
		t.Fatal("burst produced more than one event")
	}
	raw <- struct{}{}
	if _, ok := recv(t, out, time.Second); !ok {
		t.Fatal("no event after second burst")
	}
}

func TestWatchRealSocketCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	out := Watch(ctx, nil)
	cancel()
	deadline := time.After(2 * time.Second)
	for {
		select {
		case _, ok := <-out:
			if !ok {
				return
			}
		case <-deadline:
			t.Fatal("channel not closed after cancel")
		}
	}
}

func TestOpenFailureKeepsWakeDetection(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fc := &fakeClock{}
	tick := make(chan time.Time)
	out := watch(ctx, nil, config{
		open:  func(context.Context) (<-chan struct{}, error) { return nil, ErrNoGateway },
		clock: fc, tick: tick, slack: time.Second,
	})
	tick <- time.Time{} // synchronizes with the initial reading
	fc.set(reading{Wall: time.Date(2026, 1, 1, 1, 0, 0, 0, time.UTC)})
	tick <- time.Time{}
	if e, ok := recv(t, out, time.Second); !ok || e.Kind != EventWake {
		t.Fatalf("got %+v", e)
	}
}
