package proxyproto

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"net"
	"net/netip"
	"testing"
	"time"
)

const ioTimeout = 5 * time.Second

func v2Header(verCmd, fam byte, block []byte) []byte {
	if len(block) > math.MaxUint16 {
		panic("v2Header: block longer than the length field allows")
	}
	h := make([]byte, 0, fixedHeaderSize+len(block))
	h = append(h, signature[:]...)
	h = append(h, verCmd, fam)
	h = binary.BigEndian.AppendUint16(h, uint16(len(block))) //nolint:gosec // bounded by the check above
	return append(h, block...)
}

func inetBlock(src, dst netip.Addr, sport, dport uint16) []byte {
	b := append([]byte{}, src.AsSlice()...)
	b = append(b, dst.AsSlice()...)
	b = binary.BigEndian.AppendUint16(b, sport)
	return binary.BigEndian.AppendUint16(b, dport)
}

func proxyHeader(src, dst netip.AddrPort) []byte {
	if src.Addr().Is4() {
		return v2Header(0x21, 0x11, inetBlock(src.Addr(), dst.Addr(), src.Port(), dst.Port()))
	}
	block := append([]byte{}, src.Addr().AsSlice()...)
	block = append(block, netip.AddrFrom16(dst.Addr().As16()).AsSlice()...)
	block = binary.BigEndian.AppendUint16(block, src.Port())
	block = binary.BigEndian.AppendUint16(block, dst.Port())
	return v2Header(0x21, 0x21, block)
}

func newListener(t *testing.T, headerTimeout time.Duration) net.Listener {
	t.Helper()
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln := Listen(inner, headerTimeout)
	t.Cleanup(func() { _ = ln.Close() })
	return ln
}

func dial(t *testing.T, ln net.Listener) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	_ = c.SetDeadline(time.Now().Add(ioTimeout))
	return c
}

// acceptConn accepts one connection, failing the test if Accept does not return promptly.
func acceptConn(t *testing.T, ln net.Listener) *Conn {
	t.Helper()
	type result struct {
		c   net.Conn
		err error
	}
	ch := make(chan result, 1)
	go func() {
		c, err := ln.Accept()
		ch <- result{c, err}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			t.Fatal(r.err)
		}
		c, ok := r.c.(*Conn)
		if !ok {
			t.Fatalf("Accept returned %T, want *Conn", r.c)
		}
		t.Cleanup(func() { _ = c.Close() })
		return c
	case <-time.After(ioTimeout):
		t.Fatal("Accept blocked")
		return nil
	}
}

func TestProxiedSource(t *testing.T) {
	tests := []struct {
		name string
		src  netip.AddrPort
		want netip.AddrPort
	}{
		{"ipv4", netip.MustParseAddrPort("203.0.113.7:4321"), netip.MustParseAddrPort("203.0.113.7:4321")},
		{"ipv6", netip.MustParseAddrPort("[2001:db8::7]:4321"), netip.MustParseAddrPort("[2001:db8::7]:4321")},
		{"ipv4-mapped ipv6 unmapped", netip.MustParseAddrPort("[::ffff:198.51.100.9]:777"), netip.MustParseAddrPort("198.51.100.9:777")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ln := newListener(t, time.Second)
			client := dial(t, ln)
			dst := netip.MustParseAddrPort("192.168.1.10:8443")
			if _, err := client.Write(proxyHeader(tt.src, dst)); err != nil {
				t.Fatal(err)
			}
			sc := acceptConn(t, ln)

			addr := sc.RemoteAddr()
			if addr == nil || addr.String() != tt.want.String() {
				t.Fatalf("RemoteAddr = %v, want %v", addr, tt.want)
			}
			got, err := sc.Source()
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Fatalf("Source = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRemoteAddrBeforeRead(t *testing.T) {
	ln := newListener(t, time.Second)
	client := dial(t, ln)
	if _, err := client.Write(proxyHeader(netip.MustParseAddrPort("10.0.0.5:1"), netip.MustParseAddrPort("10.0.0.6:2"))); err != nil {
		t.Fatal(err)
	}
	sc := acceptConn(t, ln)
	if got := sc.RemoteAddr().String(); got != "10.0.0.5:1" {
		t.Fatalf("RemoteAddr = %s", got)
	}
}

func TestLocalCommandUsesPeer(t *testing.T) {
	tests := []struct {
		name  string
		block []byte
	}{
		{"unspec no address", nil},
		{"inet block ignored", inetBlock(netip.MustParseAddr("203.0.113.7"), netip.MustParseAddr("10.0.0.1"), 1, 2)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ln := newListener(t, time.Second)
			client := dial(t, ln)
			fam := byte(0x00)
			if tt.block != nil {
				fam = 0x11
			}
			if _, err := client.Write(v2Header(0x20, fam, tt.block)); err != nil {
				t.Fatal(err)
			}
			sc := acceptConn(t, ln)
			if got, want := sc.RemoteAddr().String(), client.LocalAddr().String(); got != want {
				t.Fatalf("RemoteAddr = %s, want peer %s", got, want)
			}
			src, err := sc.Source()
			if err != nil {
				t.Fatal(err)
			}
			if src.String() != client.LocalAddr().String() {
				t.Fatalf("Source = %v, want peer %s", src, client.LocalAddr())
			}
		})
	}
}

func TestMalformedHeadersAreRejected(t *testing.T) {
	src := netip.MustParseAddr("203.0.113.7")
	dst := netip.MustParseAddr("10.0.0.1")
	good := inetBlock(src, dst, 1, 2)

	tests := []struct {
		name    string
		payload []byte
		closeAt bool // client closes its write side after payload, truncating the header
		wantErr error
	}{
		{"bad signature", func() []byte {
			h := v2Header(0x21, 0x11, good)
			h[0] ^= 0xFF
			return h
		}(), false, ErrInvalidSignature},
		{"v1 text header", []byte("PROXY TCP4 203.0.113.7 10.0.0.1 1 2\r\n"), false, ErrInvalidSignature},
		{"no header at all", []byte("GET / HTTP/1.1\r\n\r\n"), false, ErrInvalidSignature},
		{"wrong version", v2Header(0x11, 0x11, good), false, ErrUnsupportedVersion},
		{"unknown command", v2Header(0x22, 0x11, good), false, ErrUnsupportedCommand},
		{"unix stream", v2Header(0x21, 0x31, make([]byte, 216)), false, ErrUnsupportedFamily},
		{"inet dgram", v2Header(0x21, 0x12, good), false, ErrUnsupportedFamily},
		{"inet6 dgram", v2Header(0x21, 0x22, make([]byte, 36)), false, ErrUnsupportedFamily},
		{"unspec proxy", v2Header(0x21, 0x00, nil), false, ErrUnsupportedFamily},
		{"inet block too short", v2Header(0x21, 0x11, good[:4]), false, ErrShortAddress},
		{"inet6 block too short", v2Header(0x21, 0x21, make([]byte, 35)), false, ErrShortAddress},
		{"header too large", append(append([]byte{}, signature[:]...), 0x21, 0x11, 0xFF, 0xFF), false, ErrHeaderTooLarge},
		{"header one byte over 64 KiB", append(append([]byte{}, signature[:]...), 0x21, 0x11, 0xFF, 0xF1), false, ErrHeaderTooLarge},
		{"truncated fixed header", v2Header(0x21, 0x11, good)[:10], true, io.ErrUnexpectedEOF},
		{"truncated address block", v2Header(0x21, 0x11, good)[:20], true, io.ErrUnexpectedEOF},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ln := newListener(t, time.Second)
			client := dial(t, ln)
			if _, err := client.Write(tt.payload); err != nil {
				t.Fatal(err)
			}
			if tt.closeAt {
				closeWrite(t, client)
			}
			sc := acceptConn(t, ln)

			_, err := sc.Read(make([]byte, 16))
			if err == nil {
				t.Fatal("Read succeeded on malformed header")
			}
			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Fatalf("Read error = %v, want %v", err, tt.wantErr)
			}
			if sc.RemoteAddr() != nil {
				t.Fatalf("RemoteAddr = %v after malformed header, want nil", sc.RemoteAddr())
			}
			if _, err := sc.Source(); err == nil {
				t.Fatal("Source succeeded on malformed header")
			}
			assertClosedByServer(t, client)
		})
	}
}

// assertClosedByServer checks that the client sees the connection closed.
func assertClosedByServer(t *testing.T, c net.Conn) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(ioTimeout))
	buf := make([]byte, 1)
	_, err := c.Read(buf)
	if err == nil {
		t.Fatal("connection still open after rejected header")
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		t.Fatal("connection not closed by server")
	}
}

func closeWrite(t *testing.T, c net.Conn) {
	t.Helper()
	tc, ok := c.(*net.TCPConn)
	if !ok {
		t.Fatalf("client is %T, want *net.TCPConn", c)
	}
	if err := tc.CloseWrite(); err != nil {
		t.Fatal(err)
	}
}

func TestTruncatedHeaderFromClientClose(t *testing.T) {
	ln := newListener(t, time.Second)
	client := dial(t, ln)
	if _, err := client.Write(v2Header(0x21, 0x11, inetBlock(netip.MustParseAddr("203.0.113.7"), netip.MustParseAddr("10.0.0.1"), 1, 2))[:12]); err != nil {
		t.Fatal(err)
	}
	closeWrite(t, client)
	sc := acceptConn(t, ln)
	if _, err := sc.Read(make([]byte, 1)); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("Read error = %v, want unexpected EOF", err)
	}
}

func TestTLVsSkipped(t *testing.T) {
	src := netip.MustParseAddrPort("203.0.113.7:4321")
	block := inetBlock(src.Addr(), netip.MustParseAddr("10.0.0.1"), src.Port(), 443)
	block = append(block, 0x01, 0x00, 0x03, 'h', '2', 'x', 0x04, 0x00, 0x00) // ALPN, no-op TLV
	block = append(block, append([]byte{0x20, 0x00, 0x64}, make([]byte, 100)...)...)

	ln := newListener(t, time.Second)
	client := dial(t, ln)
	payload := []byte("after-tlvs")
	if _, err := client.Write(append(v2Header(0x21, 0x11, block), payload...)); err != nil {
		t.Fatal(err)
	}
	sc := acceptConn(t, ln)
	if got := sc.RemoteAddr().String(); got != src.String() {
		t.Fatalf("RemoteAddr = %s, want %s", got, src)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(sc, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload = %q, want %q", got, payload)
	}
}

func TestHeaderSizeBoundary(t *testing.T) {
	src := netip.MustParseAddrPort("203.0.113.7:4321")
	addrs := inetBlock(src.Addr(), netip.MustParseAddr("10.0.0.1"), src.Port(), 443)

	t.Run("exactly 64 KiB accepted", func(t *testing.T) {
		// Address block of 65520 bytes: 12 address bytes, one TLV header, then its value.
		const tlvValue = 65520 - 12 - 3
		block := append([]byte{}, addrs...)
		block = append(block, 0x20, byte(tlvValue>>8), byte(tlvValue&0xFF))
		block = append(block, make([]byte, tlvValue)...)
		ln := newListener(t, time.Second)
		client := dial(t, ln)
		header := v2Header(0x21, 0x11, block)
		go func() { _, _ = client.Write(header) }()
		sc := acceptConn(t, ln)
		if got := sc.RemoteAddr().String(); got != src.String() {
			t.Fatalf("RemoteAddr = %s, want %s", got, src)
		}
	})

	t.Run("65521 bytes rejected", func(t *testing.T) {
		ln := newListener(t, time.Second)
		client := dial(t, ln)
		go func() { _, _ = client.Write(v2Header(0x21, 0x11, make([]byte, 65521))) }()
		sc := acceptConn(t, ln)
		if _, err := sc.Read(make([]byte, 1)); !errors.Is(err, ErrHeaderTooLarge) {
			t.Fatalf("Read error = %v, want %v", err, ErrHeaderTooLarge)
		}
	})
}

func TestDataAfterHeaderPreserved(t *testing.T) {
	// TLS 1.2 record header followed by a fragment, as a ClientHello would begin.
	clientHello := []byte{0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x03}
	large := bytes.Repeat([]byte{0xAB}, 1<<20)

	tests := []struct {
		name   string
		writes [][]byte
		want   []byte
	}{
		{"same write as header", [][]byte{append(v2Header(0x21, 0x11, inetBlock(netip.MustParseAddr("203.0.113.7"), netip.MustParseAddr("10.0.0.1"), 1, 2)), clientHello...)}, clientHello},
		{"separate writes", [][]byte{v2Header(0x21, 0x11, inetBlock(netip.MustParseAddr("203.0.113.7"), netip.MustParseAddr("10.0.0.1"), 1, 2)), clientHello}, clientHello},
		{"large body", [][]byte{v2Header(0x21, 0x21, make([]byte, 36)), large}, large},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ln := newListener(t, time.Second)
			client := dial(t, ln)
			go func() {
				for _, w := range tt.writes {
					if _, err := client.Write(w); err != nil {
						return
					}
				}
			}()
			sc := acceptConn(t, ln)
			got := make([]byte, len(tt.want))
			if _, err := io.ReadFull(sc, got); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, tt.want) {
				t.Fatal("bytes after header were altered or lost")
			}
		})
	}
}

func TestSlowClientDoesNotBlockAccept(t *testing.T) {
	ln := newListener(t, 10*time.Second)

	_ = dial(t, ln) // connects and sends nothing

	fast := dial(t, ln)
	if _, err := fast.Write(proxyHeader(netip.MustParseAddrPort("203.0.113.8:5555"), netip.MustParseAddrPort("10.0.0.1:443"))); err != nil {
		t.Fatal(err)
	}
	if _, err := fast.Write([]byte("hi")); err != nil {
		t.Fatal(err)
	}

	first := acceptConn(t, ln)
	second := acceptConn(t, ln)

	// Both Accept calls return while the first connection is still silent; the second is readable.
	buf := make([]byte, 2)
	_ = second.SetReadDeadline(time.Now().Add(ioTimeout))
	if _, err := io.ReadFull(second, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "hi" {
		t.Fatalf("payload = %q", buf)
	}
	if got := second.RemoteAddr().String(); got != "203.0.113.8:5555" {
		t.Fatalf("RemoteAddr = %s", got)
	}
	_ = first.Close()
}

func TestHeaderTimeoutClosesConnection(t *testing.T) {
	ln := newListener(t, 100*time.Millisecond)
	client := dial(t, ln)
	sc := acceptConn(t, ln)

	start := time.Now()
	_, err := sc.Read(make([]byte, 1))
	if err == nil {
		t.Fatal("Read succeeded without a header")
	}
	var ne net.Error
	if !errors.As(err, &ne) || !ne.Timeout() {
		t.Fatalf("Read error = %v, want timeout", err)
	}
	if elapsed := time.Since(start); elapsed > ioTimeout {
		t.Fatalf("timeout took %v", elapsed)
	}
	assertClosedByServer(t, client)
}

func TestListenDefaultTimeout(t *testing.T) {
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln := Listen(inner, 0)
	t.Cleanup(func() { _ = ln.Close() })
	l, ok := ln.(*listener)
	if !ok || l.headerTimeout != defaultHeaderTimeout {
		t.Fatalf("headerTimeout = %v, want %v", l.headerTimeout, defaultHeaderTimeout)
	}
}
