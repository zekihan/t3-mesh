package proxyproto

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"net"
	"net/netip"
	"os"
	"testing"
	"testing/synctest"
	"time"
)

const ioTimeout = 5 * time.Second

func v2Header(verCmd, fam byte, block []byte) []byte {
	if len(block) > math.MaxUint16 {
		panic("v2Header: block longer than the length field allows")
	}

	header := make([]byte, 0, fixedHeaderSize+len(block))
	header = append(header, signature[:]...)
	header = append(header, verCmd, fam)
	header = binary.BigEndian.AppendUint16(
		header,
		uint16(len(block)), //nolint:gosec // length checked against math.MaxUint16 above
	)

	return append(header, block...)
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

	var lc net.ListenConfig

	inner, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	ln := Listen(inner, headerTimeout)

	t.Cleanup(func() { _ = ln.Close() })

	return ln
}

func dial(t *testing.T, ln net.Listener) net.Conn {
	t.Helper()

	var dialer net.Dialer

	conn, err := dialer.DialContext(t.Context(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = conn.Close() })

	_ = conn.SetDeadline(time.Now().Add(ioTimeout))

	return conn
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
	case res := <-ch:
		if res.err != nil {
			t.Fatal(res.err)
		}

		wrapped, ok := res.c.(*Conn)
		if !ok {
			t.Fatalf("Accept returned %T, want *Conn", res.c)
		}

		t.Cleanup(func() { _ = wrapped.Close() })

		return wrapped
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
		{
			"ipv4",
			netip.MustParseAddrPort("203.0.113.7:4321"),
			netip.MustParseAddrPort("203.0.113.7:4321"),
		},
		{
			"ipv6",
			netip.MustParseAddrPort("[2001:db8::7]:4321"),
			netip.MustParseAddrPort("[2001:db8::7]:4321"),
		},
		{
			"ipv4-mapped ipv6 unmapped",
			netip.MustParseAddrPort("[::ffff:198.51.100.9]:777"),
			netip.MustParseAddrPort("198.51.100.9:777"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ln := newListener(t, time.Second)
			client := dial(t, ln)

			dst := netip.MustParseAddrPort("192.168.1.10:8443")

			_, err := client.Write(proxyHeader(tt.src, dst))
			if err != nil {
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

	_, err := client.Write(
		proxyHeader(netip.MustParseAddrPort("10.0.0.5:1"), netip.MustParseAddrPort("10.0.0.6:2")),
	)
	if err != nil {
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
		{
			"inet block ignored",
			inetBlock(netip.MustParseAddr("203.0.113.7"), netip.MustParseAddr("10.0.0.1"), 1, 2),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ln := newListener(t, time.Second)
			client := dial(t, ln)

			fam := byte(0x00)
			if tt.block != nil {
				fam = 0x11
			}

			_, err := client.Write(v2Header(0x20, fam, tt.block))
			if err != nil {
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

type malformedCase struct {
	wantErr error
	name    string
	payload []byte
	closeAt bool
}

func malformed(name string, payload []byte, closeAt bool, wantErr error) malformedCase {
	return malformedCase{name: name, payload: payload, closeAt: closeAt, wantErr: wantErr}
}

func TestMalformedHeadersAreRejected(t *testing.T) {
	src := netip.MustParseAddr("203.0.113.7")
	dst := netip.MustParseAddr("10.0.0.1")
	good := inetBlock(src, dst, 1, 2)

	tests := []malformedCase{
		malformed("bad signature", func() []byte {
			h := v2Header(0x21, 0x11, good)
			h[0] ^= 0xFF

			return h
		}(), false, ErrInvalidSignature),
		malformed(
			"v1 text header",
			[]byte("PROXY TCP4 203.0.113.7 10.0.0.1 1 2\r\n"),
			false,
			ErrInvalidSignature,
		),
		malformed("no header at all", []byte("GET / HTTP/1.1\r\n\r\n"), false, ErrInvalidSignature),
		malformed("wrong version", v2Header(0x11, 0x11, good), false, ErrUnsupportedVersion),
		malformed("unknown command", v2Header(0x22, 0x11, good), false, ErrUnsupportedCommand),
		malformed(
			"unix stream",
			v2Header(0x21, 0x31, make([]byte, 216)),
			false,
			ErrUnsupportedFamily,
		),
		malformed("inet dgram", v2Header(0x21, 0x12, good), false, ErrUnsupportedFamily),
		malformed(
			"inet6 dgram",
			v2Header(0x21, 0x22, make([]byte, 36)),
			false,
			ErrUnsupportedFamily,
		),
		malformed("unspec proxy", v2Header(0x21, 0x00, nil), false, ErrUnsupportedFamily),
		malformed("inet block too short", v2Header(0x21, 0x11, good[:4]), false, ErrShortAddress),
		malformed(
			"inet6 block too short",
			v2Header(0x21, 0x21, make([]byte, 35)),
			false,
			ErrShortAddress,
		),
		malformed(
			"header too large",
			append(append([]byte{}, signature[:]...), 0x21, 0x11, 0xFF, 0xFF),
			false,
			ErrHeaderTooLarge,
		),
		malformed(
			"header one byte over 64 KiB",
			append(append([]byte{}, signature[:]...), 0x21, 0x11, 0xFF, 0xF1),
			false,
			ErrHeaderTooLarge,
		),
		malformed(
			"truncated fixed header",
			v2Header(0x21, 0x11, good)[:10],
			true,
			io.ErrUnexpectedEOF,
		),
		malformed(
			"truncated address block",
			v2Header(0x21, 0x11, good)[:20],
			true,
			io.ErrUnexpectedEOF,
		),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ln := newListener(t, time.Second)

			client := dial(t, ln)

			_, err := client.Write(tt.payload)
			if err != nil {
				t.Fatal(err)
			}

			if tt.closeAt {
				closeWrite(t, client)
			}

			sc := acceptConn(t, ln)

			_, err = sc.Read(make([]byte, 16))
			if err == nil {
				t.Fatal("Read succeeded on malformed header")
			}

			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Fatalf("Read error = %v, want %v", err, tt.wantErr)
			}

			if _, ok := sc.RemoteAddr().(invalidAddr); !ok {
				t.Fatalf(
					"RemoteAddr = %v after malformed header, want invalidAddr",
					sc.RemoteAddr(),
				)
			}

			_, err = sc.Source()
			if err == nil {
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

	err := tc.CloseWrite()
	if err != nil {
		t.Fatal(err)
	}
}

func TestTruncatedHeaderFromClientClose(t *testing.T) {
	ln := newListener(t, time.Second)

	client := dial(t, ln)

	_, err := client.Write(
		v2Header(0x21, 0x11, inetBlock(netip.MustParseAddr("203.0.113.7"), netip.MustParseAddr("10.0.0.1"), 1, 2))[:12],
	)
	if err != nil {
		t.Fatal(err)
	}

	closeWrite(t, client)

	sc := acceptConn(t, ln)

	_, err = sc.Read(make([]byte, 1))
	if !errors.Is(err, io.ErrUnexpectedEOF) {
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

	_, err := client.Write(append(v2Header(0x21, 0x11, block), payload...))
	if err != nil {
		t.Fatal(err)
	}

	sc := acceptConn(t, ln)
	if got := sc.RemoteAddr().String(); got != src.String() {
		t.Fatalf("RemoteAddr = %s, want %s", got, src)
	}

	got := make([]byte, len(payload))

	_, err = io.ReadFull(sc, got)
	if err != nil {
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

		_, err := sc.Read(make([]byte, 1))
		if !errors.Is(err, ErrHeaderTooLarge) {
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
		{
			"same write as header",
			[][]byte{
				append(
					v2Header(
						0x21,
						0x11,
						inetBlock(
							netip.MustParseAddr("203.0.113.7"),
							netip.MustParseAddr("10.0.0.1"),
							1,
							2,
						),
					),
					clientHello...,
				),
			},
			clientHello,
		},
		{
			"separate writes",
			[][]byte{
				v2Header(
					0x21,
					0x11,
					inetBlock(
						netip.MustParseAddr("203.0.113.7"),
						netip.MustParseAddr("10.0.0.1"),
						1,
						2,
					),
				),
				clientHello,
			},
			clientHello,
		},
		{"large body", [][]byte{v2Header(0x21, 0x21, make([]byte, 36)), large}, large},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ln := newListener(t, time.Second)
			client := dial(t, ln)

			go func() {
				for _, w := range tt.writes {
					_, err := client.Write(w)
					if err != nil {
						return
					}
				}
			}()

			sc := acceptConn(t, ln)

			got := make([]byte, len(tt.want))

			_, err := io.ReadFull(sc, got)
			if err != nil {
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

	_, err := fast.Write(
		proxyHeader(
			netip.MustParseAddrPort("203.0.113.8:5555"),
			netip.MustParseAddrPort("10.0.0.1:443"),
		),
	)
	if err != nil {
		t.Fatal(err)
	}

	_, err = fast.Write([]byte("hi"))
	if err != nil {
		t.Fatal(err)
	}

	first := acceptConn(t, ln)
	second := acceptConn(t, ln)

	// Both Accept calls return while the first connection is still silent; the second is readable.
	buf := make([]byte, 2)

	_ = second.SetReadDeadline(time.Now().Add(ioTimeout))

	_, err = io.ReadFull(second, buf)
	if err != nil {
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

func TestHeaderTimeoutSurvivesDeadlineChanges(t *testing.T) {
	tests := []struct {
		update func(*Conn) error
		name   string
	}{
		{
			name:   "clear read deadline",
			update: func(conn *Conn) error { return conn.SetReadDeadline(time.Time{}) },
		},
		{
			name: "extend both deadlines",
			update: func(conn *Conn) error {
				return conn.SetDeadline(time.Now().Add(time.Minute))
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				const timeout = time.Second

				server, client := net.Pipe()
				defer server.Close()
				defer client.Close()

				conn := &Conn{inner: server, timeout: timeout}
				parsed := make(chan error, 1)

				go func() {
					_, err := conn.Source()
					parsed <- err
				}()

				synctest.Wait() // Source has set the deadline and is waiting for the header.

				err := tt.update(conn)
				if err != nil {
					t.Fatal(err)
				}

				<-time.After(timeout + time.Nanosecond)
				synctest.Wait()

				select {
				case err := <-parsed:
					if !errors.Is(err, os.ErrDeadlineExceeded) {
						t.Fatalf("Source error = %v, want deadline exceeded", err)
					}
				default:
					t.Fatal("Source still blocked after the header timeout")
				}
			})
		})
	}
}

func TestListenDefaultTimeout(t *testing.T) {
	var lc net.ListenConfig

	inner, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
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
