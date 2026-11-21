package proxyproto

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"runtime"
	"testing"
	"time"
)

type fuzzConn struct{ *bytes.Reader }

func (c *fuzzConn) Write(p []byte) (int, error) { return len(p), nil }
func (c *fuzzConn) Close() error                { return nil }
func (c *fuzzConn) LocalAddr() net.Addr         { return &net.TCPAddr{} }

func (c *fuzzConn) RemoteAddr() net.Addr             { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234} }
func (c *fuzzConn) SetDeadline(time.Time) error      { return nil }
func (c *fuzzConn) SetReadDeadline(time.Time) error  { return nil }
func (c *fuzzConn) SetWriteDeadline(time.Time) error { return nil }

func FuzzProxyHeader(f *testing.F) {
	f.Add(
		proxyHeader(
			netip.MustParseAddrPort("203.0.113.7:4321"),
			netip.MustParseAddrPort("192.168.1.10:8443"),
		),
	)
	f.Add(
		proxyHeader(
			netip.MustParseAddrPort("[2001:db8::7]:4321"),
			netip.MustParseAddrPort("[2001:db8::1]:8443"),
		),
	)
	f.Add(v2Header(0x20, 0, nil))
	f.Add([]byte("invalid"))
	f.Fuzz(func(t *testing.T, data []byte) {
		var before runtime.MemStats
		runtime.ReadMemStats(&before)

		defer func() {
			var after runtime.MemStats
			runtime.ReadMemStats(&after)

			if after.TotalAlloc-before.TotalAlloc > 64<<20 {
				t.Fatalf("parser allocated more than 64 MiB")
			}
		}()

		if len(data) > 1<<17 {
			t.Skip()
		}

		const tail = "payload after header"

		input := append(bytes.Clone(data), []byte(tail)...)
		raw := &fuzzConn{bytes.NewReader(input)}
		conn := &Conn{inner: raw, timeout: time.Second}
		source, err := conn.Source()

		source2, err2 := conn.Source()
		if (err == nil) != (err2 == nil) || source != source2 {
			t.Fatal("inconsistent source")
		}

		if err != nil {
			if conn.RemoteAddr().String() != "invalid-proxy-header" {
				t.Fatal("invalid header exposed peer")
			}

			return
		}

		if !source.IsValid() || conn.RemoteAddr().String() != source.String() {
			t.Fatalf("inconsistent address: %v %v", source, conn.RemoteAddr())
		}

		length := int(binary.BigEndian.Uint16(input[14:16]))

		consumed := fixedHeaderSize + length
		if consumed > maxHeaderSize || consumed > len(input) {
			t.Fatal("accepted oversized or truncated header")
		}

		remaining, readErr := io.ReadAll(conn)
		if readErr != nil || !bytes.Equal(remaining, input[consumed:]) {
			t.Fatal("header parser consumed payload")
		}
	})
}
