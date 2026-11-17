// Package proxyproto wraps a net.Listener so that every accepted connection must
// begin with a PROXY protocol version 2 header, as sent by Traefik to the hub.
//
// Design: Accept does not read from the connection. It returns a *Conn at once and
// the header is parsed lazily on the first Read, RemoteAddr or Source call, under a
// deadline of headerTimeout that starts at that call. A silent client therefore
// holds only its own connection and goroutine, never the accept loop. Parsing reads
// exactly the header bytes (the 16-byte fixed part, then the declared address and
// TLV block), so bytes after the header stay readable by the caller, for example
// a TLS ClientHello.
//
// A missing, malformed or unsupported header closes the underlying connection and
// makes Read return an error. RemoteAddr and Source then fail as well; the TCP peer
// address is never used as a fallback for PROXY commands.
package proxyproto

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"
)

const (
	defaultHeaderTimeout = 5 * time.Second
	maxHeaderSize        = 64 << 10
	fixedHeaderSize      = 16
	ipv4BlockSize        = 12
	ipv6BlockSize        = 36

	cmdLocal = 0x0
	cmdProxy = 0x1

	famInet      = 0x1
	famInet6     = 0x2
	protoStream  = 0x1
	famInetStrm  = famInet<<4 | protoStream
	famInet6Strm = famInet6<<4 | protoStream
)

var signature = [12]byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}

var (
	ErrInvalidSignature   = errors.New("invalid PROXY v2 signature")
	ErrUnsupportedVersion = errors.New("unsupported PROXY protocol version")
	ErrUnsupportedCommand = errors.New("unsupported PROXY command")
	ErrUnsupportedFamily  = errors.New("unsupported PROXY address family or protocol")
	ErrShortAddress       = errors.New("PROXY address block too short")
	ErrHeaderTooLarge     = errors.New("PROXY header exceeds 64 KiB")
	ErrNoSource           = errors.New("no source address available")
)

// Listen wraps inner. Accept returns connections whose RemoteAddr is the source
// address from the PROXY header. The header must arrive within headerTimeout; a
// non-positive value selects 5 seconds.
func Listen(inner net.Listener, headerTimeout time.Duration) net.Listener {
	if headerTimeout <= 0 {
		headerTimeout = defaultHeaderTimeout
	}
	return &listener{Listener: inner, headerTimeout: headerTimeout}
}

type listener struct {
	net.Listener
	headerTimeout time.Duration
}

func (l *listener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &Conn{inner: c, timeout: l.headerTimeout}, nil
}

// Conn is a connection whose PROXY v2 header is parsed on first use. For a PROXY
// command RemoteAddr and Source report the proxied source. For a LOCAL command
// (Traefik health checks) they report the real TCP peer.
type Conn struct {
	inner    net.Conn
	remote   net.Addr
	parseErr error

	readDeadline time.Time
	src          netip.AddrPort
	timeout      time.Duration

	parseOnce sync.Once
	mu        sync.Mutex
}

// RemoteAddr returns the proxied source address, parsing the header if needed.
// It returns nil if the header is invalid.
func (c *Conn) RemoteAddr() net.Addr {
	if err := c.parse(); err != nil {
		return nil
	}
	return c.remote
}

// Source returns the proxied source address and port. For a LOCAL command it is the
// TCP peer, and it fails if the peer is not TCP.
func (c *Conn) Source() (netip.AddrPort, error) {
	if err := c.parse(); err != nil {
		return netip.AddrPort{}, err
	}
	if !c.src.IsValid() {
		return netip.AddrPort{}, fmt.Errorf("proxyproto: %w: peer %v", ErrNoSource, c.remote)
	}
	return c.src, nil
}

// Read parses the header on first use and then reads the caller's bytes.
func (c *Conn) Read(p []byte) (int, error) {
	if err := c.parse(); err != nil {
		return 0, err
	}
	return c.inner.Read(p)
}

func (c *Conn) Write(p []byte) (int, error) {
	return c.inner.Write(p)
}

func (c *Conn) Close() error {
	return c.inner.Close()
}

func (c *Conn) LocalAddr() net.Addr {
	return c.inner.LocalAddr()
}

// SetDeadline and SetReadDeadline also apply while the header is being parsed: the
// header deadline is the earlier of headerTimeout and the read deadline set here.
func (c *Conn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readDeadline = t
	return c.inner.SetDeadline(t)
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readDeadline = t
	return c.inner.SetReadDeadline(t)
}

func (c *Conn) SetWriteDeadline(t time.Time) error {
	return c.inner.SetWriteDeadline(t)
}

func (c *Conn) parse() error {
	c.parseOnce.Do(func() {
		c.parseErr = c.readHeader()
	})
	return c.parseErr
}

func (c *Conn) readHeader() error {
	c.mu.Lock()
	headerDeadline := time.Now().Add(c.timeout)
	if !c.readDeadline.IsZero() && c.readDeadline.Before(headerDeadline) {
		headerDeadline = c.readDeadline
	}
	c.mu.Unlock()

	err := c.inner.SetReadDeadline(headerDeadline)
	if err == nil {
		err = c.parseHeader()
	}

	c.mu.Lock()
	restoreErr := c.inner.SetReadDeadline(c.readDeadline)
	c.mu.Unlock()
	if err == nil && restoreErr != nil {
		err = fmt.Errorf("proxyproto: restore read deadline: %w", restoreErr)
	}

	if err != nil {
		_ = c.inner.Close()
		return err
	}
	return nil
}

// parseHeader reads exactly the header bytes from the inner connection.
func (c *Conn) parseHeader() error {
	var fixed [fixedHeaderSize]byte
	if _, err := io.ReadFull(c.inner, fixed[:]); err != nil {
		return fmt.Errorf("proxyproto: read header: %w", err)
	}
	if !bytes.Equal(fixed[:len(signature)], signature[:]) {
		return ErrInvalidSignature
	}
	if version := fixed[12] >> 4; version != 2 {
		return fmt.Errorf("%w: %d", ErrUnsupportedVersion, version)
	}
	length := int(binary.BigEndian.Uint16(fixed[14:16]))
	if fixedHeaderSize+length > maxHeaderSize {
		return ErrHeaderTooLarge
	}
	block := make([]byte, length)
	if _, err := io.ReadFull(c.inner, block); err != nil {
		return fmt.Errorf("proxyproto: read header block: %w", err)
	}

	switch command := fixed[12] & 0x0F; command {
	case cmdLocal:
		c.remote = c.inner.RemoteAddr()
		if ta, ok := c.remote.(*net.TCPAddr); ok {
			ap := ta.AddrPort()
			c.src = netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
		}
		return nil
	case cmdProxy:
	default:
		return fmt.Errorf("%w: %d", ErrUnsupportedCommand, command)
	}

	var src netip.Addr
	var port uint16
	switch fixed[13] {
	case famInetStrm:
		if length < ipv4BlockSize {
			return ErrShortAddress
		}
		src = netip.AddrFrom4([4]byte(block[0:4]))
		port = binary.BigEndian.Uint16(block[8:10])
	case famInet6Strm:
		if length < ipv6BlockSize {
			return ErrShortAddress
		}
		src = netip.AddrFrom16([16]byte(block[0:16])).Unmap()
		port = binary.BigEndian.Uint16(block[32:34])
	default:
		return fmt.Errorf("%w: %#x", ErrUnsupportedFamily, fixed[13])
	}

	c.src = netip.AddrPortFrom(src, port)
	c.remote = net.TCPAddrFromAddrPort(c.src)
	return nil
}
