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

	protocolVersion = 0x2
	commandMask     = 0x0F
	versionShift    = 4

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

func (ln *listener) Accept() (net.Conn, error) {
	c, err := ln.Listener.Accept()
	if err != nil {
		//nolint:wrapcheck // transparent net.Listener wrapper; the accept loop inspects net errors
		return nil, err
	}

	return &Conn{inner: c, timeout: ln.headerTimeout}, nil
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
// After an invalid header it returns a placeholder address, never nil.
// It returns nil if the header is invalid.
func (conn *Conn) RemoteAddr() net.Addr {
	err := conn.parse()
	if err != nil {
		return invalidAddr{}
	}

	return conn.remote
}

// Source returns the proxied source address and port. For a LOCAL command it is the
// TCP peer, and it fails if the peer is not TCP.
func (conn *Conn) Source() (netip.AddrPort, error) {
	err := conn.parse()
	if err != nil {
		return netip.AddrPort{}, err
	}

	if !conn.src.IsValid() {
		return netip.AddrPort{}, fmt.Errorf("proxyproto: %w: peer %v", ErrNoSource, conn.remote)
	}

	return conn.src, nil
}

// Read parses the header on first use and then reads the caller's bytes.
func (conn *Conn) Read(buf []byte) (int, error) {
	err := conn.parse()
	if err != nil {
		return 0, err
	}

	//nolint:wrapcheck // transparent net.Conn wrapper; callers compare io.EOF and net errors by identity
	return conn.inner.Read(buf)
}

func (conn *Conn) Write(p []byte) (int, error) {
	//nolint:wrapcheck // transparent net.Conn wrapper; callers compare io.EOF and net errors by identity
	return conn.inner.Write(p)
}

func (conn *Conn) Close() error {
	//nolint:wrapcheck // transparent net.Conn wrapper; callers compare io.EOF and net errors by identity
	return conn.inner.Close()
}

func (conn *Conn) LocalAddr() net.Addr {
	return conn.inner.LocalAddr()
}

// SetDeadline and SetReadDeadline also apply while the header is being parsed: the
// header deadline is the earlier of headerTimeout and the read deadline set here.
func (conn *Conn) SetDeadline(deadline time.Time) error {
	conn.mu.Lock()
	defer conn.mu.Unlock()

	conn.readDeadline = deadline

	//nolint:wrapcheck // transparent net.Conn wrapper; callers compare io.EOF and net errors by identity
	return conn.inner.SetDeadline(deadline)
}

func (conn *Conn) SetReadDeadline(deadline time.Time) error {
	conn.mu.Lock()
	defer conn.mu.Unlock()

	conn.readDeadline = deadline

	//nolint:wrapcheck // transparent net.Conn wrapper; callers compare io.EOF and net errors by identity
	return conn.inner.SetReadDeadline(deadline)
}

func (conn *Conn) SetWriteDeadline(t time.Time) error {
	//nolint:wrapcheck // transparent net.Conn wrapper; callers compare io.EOF and net errors by identity
	return conn.inner.SetWriteDeadline(t)
}

func (conn *Conn) parse() error {
	conn.parseOnce.Do(func() {
		conn.parseErr = conn.readHeader()
	})

	return conn.parseErr
}

func (conn *Conn) readHeader() error {
	conn.mu.Lock()

	headerDeadline := time.Now().Add(conn.timeout)
	if !conn.readDeadline.IsZero() && conn.readDeadline.Before(headerDeadline) {
		headerDeadline = conn.readDeadline
	}
	conn.mu.Unlock()

	err := conn.inner.SetReadDeadline(headerDeadline)
	if err == nil {
		err = conn.parseHeader()
	}

	conn.mu.Lock()
	restoreErr := conn.inner.SetReadDeadline(conn.readDeadline)
	conn.mu.Unlock()

	if err == nil && restoreErr != nil {
		err = fmt.Errorf("proxyproto: restore read deadline: %w", restoreErr)
	}

	if err != nil {
		_ = conn.inner.Close()

		return err
	}

	return nil
}

// parseHeader reads exactly the header bytes from the inner connection.
func (conn *Conn) parseHeader() error {
	var fixed [fixedHeaderSize]byte

	_, err := io.ReadFull(conn.inner, fixed[:])
	if err != nil {
		return fmt.Errorf("proxyproto: read header: %w", err)
	}

	if !bytes.Equal(fixed[:len(signature)], signature[:]) {
		return ErrInvalidSignature
	}

	if version := fixed[12] >> versionShift; version != protocolVersion {
		return fmt.Errorf("%w: %d", ErrUnsupportedVersion, version)
	}

	length := int(binary.BigEndian.Uint16(fixed[14:16]))
	if fixedHeaderSize+length > maxHeaderSize {
		return ErrHeaderTooLarge
	}

	block := make([]byte, length)

	_, err = io.ReadFull(conn.inner, block)
	if err != nil {
		return fmt.Errorf("proxyproto: read header block: %w", err)
	}

	switch command := fixed[12] & commandMask; command {
	case cmdLocal:
		conn.remote = conn.inner.RemoteAddr()
		if ta, ok := conn.remote.(*net.TCPAddr); ok {
			ap := ta.AddrPort()
			conn.src = netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
		}

		return nil
	case cmdProxy:
	default:
		return fmt.Errorf("%w: %d", ErrUnsupportedCommand, command)
	}

	var (
		src  netip.Addr
		port uint16
	)

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

	conn.src = netip.AddrPortFrom(src, port)
	conn.remote = net.TCPAddrFromAddrPort(conn.src)

	return nil
}

// invalidAddr is returned by RemoteAddr when the header is invalid, so callers
// that format the address do not panic. Use Source to detect the failure.
type invalidAddr struct{}

func (invalidAddr) Network() string { return "tcp" }
func (invalidAddr) String() string  { return "invalid-proxy-header" }
