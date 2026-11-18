package integration

import (
	"bufio"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // RFC 6455 handshake, not a security use
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// A minimal WebSocket client (RFC 6455) for the compatibility test: it sends the
// handshake the way a browser does, over a connection the caller dials, so the
// bytes the proxies see are the ones the apps send.

const (
	wsGUID       = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	wsMaxMessage = 16 << 20

	wsOpText  = 0x1
	wsOpClose = 0x8
	wsOpPing  = 0x9
	wsOpPong  = 0xa

	wsLen16 = 126
	wsLen64 = 127
)

var (
	errWSAccept  = errors.New("wrong Sec-WebSocket-Accept")
	errWSTooBig  = errors.New("message too large")
	errWSBadFram = errors.New("unexpected frame")
)

type wsMessage struct {
	payload []byte
	op      byte
}

type wsConn struct {
	conn net.Conn
	br   *bufio.Reader
}

// upgradeReply is what came back for an upgrade request.
type upgradeReply struct {
	header http.Header
	ws     *wsConn
	body   string
	status int
}

// wsUpgrade sends a WebSocket handshake for target on conn and reads the reply. On
// 101 the reply carries the open connection; any other status carries its body.
func wsUpgrade(
	t *testing.T,
	conn net.Conn,
	host, target string,
	hdr http.Header,
) upgradeReply {
	t.Helper()

	keyRaw := make([]byte, 16)

	_, err := rand.Read(keyRaw)
	if err != nil {
		t.Fatal(err)
	}

	key := base64.StdEncoding.EncodeToString(keyRaw)

	var sb strings.Builder

	sb.WriteString("GET " + target + " HTTP/1.1\r\nHost: " + host + "\r\n" +
		"Connection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\n" +
		"Sec-WebSocket-Key: " + key + "\r\n")
	_ = hdr.Write(&sb)
	sb.WriteString("\r\n")

	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))

	_, err = io.WriteString(conn, sb.String())
	if err != nil {
		t.Fatalf("write upgrade request: %v", err)
	}

	br := bufio.NewReader(conn)

	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read upgrade reply: %v", err)
	}

	defer func() { _ = resp.Body.Close() }()

	reply := upgradeReply{status: resp.StatusCode, header: resp.Header}

	if resp.StatusCode != http.StatusSwitchingProtocols {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
		reply.body = string(body)

		return reply
	}

	sum := sha1.Sum([]byte(key + wsGUID)) //nolint:gosec // RFC 6455 handshake

	if resp.Header.Get("Sec-WebSocket-Accept") != base64.StdEncoding.EncodeToString(sum[:]) {
		t.Fatalf("101 reply: %v (%v)", errWSAccept, resp.Header)
	}

	reply.ws = &wsConn{conn: conn, br: br}

	return reply
}

// send writes one masked frame.
func (ws *wsConn) send(op byte, payload []byte) error {
	hdr := []byte{0x80 | op}

	switch size := len(payload); {
	case size < wsLen16:
		hdr = append(hdr, 0x80|byte(size))
	case size <= 0xffff:
		hdr = append(hdr, 0x80|wsLen16)
		hdr = binary.BigEndian.AppendUint16(hdr, uint16(size))
	default:
		hdr = append(hdr, 0x80|wsLen64)
		hdr = binary.BigEndian.AppendUint64(hdr, uint64(size))
	}

	mask := make([]byte, 4)

	_, err := rand.Read(mask)
	if err != nil {
		return fmt.Errorf("mask: %w", err)
	}

	hdr = append(hdr, mask...)

	masked := make([]byte, len(payload))
	for i, b := range payload {
		masked[i] = b ^ mask[i%4]
	}

	_ = ws.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))

	_, err = ws.conn.Write(append(hdr, masked...))
	if err != nil {
		return fmt.Errorf("write frame: %w", err)
	}

	return nil
}

// frame reads one frame.
func (ws *wsConn) frame() (byte, bool, []byte, error) {
	var head [2]byte

	_, err := io.ReadFull(ws.br, head[:])
	if err != nil {
		return 0, false, nil, fmt.Errorf("read frame header: %w", err)
	}

	size := uint64(head[1] & 0x7f)

	switch size {
	case wsLen16:
		var ext [2]byte

		_, err = io.ReadFull(ws.br, ext[:])
		size = uint64(binary.BigEndian.Uint16(ext[:]))
	case wsLen64:
		var ext [8]byte

		_, err = io.ReadFull(ws.br, ext[:])
		size = binary.BigEndian.Uint64(ext[:])
	}

	if err != nil {
		return 0, false, nil, fmt.Errorf("read frame length: %w", err)
	}

	if size > wsMaxMessage || head[1]&0x80 != 0 {
		return 0, false, nil, fmt.Errorf(
			"%w: %d bytes, masked %v",
			errWSBadFram,
			size,
			head[1]&0x80 != 0,
		)
	}

	payload := make([]byte, size)

	_, err = io.ReadFull(ws.br, payload)
	if err != nil {
		return 0, false, nil, fmt.Errorf("read frame payload: %w", err)
	}

	return head[0] & 0x0f, head[0]&0x80 != 0, payload, nil
}

// next returns the next whole message, reassembling fragments and answering pings.
// A pong or a close is returned as such.
func (ws *wsConn) next(wait time.Duration) (wsMessage, error) {
	_ = ws.conn.SetReadDeadline(time.Now().Add(wait))

	var (
		data   []byte
		dataOp byte
	)

	for {
		op, fin, payload, err := ws.frame()
		if err != nil {
			return wsMessage{}, err
		}

		switch op {
		case wsOpPing:
			err = ws.send(wsOpPong, payload)
			if err != nil {
				return wsMessage{}, err
			}

			continue
		case wsOpPong, wsOpClose:
			return wsMessage{op: op, payload: payload}, nil
		case 0: // continuation
		default:
			dataOp = op
		}

		data = append(data, payload...)

		if len(data) > wsMaxMessage {
			return wsMessage{}, errWSTooBig
		}

		if fin {
			return wsMessage{op: dataOp, payload: data}, nil
		}
	}
}

// close sends a close frame and expects T3 to answer with one.
func (ws *wsConn) close() error {
	err := ws.send(wsOpClose, []byte{0x03, 0xe8})
	if err != nil {
		return err
	}

	for {
		msg, err := ws.next(5 * time.Second)
		if err != nil {
			return err
		}

		if msg.op == wsOpClose {
			return nil
		}
	}
}
