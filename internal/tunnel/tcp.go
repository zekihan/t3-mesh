package tunnel

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

const (
	tcpRecordHeader = 2
	tcpRecordData   = 16 << 10
	tcpEndEvents    = 3
)

// JoinTCP carries one TCP connection over a mesh stream. A length-prefixed
// record with zero length is a write-side EOF. The transport stays open until
// both sides send EOF so yamux's stream-close timer cannot cut a half-open TCP
// connection, and a transport close before both EOFs can abort the connection.
func JoinTCP(local, stream net.Conn) {
	// The reader reports the peer's EOF, then watches for a transport close
	// while the local side can still send. Neither worker waits on the other.
	ends := make(chan bool, tcpEndEvents)

	var wg sync.WaitGroup

	wg.Go(func() { ends <- sendTCP(local, stream) })
	wg.Go(func() {
		ok := receiveTCP(stream, local)
		ends <- ok

		if ok {
			var extra [1]byte

			//nolint:errcheck // any data or close after EOF ends the stream
			_, _ = io.ReadFull(stream, extra[:])

			ends <- false
		}
	})

	if <-ends {
		<-ends
	}

	_ = local.Close()
	_ = stream.SetDeadline(time.Now()) //nolint:errcheck // unblock the yamux reader before Close
	_ = stream.Close()

	wg.Wait()
}

func sendTCP(local io.Reader, stream io.Writer) bool {
	var record [tcpRecordHeader + tcpRecordData]byte

	for {
		size, err := local.Read(record[tcpRecordHeader:])
		if size > 0 {
			binary.BigEndian.PutUint16(
				record[:tcpRecordHeader],
				uint16(size), //nolint:gosec // bounded by tcpRecordData
			)

			_, writeErr := stream.Write(record[:tcpRecordHeader+size])
			if writeErr != nil {
				return false
			}
		}

		if err != nil {
			if !errors.Is(err, io.EOF) {
				return false
			}

			clear(record[:tcpRecordHeader])
			_, err = stream.Write(record[:tcpRecordHeader])

			return err == nil
		}
	}
}

func receiveTCP(stream io.Reader, local net.Conn) bool {
	var record [tcpRecordData]byte

	for {
		_, err := io.ReadFull(stream, record[:tcpRecordHeader])
		if err != nil {
			return false
		}

		size := int(binary.BigEndian.Uint16(record[:tcpRecordHeader]))
		if size == 0 {
			cw, ok := local.(closeWriter)

			return ok && cw.CloseWrite() == nil
		}

		if size > len(record) {
			return false
		}

		_, err = io.ReadFull(stream, record[:size])
		if err != nil {
			return false
		}

		_, err = local.Write(record[:size])
		if err != nil {
			return false
		}
	}
}
