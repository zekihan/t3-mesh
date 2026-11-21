package tunnel

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/hashicorp/yamux"
)

const (
	tcpRecordHeader = 2
	tcpRecordData   = 16 << 10
	tcpRecordAck    = 0xffff
	tcpRecordWindow = 64
	tcpDirections   = 2
)

// JoinTCP carries one TCP connection over a mesh stream. A zero-length record
// is a write-side EOF, and each data or EOF record consumes a credit until the
// receiver applies it to its local socket. The window keeps the stream reader
// independent of a blocked local write so it can always observe a transport
// close, with bounded memory.
func JoinTCP(ctx context.Context, local, stream net.Conn) {
	records := make(chan []byte, tcpRecordWindow)
	credits := make(chan struct{}, tcpRecordWindow)

	for range tcpRecordWindow {
		credits <- struct{}{}
	}

	ctx, cancel := context.WithCancel(ctx)
	writer := &tcpRecordWriter{stream: stream}
	ends := make(chan bool, tcpDirections+1)

	var closed <-chan struct{}
	if st, ok := stream.(*yamux.Stream); ok {
		closed = st.Session().CloseChan()
	}

	var wg sync.WaitGroup

	wg.Go(func() {
		readTCP(stream, records, credits)

		ends <- false
	})
	wg.Go(func() { ends <- sendTCP(ctx, local, writer, credits) })
	wg.Go(func() { ends <- receiveTCP(ctx, records, local, writer) })

	waitTCP(ctx, ends, closed)
	cancel()

	_ = local.Close()
	_ = stream.SetDeadline(time.Now()) //nolint:errcheck // unblock yamux before Close
	_ = stream.Close()

	wg.Wait()
}

func waitTCP(ctx context.Context, ends <-chan bool, closed <-chan struct{}) {
	for range tcpDirections {
		select {
		case <-ctx.Done():
			return
		case <-closed:
			return
		case complete := <-ends:
			if !complete {
				return
			}
		}
	}
}

type tcpRecordWriter struct {
	stream io.Writer
	mu     sync.Mutex
}

func (w *tcpRecordWriter) write(record []byte) bool {
	w.mu.Lock()
	defer w.mu.Unlock()

	_, err := w.stream.Write(record)

	return err == nil
}

func (w *tcpRecordWriter) ack() bool {
	var header [tcpRecordHeader]byte

	binary.BigEndian.PutUint16(header[:], tcpRecordAck)

	return w.write(header[:])
}

func takeCredit(ctx context.Context, credits <-chan struct{}) bool {
	select {
	case <-credits:
		return true
	case <-ctx.Done():
		return false
	}
}

func sendTCP(
	ctx context.Context,
	local io.Reader,
	writer *tcpRecordWriter,
	credits <-chan struct{},
) bool {
	var record [tcpRecordHeader + tcpRecordData]byte

	for takeCredit(ctx, credits) {
		size, err := local.Read(record[tcpRecordHeader:])
		if size > 0 {
			binary.BigEndian.PutUint16(
				record[:tcpRecordHeader],
				uint16(size), //nolint:gosec // bounded by tcpRecordData
			)

			if !writer.write(record[:tcpRecordHeader+size]) {
				return false
			}
		}

		if err == nil {
			continue
		}

		if !errors.Is(err, io.EOF) || (size > 0 && !takeCredit(ctx, credits)) {
			return false
		}

		clear(record[:tcpRecordHeader])

		return writer.write(record[:tcpRecordHeader]) && awaitTCPDelivery(ctx, credits)
	}

	return false
}

// Wait for all records, including EOF, to reach the peer's local socket before
// reporting completion. A transport close can then abort all remaining work.
func awaitTCPDelivery(ctx context.Context, credits <-chan struct{}) bool {
	for range tcpRecordWindow {
		if !takeCredit(ctx, credits) {
			return false
		}
	}

	return true
}

func readTCP(stream io.Reader, records chan<- []byte, credits chan<- struct{}) {
	var header [tcpRecordHeader]byte

	eof := false

	for {
		_, err := io.ReadFull(stream, header[:])
		if err != nil {
			return
		}

		size := binary.BigEndian.Uint16(header[:])
		if size == tcpRecordAck {
			select {
			case credits <- struct{}{}:
				continue
			default:
				return // unsolicited acknowledgement
			}
		}

		if size > tcpRecordData || eof {
			return
		}

		record := make([]byte, size)

		_, err = io.ReadFull(stream, record)
		if err != nil {
			return
		}

		select {
		case records <- record:
			eof = size == 0
		default:
			return // peer exceeded the window
		}
	}
}

func receiveTCP(
	ctx context.Context,
	records <-chan []byte,
	local net.Conn,
	writer *tcpRecordWriter,
) bool {
	for {
		select {
		case <-ctx.Done():
			return false
		case record := <-records:
			if len(record) == 0 {
				cw, ok := local.(closeWriter)

				return ok && cw.CloseWrite() == nil && writer.ack()
			}

			_, err := local.Write(record)
			if err != nil || !writer.ack() {
				return false
			}
		}
	}
}
