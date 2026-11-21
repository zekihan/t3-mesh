package proto

import (
	"bytes"
	"encoding/binary"
	"errors"
	"reflect"
	"runtime"
	"testing"
)

func FuzzReadMessage(f *testing.F) {
	for _, msg := range []Message{
		Ping{Seq: 7},
		Hello{Version: "v0.3.2", Services: []string{"t3"}},
		Enroll{Token: "token", CSR: "csr"},
	} {
		var buf bytes.Buffer

		err := WriteMessage(&buf, msg)
		if err != nil {
			f.Fatal(err)
		}

		f.Add(buf.Bytes())
	}

	f.Add([]byte{0xff, 0xff, 0xff, 0xff})
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

		const limit = 4096

		if len(data) > 1<<16 {
			t.Skip()
		}

		reader := bytes.NewReader(data)

		msg, err := ReadMessage(reader, limit)
		if len(data) >= 4 && binary.BigEndian.Uint32(data[:4]) > limit &&
			!errors.Is(err, ErrTooLarge) {
			t.Fatal("oversized frame accepted")
		}

		if err != nil {
			return
		}

		n := int(binary.BigEndian.Uint32(data[:4]))
		if reader.Len() != len(data)-4-n {
			t.Fatal("read beyond frame")
		}

		var buf bytes.Buffer

		writeErr := WriteMessage(&buf, msg)
		if writeErr != nil {
			t.Fatal(writeErr)
		}

		again, err := ReadMessage(&buf, MaxMessageSize)
		if err != nil || !reflect.DeepEqual(msg, again) {
			t.Fatalf("round trip: %v", err)
		}
	})
}
