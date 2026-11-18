package proto

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"testing"
)

func TestMessageRoundTrip(t *testing.T) {
	home := true
	msgs := []Message{
		Hello{Version: "v0.1.0", Services: []string{"t3"}, CertFingerprint: "ab"},
		HelloAck{
			Machine: "z-mac",
			Rules:   Rules{Allow: map[string][]string{"t3.devbox": {"z-phone"}}},
		},
		Update{Home: &home},
		Ping{Seq: 3, SentUnixNano: 42},
		Reject{Reason: RejectOther},
	}

	var buf bytes.Buffer
	for _, m := range msgs {
		err := WriteMessage(&buf, m)
		if err != nil {
			t.Fatal(err)
		}
	}

	for _, want := range msgs {
		got, err := ReadMessage(&buf, MaxMessageSize)
		if err != nil {
			t.Fatal(err)
		}

		if !reflect.DeepEqual(got, want) {
			t.Fatalf("got %#v, want %#v", got, want)
		}
	}
}

func TestReadMessageLimit(t *testing.T) {
	var buf bytes.Buffer

	err := WriteMessage(&buf, Enroll{Token: string(make([]byte, MaxEnrollSize))})
	if err != nil {
		t.Fatal(err)
	}

	_, err = ReadMessage(&buf, MaxEnrollSize)
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("err = %v, want ErrTooLarge", err)
	}
}

func TestReadLineLeavesRest(t *testing.T) {
	var buf bytes.Buffer

	err := WriteLine(&buf, StreamHeader{Svc: "t3", Viewer: "z-phone"})
	if err != nil {
		t.Fatal(err)
	}

	buf.WriteString("GET / HTTP/1.1\r\n")

	var hdr StreamHeader

	err = ReadLine(&buf, &hdr)
	if err != nil {
		t.Fatal(err)
	}

	if hdr.Viewer != "z-phone" {
		t.Fatalf("viewer = %q", hdr.Viewer)
	}

	rest, _ := io.ReadAll(&buf)
	if string(rest) != "GET / HTTP/1.1\r\n" {
		t.Fatalf("rest = %q", rest)
	}
}

// The app speaks the enrollment protocol from the documented JSON, so the exact
// bytes of both messages are pinned here.
func TestEnrollWireFormat(t *testing.T) {
	frame := func(msg Message) string {
		t.Helper()

		var buf bytes.Buffer

		err := WriteMessage(&buf, msg)
		if err != nil {
			t.Fatal(err)
		}

		raw := buf.Bytes()
		if n := binary.BigEndian.Uint32(raw[:4]); int(n) != len(raw)-4 {
			t.Fatalf("length prefix %d, body %d", n, len(raw)-4)
		}

		return string(raw[4:])
	}

	got := frame(Enroll{Token: "tok", CSR: "csr"})
	if want := `{"type":"Enroll","body":{"token":"tok","csr":"csr"}}`; got != want {
		t.Errorf("Enroll = %s, want %s", got, want)
	}

	got = frame(Enrolled{Certificate: "leaf", Chain: "chain", CABundle: "bundle", CARevision: "r1"})
	want := `{"type":"Enrolled","body":{"certificate":"leaf","chain":"chain",` +
		`"caBundle":"bundle","caRevision":"r1"}}`

	if got != want {
		t.Errorf("Enrolled = %s, want %s", got, want)
	}

	got = frame(Reject{Reason: RejectEnrollFailed, Detail: "invalid token"})
	if want := `{"type":"Reject","body":{"reason":"enroll-failed","detail":"invalid token"}}`; got != want {
		t.Errorf("Reject = %s, want %s", got, want)
	}
}

// A release that predates the CA fields still reads a new reply, and a new
// reader reads an old one.
func TestEnrolledIsCompatible(t *testing.T) {
	var legacy struct {
		Certificate string `json:"certificate"`
		Chain       string `json:"chain"`
	}

	data, err := json.Marshal(
		Enrolled{Certificate: "leaf", Chain: "chain", CABundle: "b", CARevision: "r"},
	)
	if err != nil {
		t.Fatal(err)
	}

	err = json.Unmarshal(data, &legacy)
	if err != nil || legacy.Certificate != "leaf" || legacy.Chain != "chain" {
		t.Fatalf("legacy decode: %+v, %v", legacy, err)
	}

	var current Enrolled

	err = json.Unmarshal([]byte(`{"certificate":"leaf","chain":"chain"}`), &current)
	if err != nil || current.CABundle != "" || current.CARevision != "" {
		t.Fatalf("decode without CA fields: %+v, %v", current, err)
	}
}
