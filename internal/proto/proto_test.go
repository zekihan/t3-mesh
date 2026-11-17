package proto

import (
	"bytes"
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
