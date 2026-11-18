package proto

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
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

func TestDeviceLeavesWireFormat(t *testing.T) {
	leaves := &DeviceLeaves{
		Revision: "d1",
		Leaves:   []DeviceLeaf{{Identity: "device-z-phone-mesh", Fingerprint: "aa"}},
	}

	data, err := json.Marshal(Update{DeviceLeaves: leaves})
	if err != nil {
		t.Fatal(err)
	}

	const want = `{"deviceLeaves":{"revision":"d1","leaves":[{"identity":"device-z-phone-mesh","fingerprint":"aa"}]}}`
	if string(data) != want {
		t.Fatalf("Update = %s, want %s", data, want)
	}

	// Unchanged is absent, so a release before the field sees the same Update.
	data, err = json.Marshal(Update{})
	if err != nil || string(data) != `{}` {
		t.Fatalf("empty Update = %s (%v)", data, err)
	}

	data, err = json.Marshal(HelloAck{})
	if err != nil || strings.Contains(string(data), "deviceLeaves") {
		t.Fatalf("HelloAck without leaves = %s (%v)", data, err)
	}

	var buf bytes.Buffer

	err = WriteMessage(&buf, HelloAck{Machine: "z-mac", DeviceLeaves: leaves})
	if err != nil {
		t.Fatal(err)
	}

	got, err := ReadMessage(&buf, MaxMessageSize)
	if err != nil {
		t.Fatal(err)
	}

	ack, ok := got.(HelloAck)
	if !ok || !reflect.DeepEqual(ack.DeviceLeaves, leaves) {
		t.Fatalf("HelloAck round trip = %#v", got)
	}
}

// A release before device leaves ignores the field instead of failing on it.
func TestDeviceLeavesAreIgnoredByOlderReaders(t *testing.T) {
	var legacy struct {
		Machine string `json:"machine"`
		Home    bool   `json:"home"`
	}

	data, err := json.Marshal(HelloAck{
		Machine: "z-mac",
		Home:    true,
		DeviceLeaves: &DeviceLeaves{
			Revision: "d1",
			Leaves:   []DeviceLeaf{{Identity: "x", Fingerprint: "y"}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	err = json.Unmarshal(data, &legacy)
	if err != nil || legacy.Machine != "z-mac" || !legacy.Home {
		t.Fatalf("legacy decode: %+v (%v)", legacy, err)
	}

	var current HelloAck

	err = json.Unmarshal([]byte(`{"machine":"z-mac"}`), &current)
	if err != nil || current.DeviceLeaves != nil {
		t.Fatalf("decode without leaves: %+v (%v)", current, err)
	}
}

func TestViewerDomainWireFormat(t *testing.T) {
	domain := "mesh.noqer.com"

	data, err := json.Marshal(Update{ViewerDomain: &domain})
	if err != nil || string(data) != `{"viewerDomain":"mesh.noqer.com"}` {
		t.Fatalf("Update = %s (%v)", data, err)
	}

	// Unchanged and unknown are both absent, so an older agent sees nothing new.
	data, err = json.Marshal(HelloAck{})
	if err != nil || strings.Contains(string(data), "viewerDomain") {
		t.Fatalf("HelloAck without a domain = %s (%v)", data, err)
	}

	var buf bytes.Buffer

	err = WriteMessage(&buf, HelloAck{Machine: "z-mac", ViewerDomain: domain})
	if err != nil {
		t.Fatal(err)
	}

	got, err := ReadMessage(&buf, MaxMessageSize)
	if err != nil {
		t.Fatal(err)
	}

	ack, ok := got.(HelloAck)
	if !ok || ack.ViewerDomain != domain {
		t.Fatalf("HelloAck round trip = %#v", got)
	}

	var legacy struct {
		Machine string `json:"machine"`
	}

	data, err = json.Marshal(HelloAck{Machine: "z-mac", ViewerDomain: domain})
	if err != nil {
		t.Fatal(err)
	}

	err = json.Unmarshal(data, &legacy)
	if err != nil || legacy.Machine != "z-mac" {
		t.Fatalf("legacy decode: %+v (%v)", legacy, err)
	}
}
