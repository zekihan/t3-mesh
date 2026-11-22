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
		Release{Version: "v1.2.3", RollbackAllowed: true, Revision: "release-1"},
		Ping{Seq: 3, SentUnixNano: 42},
		Pong{Seq: 3, SentUnixNano: 42},
		Renew{CSR: "csr"},
		Renewed{Certificate: "leaf", Chain: "chain"},
		Reject{Reason: RejectOther},
		Status{
			Version:        "v1.2.3",
			DeviceListener: &DeviceListener{Addrs: []string{"127.0.0.1"}, Port: 8444},
		},
		Enroll{Token: "token", CSR: "csr"},
		Enrolled{Certificate: "leaf", Chain: "chain", CABundle: "bundle", CARevision: "ca-1"},
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

func TestValidServiceKind(t *testing.T) {
	for kind, want := range map[string]bool{
		KindHTTP: true, KindTCP: true, "": false, "HTTP": false, "udp": false,
	} {
		if got := ValidServiceKind(kind); got != want {
			t.Errorf("ValidServiceKind(%q) = %v, want %v", kind, got, want)
		}
	}

	if got := (&StreamHeader{}).ServiceKind(); got != KindHTTP {
		t.Errorf("empty header kind = %q, want %q", got, KindHTTP)
	}

	if got := (&StreamHeader{Kind: KindTCP}).ServiceKind(); got != KindTCP {
		t.Errorf("tcp header kind = %q, want %q", got, KindTCP)
	}
}

func TestTunnelALPNs(t *testing.T) {
	if got := TunnelALPN(ProtocolVersion); got != "t3-mesh/2" {
		t.Errorf("TunnelALPN = %q", got)
	}

	got := AcceptedTunnelALPNs()
	if len(got) != 2 || got[0] != "t3-mesh/2" || got[1] != "t3-mesh/1" {
		t.Errorf("AcceptedTunnelALPNs = %v", got)
	}
}

func TestReadMessageLimit(t *testing.T) {
	var buf bytes.Buffer

	err := WriteMessage(&buf, Enroll{Token: string(make([]byte, MaxEnrollSize))})
	if err != nil {
		t.Fatal(err)
	}

	bodyLen := buf.Len() - lengthPrefixSize

	_, err = ReadMessage(&buf, MaxEnrollSize)
	if !errors.Is(err, ErrTooLarge) || buf.Len() != bodyLen {
		t.Fatalf(
			"ReadMessage = %v, left %d bytes; want ErrTooLarge and %d",
			err,
			buf.Len(),
			bodyLen,
		)
	}
}

func TestReadMessageRejectsMalformedFrames(t *testing.T) {
	tests := []struct {
		want   error
		name   string
		prefix string
		body   string
		size   uint32
	}{
		{io.ErrUnexpectedEOF, "short length", "read length", "", 0},
		{io.ErrUnexpectedEOF, "short body", "read body", "{", 2},
		{nil, "bad envelope", "unmarshal envelope", `{"type":`, 0},
		{ErrUnknownType, "unknown type", "", `{"type":"FutureMessage","body":{}}`, 0},
		{nil, "wrong body type", "unmarshal Ping", `{"type":"Ping","body":{"seq":"three"}}`, 0},
		{nil, "missing body", "unmarshal Ping", `{"type":"Ping"}`, 0},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			size := tc.size
			if size == 0 {
				size = uint32(len(tc.body)) //nolint:gosec // small test fixture
			}

			frame := binary.BigEndian.AppendUint32(nil, size)
			if tc.body == "" {
				frame = frame[:2]
			}

			frame = append(frame, tc.body...)

			got, err := ReadMessage(bytes.NewReader(frame), MaxMessageSize)
			if got != nil || err == nil || (tc.want != nil && !errors.Is(err, tc.want)) ||
				!strings.Contains(err.Error(), tc.prefix) {
				t.Fatalf(
					"ReadMessage = %v, %v; want no message and %q (%v)",
					got,
					err,
					tc.prefix,
					tc.want,
				)
			}
		})
	}
}

func TestMessageSizeBoundary(t *testing.T) {
	var empty bytes.Buffer

	err := WriteMessage(&empty, Renew{})
	if err != nil {
		t.Fatal(err)
	}

	csr := strings.Repeat("x", MaxMessageSize-empty.Len()+lengthPrefixSize)

	var frame bytes.Buffer

	err = WriteMessage(&frame, Renew{CSR: csr})
	if err != nil {
		t.Fatal(err)
	}

	if got := binary.BigEndian.Uint32(frame.Bytes()); got != MaxMessageSize {
		t.Fatalf("frame length = %d, want %d", got, MaxMessageSize)
	}

	got, err := ReadMessage(&frame, MaxMessageSize)
	if err != nil || got != (Renew{CSR: csr}) {
		t.Fatalf("ReadMessage at the limit = %T, %v", got, err)
	}

	err = WriteMessage(&frame, Renew{CSR: csr + "x"})
	if !errors.Is(err, ErrTooLarge) || frame.Len() != 0 {
		t.Fatalf("oversize write = %v, wrote %d bytes", err, frame.Len())
	}
}

func TestStreamHeaderSizeBoundary(t *testing.T) {
	const empty = "{\"svc\":\"\"}\n"

	svc := strings.Repeat("x", MaxHeaderLine-len(empty))

	var frame bytes.Buffer

	err := WriteLine(&frame, StreamHeader{Svc: svc})
	if err != nil {
		t.Fatal(err)
	}

	if frame.Len() != MaxHeaderLine {
		t.Fatalf("line length = %d, want %d", frame.Len(), MaxHeaderLine)
	}

	var hdr StreamHeader

	err = ReadLine(&frame, &hdr)
	if err != nil || hdr.Svc != svc {
		t.Fatalf("ReadLine at the limit = %v, service length %d", err, len(hdr.Svc))
	}

	err = WriteLine(&frame, StreamHeader{Svc: svc + "x"})
	if !errors.Is(err, ErrTooLarge) || frame.Len() != 0 {
		t.Fatalf("oversize write = %v, wrote %d bytes", err, frame.Len())
	}

	input := strings.NewReader(`{"svc":"` + svc + "x\"}\n")

	err = ReadLine(input, &hdr)
	if !errors.Is(err, ErrTooLarge) || input.Len() != 1 {
		t.Fatalf("oversize read = %v, left %d bytes", err, input.Len())
	}
}

func TestReadLineRejectsInvalidHeaders(t *testing.T) {
	tests := []struct {
		line string
		want string
	}{
		{`{"svc":"t3"}`, "read line"},
		{"{\"svc\":\n", "decode line"},
		{"{\"svc\":7}\n", "cannot unmarshal number"},
		{"{\"serv\":\"t3\"}\n", `unknown field "serv"`},
	}

	for _, tc := range tests {
		var hdr StreamHeader

		err := ReadLine(strings.NewReader(tc.line), &hdr)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("ReadLine(%q) = %v, want %q", tc.line, err, tc.want)
		}
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

func TestReadLineRejectsTrailingData(t *testing.T) {
	for _, suffix := range []string{`{}`, "garbage", "\u00a0"} {
		var hdr StreamHeader

		err := ReadLine(strings.NewReader(`{"svc":"t3"} `+suffix+"\n"), &hdr)
		if err == nil {
			t.Errorf("ReadLine accepted trailing data %q", suffix)
		}
	}
}

func TestReadLineAllowsTrailingJSONWhitespace(t *testing.T) {
	var hdr StreamHeader

	err := ReadLine(strings.NewReader("{\"svc\":\"t3\"} \t\r\n"), &hdr)
	if err != nil || hdr.Svc != "t3" {
		t.Fatalf("ReadLine got %+v, %v; want service t3", hdr, err)
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
