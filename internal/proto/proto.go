// Package proto defines the t3-mesh wire protocol: ALPN names, control-stream
// messages and data-stream header lines.
package proto

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
)

const (
	lengthPrefixSize = 4
)

// ProtocolVersion is the protocol version carried in the tunnel ALPN.
const ProtocolVersion = 1

// ALPN protocol names.
const (
	ALPNEnroll = "t3-mesh-enroll/1"
	ALPNDirect = "t3-mesh-direct/1"
)

// Size limits.
const (
	MaxMessageSize = 4 << 20
	MaxEnrollSize  = 4 << 10
	MaxHeaderLine  = 4 << 10
)

// TunnelALPN returns the tunnel ALPN for protocol version n.
func TunnelALPN(n int) string {
	return "t3-mesh/" + strconv.Itoa(n)
}

// AcceptedTunnelALPNs returns the tunnel ALPNs the hub accepts: the current and
// the previous protocol version.
func AcceptedTunnelALPNs() []string {
	if ProtocolVersion <= 1 {
		return []string{TunnelALPN(ProtocolVersion)}
	}

	return []string{TunnelALPN(ProtocolVersion), TunnelALPN(ProtocolVersion - 1)}
}

// Message types.
const (
	TypeHello    = "Hello"
	TypeHelloAck = "HelloAck"
	TypeUpdate   = "Update"
	TypeRelease  = "Release"
	TypePing     = "Ping"
	TypePong     = "Pong"
	TypeRenew    = "Renew"
	TypeRenewed  = "Renewed"
	TypeReject   = "Reject"
	TypeStatus   = "Status"
	TypeEnroll   = "Enroll"
	TypeEnrolled = "Enrolled"
)

// Reject reasons.
const (
	RejectIdentityDisabled   = "identity-disabled"
	RejectLeafNotNewest      = "leaf-not-newest"
	RejectUnsupportedVersion = "unsupported-version"
	RejectRenewFailed        = "renew-failed"
	RejectEnrollFailed       = "enroll-failed"
	RejectOther              = "other"
)

// Message is implemented by every control-stream message.
type Message interface {
	MessageType() string
}

// Hello is the first message an agent sends on the control stream.
type Hello struct { //nolint:govet // JSON field order is the wire format
	Version         string   `json:"version"`
	Services        []string `json:"services"`
	LANAddrs        []string `json:"lanAddrs,omitempty"`
	DirectPort      int      `json:"directPort,omitempty"`
	CertFingerprint string   `json:"certFingerprint"`
}

// Peer is one machine an agent may reach directly.
type Peer struct {
	Machine    string   `json:"machine"`
	Identity   string   `json:"identity"`
	Services   []string `json:"services"`
	LANAddrs   []string `json:"lanAddrs,omitempty"`
	DirectPort int      `json:"directPort,omitempty"`
	Home       bool     `json:"home"`
}

// PeerTable is the set of peers this agent may reach.
type PeerTable struct {
	Revision string `json:"revision"`
	Peers    []Peer `json:"peers"`
}

// Rules says which identities may reach which services. Keys are
// "<svc>.<machine>", values are identity names (e.g. "agent-z-arch", "z-phone").
type Rules struct { //nolint:govet // JSON field order is the wire format
	Revision string              `json:"revision"`
	Allow    map[string][]string `json:"allow"`
}

// Revocations lists disabled identities and blocked leaf fingerprints
// (lowercase hex SHA-256 of the leaf DER).
type Revocations struct {
	Revision            string   `json:"revision"`
	DisabledIdentities  []string `json:"disabledIdentities"`
	BlockedFingerprints []string `json:"blockedFingerprints"`
}

// TrustBundle is the versioned set of clients CA certificates (PEM).
type TrustBundle struct {
	Revision string `json:"revision"`
	PEM      string `json:"pem"`
}

// HelloAck answers Hello.
type HelloAck struct { //nolint:govet // JSON field order is the wire format
	Machine     string      `json:"machine"`
	Home        bool        `json:"home"`
	Release     Release     `json:"release"`
	Rules       Rules       `json:"rules"`
	Peers       PeerTable   `json:"peers"`
	Revocations Revocations `json:"revocations"`
	TrustBundle TrustBundle `json:"trustBundle"`
	// HomeCIDRs are the LAN prefixes; the direct listener binds only inside them.
	HomeCIDRs []string `json:"homeCIDRs,omitempty"` //nolint:tagliatelle // wire protocol field name
}

// Update carries changed state. Nil fields are unchanged.
type Update struct {
	Home        *bool        `json:"home,omitempty"`
	Rules       *Rules       `json:"rules,omitempty"`
	Peers       *PeerTable   `json:"peers,omitempty"`
	Revocations *Revocations `json:"revocations,omitempty"`
	TrustBundle *TrustBundle `json:"trustBundle,omitempty"`
	// HomeCIDRs is nil when unchanged; a pointer to an empty slice clears the list.
	HomeCIDRs *[]string `json:"homeCIDRs,omitempty"` //nolint:tagliatelle // wire protocol field name
}

// Release is the desired agent version.
type Release struct { //nolint:govet // JSON field order is the wire format
	Version         string `json:"version"`
	RollbackAllowed bool   `json:"rollbackAllowed"`
	Revision        string `json:"revision"`
}

// Ping is a liveness probe.
type Ping struct {
	Seq          uint64 `json:"seq"`
	SentUnixNano int64  `json:"sentUnixNano"`
}

// Pong answers Ping, echoing its fields.
type Pong struct {
	Seq          uint64 `json:"seq"`
	SentUnixNano int64  `json:"sentUnixNano"`
}

// Renew asks for a new certificate. CSR is PEM.
type Renew struct {
	CSR string `json:"csr"`
}

// Renewed carries a renewed certificate and chain (PEM).
type Renewed struct {
	Certificate string `json:"certificate"`
	Chain       string `json:"chain"`
}

// Reject is sent before the hub closes a session or refuses a request.
type Reject struct {
	Reason  string `json:"reason"`
	Detail  string `json:"detail,omitempty"`
	Version string `json:"version,omitempty"`
}

// FailedUpdate records a version an agent refused or rolled back.
type FailedUpdate struct {
	Version  string `json:"version"`
	Reason   string `json:"reason"`
	Attempts int    `json:"attempts"`
	Final    bool   `json:"final"`
}

// Status is the agent's periodic report.
type Status struct { //nolint:govet // JSON field order is the wire format
	Version             string         `json:"version"`
	Warnings            []string       `json:"warnings,omitempty"`
	DirectSessions      int            `json:"directSessions"`
	ReleaseRevision     string         `json:"releaseRevision"`
	RulesRevision       string         `json:"rulesRevision"`
	RevocationRevision  string         `json:"revocationRevision"`
	TrustBundleRevision string         `json:"trustBundleRevision"`
	FailedUpdates       []FailedUpdate `json:"failedUpdates,omitempty"`
	CertNotAfter        string         `json:"certNotAfter,omitempty"`
}

// Enroll requests a first certificate with a single-use token.
type Enroll struct {
	Token string `json:"token"`
	CSR   string `json:"csr"`
}

// Enrolled carries the enrolled certificate and chain (PEM), and the clients CA
// bundle (PEM, one or more certificates) with its revision. An app that has no
// tunnel to carry a HelloAck takes its trust anchors from here; agents already
// get the same bundle in HelloAck and ignore these fields. Releases before
// device enrollment send neither.
type Enrolled struct {
	Certificate string `json:"certificate"`
	Chain       string `json:"chain"`
	CABundle    string `json:"caBundle,omitempty"`
	CARevision  string `json:"caRevision,omitempty"`
}

func (Hello) MessageType() string    { return TypeHello }
func (HelloAck) MessageType() string { return TypeHelloAck }
func (Update) MessageType() string   { return TypeUpdate }
func (Release) MessageType() string  { return TypeRelease }
func (Ping) MessageType() string     { return TypePing }
func (Pong) MessageType() string     { return TypePong }
func (Renew) MessageType() string    { return TypeRenew }
func (Renewed) MessageType() string  { return TypeRenewed }
func (Reject) MessageType() string   { return TypeReject }
func (Status) MessageType() string   { return TypeStatus }
func (Enroll) MessageType() string   { return TypeEnroll }
func (Enrolled) MessageType() string { return TypeEnrolled }

// ErrTooLarge is returned when a message exceeds the size limit.
var ErrTooLarge = errors.New("proto: message too large")

// ErrUnknownType is returned for a message with an unknown type.
var ErrUnknownType = errors.New("proto: unknown message type")

type envelope struct {
	Type string          `json:"type"`
	Body json.RawMessage `json:"body"`
}

// WriteMessage writes one length-prefixed JSON message.
func WriteMessage(w io.Writer, msg Message) error {
	body, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("proto: marshal %s: %w", msg.MessageType(), err)
	}

	data, err := json.Marshal(envelope{Type: msg.MessageType(), Body: body})
	if err != nil {
		return fmt.Errorf("proto: marshal envelope: %w", err)
	}

	if len(data) > MaxMessageSize {
		return ErrTooLarge
	}

	buf := make([]byte, lengthPrefixSize+len(data))
	binary.BigEndian.PutUint32(buf, uint32(len(data))) //nolint:gosec // bounded above
	copy(buf[lengthPrefixSize:], data)

	_, err = w.Write(buf)
	if err != nil {
		return fmt.Errorf("proto: write: %w", err)
	}

	return nil
}

// ReadMessage reads one length-prefixed JSON message of at most limit bytes.
//
//nolint:ireturn // Message is the polymorphic wire type
func ReadMessage(r io.Reader, limit int) (Message, error) {
	var hdr [lengthPrefixSize]byte

	_, err := io.ReadFull(r, hdr[:])
	if err != nil {
		return nil, fmt.Errorf("proto: read length: %w", err)
	}

	n := binary.BigEndian.Uint32(hdr[:])
	if uint64(n) > uint64(limit) { //nolint:gosec // negative limit means a huge bound
		return nil, ErrTooLarge
	}

	data := make([]byte, n)

	_, err = io.ReadFull(r, data)
	if err != nil {
		return nil, fmt.Errorf("proto: read body: %w", err)
	}

	var env envelope

	err = json.Unmarshal(data, &env)
	if err != nil {
		return nil, fmt.Errorf("proto: unmarshal envelope: %w", err)
	}

	msg, err := newMessage(env.Type)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(env.Body, msg)
	if err != nil {
		return nil, fmt.Errorf("proto: unmarshal %s: %w", env.Type, err)
	}

	return deref(msg), nil
}

func newMessage(typ string) (any, error) {
	switch typ {
	case TypeHello:
		return &Hello{}, nil
	case TypeHelloAck:
		return &HelloAck{}, nil
	case TypeUpdate:
		return &Update{}, nil
	case TypeRelease:
		return &Release{}, nil
	case TypePing:
		return &Ping{}, nil
	case TypePong:
		return &Pong{}, nil
	case TypeRenew:
		return &Renew{}, nil
	case TypeRenewed:
		return &Renewed{}, nil
	case TypeReject:
		return &Reject{}, nil
	case TypeStatus:
		return &Status{}, nil
	case TypeEnroll:
		return &Enroll{}, nil
	case TypeEnrolled:
		return &Enrolled{}, nil
	default:
		return nil, fmt.Errorf("%w: %q", ErrUnknownType, typ)
	}
}

func deref(val any) Message { //nolint:ireturn // Message is the polymorphic wire type
	switch typed := val.(type) {
	case *Hello:
		return *typed
	case *HelloAck:
		return *typed
	case *Update:
		return *typed
	case *Release:
		return *typed
	case *Ping:
		return *typed
	case *Pong:
		return *typed
	case *Renew:
		return *typed
	case *Renewed:
		return *typed
	case *Reject:
		return *typed
	case *Status:
		return *typed
	case *Enroll:
		return *typed
	case *Enrolled:
		return *typed
	default:
		panic(fmt.Sprintf("proto: unexpected %T", val))
	}
}

// StreamHeader is the first line on every data stream.
//
// Hub → agent viewer traffic sets Svc and Viewer; hub → agent relayed traffic
// sets Svc and From; agent → hub link traffic sets To ("<svc>.<machine>");
// direct connections set Svc.
type StreamHeader struct {
	Svc    string `json:"svc,omitempty"`
	Viewer string `json:"viewer,omitempty"`
	From   string `json:"from,omitempty"`
	To     string `json:"to,omitempty"`
}

// StreamReply is the accept line sent back on agent → hub link streams and on
// direct connections, before raw bytes flow.
type StreamReply struct { //nolint:govet // JSON field order is the wire format
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

// WriteLine writes v as one JSON line.
func WriteLine(w io.Writer, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("proto: marshal line: %w", err)
	}

	if len(data)+1 > MaxHeaderLine {
		return ErrTooLarge
	}

	data = append(data, '\n')

	_, err = w.Write(data)
	if err != nil {
		return fmt.Errorf("proto: write line: %w", err)
	}

	return nil
}

// ReadLine reads one JSON line into v without consuming bytes past the newline,
// so raw stream bytes after the line stay unread in r.
func ReadLine(r io.Reader, dst any) error {
	var (
		line []byte
		one  [1]byte
	)

	for {
		if len(line) >= MaxHeaderLine {
			return ErrTooLarge
		}

		_, err := io.ReadFull(r, one[:])
		if err != nil {
			return fmt.Errorf("proto: read line: %w", err)
		}

		if one[0] == '\n' {
			break
		}

		line = append(line, one[0])
	}

	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields()

	err := dec.Decode(dst)
	if err != nil {
		return fmt.Errorf("proto: decode line: %w", err)
	}

	return nil
}
