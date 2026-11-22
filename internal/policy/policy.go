// Package policy evaluates access rules and revocations shared by the hub and
// agents.
package policy

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/zekihan/t3-mesh/internal/proto"
)

// URIPrefix is the URI SAN prefix of every clients CA identity.
const URIPrefix = "urn:noqer:mtls:clients:"

// AgentPrefix is the name prefix of agent identities.
const AgentPrefix = "agent-"

// MaxIdentityLen is the longest identity name the hub issues a certificate for.
const MaxIdentityLen = 40

// Kind says which family an identity belongs to. It decides the usages the
// hub requests, so a certificate never carries those of the other kind.
type Kind string

// Identity kinds.
const (
	KindAgent  Kind = "agent"
	KindDevice Kind = "device"
)

// deviceRe matches the names of enrolled-device identities, such as
// device-z-phone-mesh. They sit in their own namespace: no existing device
// identity (z-phone) and no agent identity can match.
var deviceRe = regexp.MustCompile(`^device-[a-z0-9]+(-[a-z0-9]+)*-mesh$`)

// Errors returned by Check.
var (
	ErrDisabled    = errors.New("policy: identity disabled")
	ErrBlocked     = errors.New("policy: leaf fingerprint blocked")
	ErrExpired     = errors.New("policy: certificate expired")
	ErrNotAllowed  = errors.New("policy: not allowed by rules")
	ErrBadIdentity = errors.New("policy: invalid identity URI")
)

// IdentityURI returns the URI SAN for an identity name.
func IdentityURI(name string) string {
	return URIPrefix + name
}

// IdentityFromURI returns the identity name of a URI SAN.
func IdentityFromURI(uri string) (string, error) {
	name, ok := strings.CutPrefix(uri, URIPrefix)
	if !ok || name == "" || strings.ContainsAny(name, ":/ ") {
		return "", fmt.Errorf("%w: %q", ErrBadIdentity, uri)
	}

	return name, nil
}

// AgentIdentity returns the agent identity name for a machine.
func AgentIdentity(machine string) string {
	return AgentPrefix + machine
}

// IsAgent reports whether name is an agent identity.
func IsAgent(name string) bool {
	return strings.HasPrefix(name, AgentPrefix)
}

// IsDevice reports whether name is the name of an enrolled-device identity.
func IsDevice(name string) bool {
	return deviceRe.MatchString(name)
}

// KindOf returns the kind of an identity name, or false when it is neither an
// agent nor an enrolled device.
func KindOf(name string) (Kind, bool) {
	switch {
	case IsAgent(name):
		return KindAgent, true
	case IsDevice(name):
		return KindDevice, true
	default:
		return "", false
	}
}

// Target returns the rules key for a service on a machine.
func Target(svc, machine string) string {
	return svc + "." + machine
}

// SplitTarget splits "<svc>.<machine>". Both parts are single labels, so a
// target with more than one dot is rejected rather than treated as a machine
// name containing dots.
func SplitTarget(target string) (string, string, bool) {
	svc, machine, ok := strings.Cut(target, ".")
	if !ok || svc == "" || machine == "" || strings.Contains(machine, ".") {
		return "", "", false
	}

	return svc, machine, true
}

// Allowed reports whether identity may reach svc on machine.
func Allowed(rules proto.Rules, identity, svc, machine string) bool {
	return slices.Contains(rules.Allow[Target(svc, machine)], identity)
}

// Revoked returns ErrDisabled or ErrBlocked when the identity or leaf is
// revoked, nil otherwise. The fingerprint may be empty when unknown.
func Revoked(revs proto.Revocations, identity, fingerprint string) error {
	if slices.Contains(revs.DisabledIdentities, identity) {
		return fmt.Errorf("%w: %s", ErrDisabled, identity)
	}

	if fingerprint != "" &&
		slices.Contains(revs.BlockedFingerprints, strings.ToLower(fingerprint)) {
		return fmt.Errorf("%w: %s", ErrBlocked, fingerprint)
	}

	return nil
}

// Session describes a live stream or connection for re-checking.
type Session struct {
	Identity    string
	Fingerprint string
	NotAfter    time.Time
	Svc         string
	Machine     string
}

// CheckLeaf returns nil when the identity is not disabled, the leaf is not
// blocked and the certificate has not expired at now. It ignores the rules.
//
//nolint:gocritic // exported API takes Session by value
func CheckLeaf(revs proto.Revocations, sess Session, now time.Time) error {
	err := Revoked(revs, sess.Identity, sess.Fingerprint)
	if err != nil {
		return err
	}

	if !sess.NotAfter.IsZero() && !now.Before(sess.NotAfter) {
		return fmt.Errorf(
			"%w: %s at %s",
			ErrExpired,
			sess.Identity,
			sess.NotAfter.Format(time.RFC3339),
		)
	}

	return nil
}

// Check returns nil when s is still allowed at now under rules and revs.
//
//nolint:gocritic // exported API takes Session by value
func Check(rules proto.Rules, revs proto.Revocations, sess Session, now time.Time) error {
	err := CheckLeaf(revs, sess, now)
	if err != nil {
		return err
	}

	if !Allowed(rules, sess.Identity, sess.Svc, sess.Machine) {
		return fmt.Errorf(
			"%w: %s → %s",
			ErrNotAllowed,
			sess.Identity,
			Target(sess.Svc, sess.Machine),
		)
	}

	return nil
}
