// Package policy evaluates access rules and revocations shared by the hub and
// agents.
package policy

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/zekihan/t3-mesh/internal/proto"
)

// URIPrefix is the URI SAN prefix of every clients CA identity.
const URIPrefix = "urn:noqer:mtls:clients:"

// AgentPrefix is the name prefix of agent identities.
const AgentPrefix = "agent-"

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

// Target returns the rules key for a service on a machine.
func Target(svc, machine string) string {
	return svc + "." + machine
}

// SplitTarget splits "<svc>.<machine>".
func SplitTarget(target string) (svc, machine string, ok bool) {
	svc, machine, ok = strings.Cut(target, ".")
	if !ok || svc == "" || machine == "" {
		return "", "", false
	}

	return svc, machine, true
}

// Allowed reports whether identity may reach svc on machine.
func Allowed(rules proto.Rules, identity, svc, machine string) bool {
	return slices.Contains(rules.Allow[Target(svc, machine)], identity)
}

// Revoked returns ErrDisabled or ErrBlocked when the identity or leaf is
// revoked, nil otherwise. fingerprint may be empty when unknown.
func Revoked(revs proto.Revocations, identity, fingerprint string) error {
	if slices.Contains(revs.DisabledIdentities, identity) {
		return fmt.Errorf("%w: %s", ErrDisabled, identity)
	}

	if fingerprint != "" && slices.Contains(revs.BlockedFingerprints, strings.ToLower(fingerprint)) {
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

// Check returns nil when s is still allowed at now under rules and revs.
func Check(rules proto.Rules, revs proto.Revocations, s Session, now time.Time) error {
	if err := Revoked(revs, s.Identity, s.Fingerprint); err != nil {
		return err
	}

	if !s.NotAfter.IsZero() && !now.Before(s.NotAfter) {
		return fmt.Errorf("%w: %s at %s", ErrExpired, s.Identity, s.NotAfter.Format(time.RFC3339))
	}

	if !Allowed(rules, s.Identity, s.Svc, s.Machine) {
		return fmt.Errorf("%w: %s → %s", ErrNotAllowed, s.Identity, Target(s.Svc, s.Machine))
	}

	return nil
}
