// Package hubconfig loads, validates and live-reloads the hub's mounted
// configuration: the config ConfigMap, the clients CA trust bundle and the
// serving certificate.
package hubconfig

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/zekihan/t3-mesh/internal/policy"
	"github.com/zekihan/t3-mesh/internal/proto"
)

// File names inside the mounted directories.
const (
	ConfigFile = "config.yaml"
	TrustFile  = "ca.crt"
	RevFile    = "revision"
	CertFile   = "tls.crt"
	KeyFile    = "tls.key"
)

// KindHTTP is the only supported service kind.
const KindHTTP = "http"

// ErrInvalid wraps every validation failure of the configuration.
var ErrInvalid = errors.New("hubconfig: invalid configuration")

var (
	labelRe   = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	versionRe = regexp.MustCompile(`^v\d+\.\d+\.\d+$`)
	fprRe     = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// Service is one configured service of a machine.
type Service struct {
	Kind string
}

// Machine is one configured machine.
type Machine struct {
	Identity string
	Services map[string]Service
	// DisconnectAlertAfter is how long the agent may be disconnected before
	// its disconnected alert fires.
	DisconnectAlertAfter time.Duration
}

// DefaultDisconnectAlertAfter applies when a machine sets no threshold.
const DefaultDisconnectAlertAfter = 10 * time.Minute

// Issuer references the cert-manager issuer for the clients CA.
type Issuer struct {
	Namespace string
	Name      string
	Kind      string
	Group     string
}

// Snapshot is an immutable view of the loaded configuration. Callers must not
// modify any of its fields.
type Snapshot struct {
	Machines     map[string]Machine
	ViewerDomain string
	HomePrefixes []netip.Prefix
	Issuer       Issuer

	Rules       proto.Rules
	Revocations proto.Revocations
	Release     proto.Release
	TrustBundle proto.TrustBundle
	// TrustPool holds every CA certificate of TrustBundle.
	TrustPool *x509.CertPool

	ServingCert *tls.Certificate
	// CertNotAfter is the serving certificate's expiry.
	CertNotAfter time.Time

	// PolicyRevision hashes rules and revocations; the stale check compares it.
	PolicyRevision string

	// Fingerprint identifies the raw inputs this snapshot was built from.
	Fingerprint string

	byIdentity map[string]string
}

// MachineForIdentity returns the machine whose agent identity is id.
func (s *Snapshot) MachineForIdentity(id string) (string, bool) {
	m, ok := s.byIdentity[id]

	return m, ok
}

// HostTarget maps a viewer host "<svc>.<machine>.<viewerDomain>" (any case,
// optional port) to its machine and service.
func (s *Snapshot) HostTarget(host string) (machine, svc string, ok bool) {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}

	host = strings.TrimSuffix(strings.ToLower(host), ".")

	rest, found := strings.CutSuffix(host, "."+s.ViewerDomain)
	if !found {
		return "", "", false
	}

	svc, machine, ok = policy.SplitTarget(rest)
	if !ok {
		return "", "", false
	}

	m, found := s.Machines[machine]
	if !found {
		return "", "", false
	}

	if _, found := m.Services[svc]; !found {
		return "", "", false
	}

	return machine, svc, true
}

// IsHome reports whether addr is inside a configured home CIDR.
func (s *Snapshot) IsHome(addr netip.Addr) bool {
	addr = addr.Unmap().WithZone("")
	for _, p := range s.HomePrefixes {
		if p.Contains(addr) {
			return true
		}
	}

	return false
}

// Services returns the sorted service names of machine.
func (s *Snapshot) Services(machine string) []string {
	m, ok := s.Machines[machine]
	if !ok {
		return nil
	}

	out := make([]string, 0, len(m.Services))
	for name := range m.Services {
		out = append(out, name)
	}

	slices.Sort(out)

	return out
}

type rawConfig struct {
	Machines     map[string]rawMachine `yaml:"machines"`
	HomeCIDRs    []string              `yaml:"homeCIDRs"`
	ViewerDomain string                `yaml:"viewerDomain"`
	Release      struct {
		Version         string `yaml:"version"`
		RollbackAllowed bool   `yaml:"rollbackAllowed"`
	} `yaml:"release"`
	Issuer struct {
		Namespace string `yaml:"namespace"`
		Name      string `yaml:"name"`
		Kind      string `yaml:"kind"`
		Group     string `yaml:"group"`
	} `yaml:"issuer"`
	Policy struct {
		Entries map[string]struct {
			Identities []string `yaml:"identities"`
		} `yaml:"entries"`
		DisabledIdentities  []string `yaml:"disabledIdentities"`
		BlockedFingerprints []string `yaml:"blockedFingerprints"`
	} `yaml:"policy"`
}

type rawMachine struct {
	Identity             string `yaml:"identity"`
	DisconnectAlertAfter string `yaml:"disconnectAlertAfter"`
	Services             map[string]struct {
		Kind string `yaml:"kind"`
	} `yaml:"services"`
}

// config is the validated, derived content of config.yaml.
type config struct {
	machines     map[string]Machine
	viewerDomain string
	home         []netip.Prefix
	issuer       Issuer
	rules        proto.Rules
	revs         proto.Revocations
	release      proto.Release
}

func (c *config) policyRevision() string {
	return shortHash(c.rules.Revision, c.revs.Revision)
}

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}

func shortHash(parts ...string) string {
	h := sha256.New()

	for _, p := range parts {
		_, _ = h.Write([]byte(p))
		_, _ = h.Write([]byte{0})
	}

	return hex.EncodeToString(h.Sum(nil)[:8])
}

func jsonRevision(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		// Only plain strings, bools and maps of them are hashed.
		panic(fmt.Sprintf("hubconfig: marshal: %v", err))
	}

	sum := sha256.Sum256(b)

	return hex.EncodeToString(sum[:8])
}

func sortedUnique(in []string) []string {
	out := slices.Clone(in)
	slices.Sort(out)

	return slices.Compact(out)
}

func parseConfig(data []byte) (*config, error) {
	var raw rawConfig

	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)

	if err := dec.Decode(&raw); err != nil {
		return nil, invalid("parse %s: %v", ConfigFile, err)
	}

	c := &config{machines: map[string]Machine{}}

	if err := c.parseMachines(raw.Machines); err != nil {
		return nil, err
	}

	if err := c.parseGeneral(&raw); err != nil {
		return nil, err
	}

	if err := c.parsePolicy(&raw); err != nil {
		return nil, err
	}

	return c, nil
}

func (c *config) parseMachines(in map[string]rawMachine) error {
	if len(in) == 0 {
		return invalid("no machines configured")
	}

	for name, m := range in {
		if !labelRe.MatchString(name) {
			return invalid("machine name %q is not a DNS label", name)
		}

		if m.Identity != policy.AgentIdentity(name) {
			return invalid("machine %q identity %q must be %q", name, m.Identity, policy.AgentIdentity(name))
		}

		if len(m.Services) == 0 {
			return invalid("machine %q has no services", name)
		}

		svcs := map[string]Service{}

		for svc, s := range m.Services {
			if !labelRe.MatchString(svc) {
				return invalid("machine %q service name %q is not a DNS label", name, svc)
			}

			if s.Kind != KindHTTP {
				return invalid("machine %q service %q kind %q unsupported", name, svc, s.Kind)
			}

			svcs[svc] = Service{Kind: s.Kind}
		}

		alertAfter := DefaultDisconnectAlertAfter

		if m.DisconnectAlertAfter != "" {
			d, err := time.ParseDuration(m.DisconnectAlertAfter)
			if err != nil || d <= 0 {
				return invalid("machine %q disconnectAlertAfter %q is not a positive duration", name, m.DisconnectAlertAfter)
			}

			alertAfter = d
		}

		c.machines[name] = Machine{Identity: m.Identity, Services: svcs, DisconnectAlertAfter: alertAfter}
	}

	return nil
}

func (c *config) parseGeneral(raw *rawConfig) error {
	c.viewerDomain = strings.ToLower(strings.TrimSuffix(raw.ViewerDomain, "."))
	if c.viewerDomain == "" {
		return invalid("viewerDomain is required")
	}

	for label := range strings.SplitSeq(c.viewerDomain, ".") {
		if !labelRe.MatchString(label) {
			return invalid("viewerDomain %q is not a valid domain", raw.ViewerDomain)
		}
	}

	for _, s := range raw.HomeCIDRs {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return invalid("homeCIDR %q: %v", s, err)
		}

		c.home = append(c.home, p.Masked())
	}

	if !versionRe.MatchString(raw.Release.Version) {
		return invalid("release.version %q must look like vX.Y.Z", raw.Release.Version)
	}

	c.release = proto.Release{Version: raw.Release.Version, RollbackAllowed: raw.Release.RollbackAllowed}
	c.release.Revision = jsonRevision(struct {
		Version         string `json:"version"`
		RollbackAllowed bool   `json:"rollbackAllowed"`
	}{c.release.Version, c.release.RollbackAllowed})

	c.issuer = Issuer(raw.Issuer)
	if (c.issuer != Issuer{}) && (c.issuer.Name == "" || c.issuer.Kind == "") {
		return invalid("issuer needs at least name and kind")
	}

	return nil
}

func (c *config) parsePolicy(raw *rawConfig) error {
	// Entry names are "mesh-<svc>-<machine>"; both parts may contain dashes, so
	// match against the configured pairs instead of splitting.
	known := map[string]string{}

	for machine, m := range c.machines {
		for svc := range m.Services {
			known["mesh-"+svc+"-"+machine] = policy.Target(svc, machine)
		}
	}

	allow := map[string][]string{}

	for name, e := range raw.Policy.Entries {
		target, ok := known[name]
		if !ok {
			return invalid("policy entry %q matches no configured mesh-<svc>-<machine>", name)
		}

		if len(e.Identities) == 0 {
			return invalid("policy entry %q has no identities", name)
		}

		for _, id := range e.Identities {
			if strings.TrimSpace(id) == "" || strings.ContainsAny(id, " \t:/") {
				return invalid("policy entry %q has invalid identity %q", name, id)
			}
		}

		allow[target] = sortedUnique(e.Identities)
	}

	c.rules = proto.Rules{Allow: allow, Revision: jsonRevision(allow)}

	disabled := sortedUnique(raw.Policy.DisabledIdentities)
	if slices.Contains(disabled, "") {
		return invalid("disabledIdentities contains an empty name")
	}

	blocked := make([]string, 0, len(raw.Policy.BlockedFingerprints))

	for _, f := range raw.Policy.BlockedFingerprints {
		n := strings.ToLower(strings.TrimSpace(f))
		if !fprRe.MatchString(n) {
			return invalid("blocked fingerprint %q is not 64 hex characters", f)
		}

		blocked = append(blocked, n)
	}

	blocked = sortedUnique(blocked)
	c.revs = proto.Revocations{DisabledIdentities: disabled, BlockedFingerprints: blocked}
	c.revs.Revision = jsonRevision(struct {
		Disabled []string `json:"disabledIdentities"`
		Blocked  []string `json:"blockedFingerprints"`
	}{disabled, blocked})

	return nil
}

func readFile(dir, name string) ([]byte, error) {
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return nil, fmt.Errorf("hubconfig: read %s: %w", name, err)
	}

	return b, nil
}

func loadTrust(dir string) (proto.TrustBundle, *x509.CertPool, []byte, error) {
	pemBytes, err := readFile(dir, TrustFile)
	if err != nil {
		return proto.TrustBundle{}, nil, nil, err
	}

	rev, err := readFile(dir, RevFile)
	if err != nil {
		return proto.TrustBundle{}, nil, nil, err
	}

	revision := strings.TrimSpace(string(rev))
	if revision == "" {
		return proto.TrustBundle{}, nil, nil, invalid("trust bundle revision is empty")
	}

	pool := x509.NewCertPool()
	n := 0

	rest := pemBytes
	for {
		var block *pemBlock

		block, rest = nextCert(rest)
		if block == nil {
			break
		}

		cert, perr := x509.ParseCertificate(block.Bytes)
		if perr != nil {
			return proto.TrustBundle{}, nil, nil, invalid("trust bundle certificate: %v", perr)
		}

		pool.AddCert(cert)

		n++
	}

	if n == 0 {
		return proto.TrustBundle{}, nil, nil, invalid("trust bundle has no certificates")
	}

	return proto.TrustBundle{Revision: revision, PEM: string(pemBytes)}, pool, append(pemBytes, rev...), nil
}

func loadCert(dir string) (*tls.Certificate, []byte, error) {
	crt, err := readFile(dir, CertFile)
	if err != nil {
		return nil, nil, err
	}

	key, err := readFile(dir, KeyFile)
	if err != nil {
		return nil, nil, err
	}

	pair, err := tls.X509KeyPair(crt, key)
	if err != nil {
		return nil, nil, fmt.Errorf("hubconfig: serving certificate: %w", err)
	}

	if pair.Leaf == nil {
		pair.Leaf, err = x509.ParseCertificate(pair.Certificate[0])
		if err != nil {
			return nil, nil, fmt.Errorf("hubconfig: serving certificate: %w", err)
		}
	}

	return &pair, append(crt, key...), nil
}

// Load reads and validates every input and builds a Snapshot.
func Load(p Paths) (*Snapshot, error) {
	cfgBytes, err := readFile(p.ConfigDir, ConfigFile)
	if err != nil {
		return nil, err
	}

	cfg, err := parseConfig(cfgBytes)
	if err != nil {
		return nil, err
	}

	bundle, pool, trustRaw, err := loadTrust(p.TrustDir)
	if err != nil {
		return nil, err
	}

	cert, certRaw, err := loadCert(p.CertDir)
	if err != nil {
		return nil, err
	}

	s := &Snapshot{
		Machines:       cfg.machines,
		ViewerDomain:   cfg.viewerDomain,
		HomePrefixes:   cfg.home,
		Issuer:         cfg.issuer,
		Rules:          cfg.rules,
		Revocations:    cfg.revs,
		Release:        cfg.release,
		TrustBundle:    bundle,
		TrustPool:      pool,
		ServingCert:    cert,
		CertNotAfter:   cert.Leaf.NotAfter,
		PolicyRevision: cfg.policyRevision(),
		Fingerprint:    shortHash(string(cfgBytes), string(trustRaw), string(certRaw)),
		byIdentity:     map[string]string{},
	}

	for name, m := range cfg.machines {
		s.byIdentity[m.Identity] = name
	}

	return s, nil
}
