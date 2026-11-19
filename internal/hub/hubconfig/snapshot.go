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
	"io"
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
	Services             map[string]Service
	Identity             string
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
	CertNotAfter   time.Time
	Rules          proto.Rules
	TrustPool      *x509.CertPool
	byIdentity     map[string]string
	Machines       map[string]Machine
	ServingCert    *tls.Certificate
	Issuer         Issuer
	Release        proto.Release
	TrustBundle    proto.TrustBundle
	PolicyRevision string
	Fingerprint    string
	ViewerDomain   string
	APIHost        string
	Revocations    proto.Revocations
	HomePrefixes   []netip.Prefix
	APIIdentities  []string
	// Devices are the enrolled-device identities allowed to enroll and renew,
	// sorted. Empty means device enrollment is off.
	Devices []string
}

// IsAPIHost reports whether host (any case, optional port) is the hub API host.
func (snap *Snapshot) IsAPIHost(host string) bool {
	return normalizeHost(host) == snap.APIHost
}

// APICaller reports whether identity is listed under api.identities.
func (snap *Snapshot) APICaller(identity string) bool {
	return slices.Contains(snap.APIIdentities, identity)
}

// Device reports whether identity is a configured enrolled-device identity.
func (snap *Snapshot) Device(identity string) bool {
	return slices.Contains(snap.Devices, identity)
}

func normalizeHost(host string) string {
	h, _, err := net.SplitHostPort(host)
	if err == nil {
		host = h
	}

	return strings.TrimSuffix(strings.ToLower(host), ".")
}

// MachineForIdentity returns the machine whose agent identity is id.
func (snap *Snapshot) MachineForIdentity(id string) (string, bool) {
	m, ok := snap.byIdentity[id]

	return m, ok
}

// HostTarget maps a viewer host "<svc>.<machine>.<viewerDomain>" (any case,
// optional port) to its machine and service.
func (snap *Snapshot) HostTarget(host string) (string, string, bool) {
	rest, found := strings.CutSuffix(normalizeHost(host), "."+snap.ViewerDomain)
	if !found {
		return "", "", false
	}

	svc, machine, ok := policy.SplitTarget(rest)
	if !ok {
		return "", "", false
	}

	m, found := snap.Machines[machine]
	if !found {
		return "", "", false
	}

	if _, found := m.Services[svc]; !found {
		return "", "", false
	}

	return machine, svc, true
}

// IsHome reports whether addr is inside a configured home CIDR.
func (snap *Snapshot) IsHome(addr netip.Addr) bool {
	addr = addr.Unmap().WithZone("")
	for _, p := range snap.HomePrefixes {
		if p.Contains(addr) {
			return true
		}
	}

	return false
}

// Services returns the sorted service names of machine.
func (snap *Snapshot) Services(machine string) []string {
	m, ok := snap.Machines[machine]
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
	Machines map[string]rawMachine `yaml:"machines"`
	Devices  []string              `yaml:"devices"`
	//nolint:tagliatelle // public config key; renaming it would break existing config files
	HomeCIDRs    []string `yaml:"homeCIDRs"`
	ViewerDomain string   `yaml:"viewerDomain"`
	API          struct {
		Host       string   `yaml:"host"`
		Identities []string `yaml:"identities"`
	} `yaml:"api"`
	Release struct {
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
	Services map[string]struct {
		Kind string `yaml:"kind"`
	} `yaml:"services"`
	Identity             string `yaml:"identity"`
	DisconnectAlertAfter string `yaml:"disconnectAlertAfter"`
}

// config is the validated, derived content of config.yaml.
type config struct {
	rules        proto.Rules
	machines     map[string]Machine
	issuer       Issuer
	release      proto.Release
	viewerDomain string
	apiHost      string
	apiCallers   []string
	devices      []string
	revs         proto.Revocations
	home         []netip.Prefix
}

func (cfg *config) policyRevision() string {
	return shortHash(cfg.rules.Revision, cfg.revs.Revision)
}

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}

func shortHash(parts ...string) string {
	hasher := sha256.New()

	for _, p := range parts {
		_, _ = hasher.Write([]byte(p))
		_, _ = hasher.Write([]byte{0})
	}

	return hex.EncodeToString(hasher.Sum(nil)[:8])
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

	err := dec.Decode(&raw)
	if err != nil {
		return nil, invalid("parse %s: %v", ConfigFile, err)
	}

	switch err = dec.Decode(&yaml.Node{}); {
	case err == nil:
		return nil, invalid("parse %s: expected a single YAML document", ConfigFile)
	case !errors.Is(err, io.EOF):
		return nil, invalid("parse %s: %v", ConfigFile, err)
	}

	cfg := &config{machines: map[string]Machine{}}

	err = cfg.parseMachines(raw.Machines)
	if err != nil {
		return nil, err
	}

	err = cfg.parseDevices(raw.Devices)
	if err != nil {
		return nil, err
	}

	err = cfg.parseGeneral(&raw)
	if err != nil {
		return nil, err
	}

	err = cfg.parseAPI(&raw)
	if err != nil {
		return nil, err
	}

	err = cfg.parsePolicy(&raw)
	if err != nil {
		return nil, err
	}

	return cfg, nil
}

func (cfg *config) parseMachines(in map[string]rawMachine) error {
	if len(in) == 0 {
		return invalid("no machines configured")
	}

	for name, machine := range in {
		if !labelRe.MatchString(name) {
			return invalid("machine name %q is not a DNS label", name)
		}

		if machine.Identity != policy.AgentIdentity(name) {
			return invalid(
				"machine %q identity %q must be %q",
				name,
				machine.Identity,
				policy.AgentIdentity(name),
			)
		}

		if len(machine.Services) == 0 {
			return invalid("machine %q has no services", name)
		}

		svcs := map[string]Service{}

		for svc, service := range machine.Services {
			if !labelRe.MatchString(svc) {
				return invalid("machine %q service name %q is not a DNS label", name, svc)
			}

			if service.Kind != KindHTTP {
				return invalid("machine %q service %q kind %q unsupported", name, svc, service.Kind)
			}

			svcs[svc] = Service{Kind: service.Kind}
		}

		alertAfter := DefaultDisconnectAlertAfter

		if machine.DisconnectAlertAfter != "" {
			duration, err := time.ParseDuration(machine.DisconnectAlertAfter)
			if err != nil || duration <= 0 {
				return invalid(
					"machine %q disconnectAlertAfter %q is not a positive duration",
					name,
					machine.DisconnectAlertAfter,
				)
			}

			alertAfter = duration
		}

		cfg.machines[name] = Machine{
			Identity:             machine.Identity,
			Services:             svcs,
			DisconnectAlertAfter: alertAfter,
		}
	}

	return nil
}

// parseDevices validates the enrolled-device identities. A device is never an
// agent: the names are disjoint by construction, and an overlap is refused
// anyway, so no identity can be both enrolled as a device and tunnel as an agent.
func (cfg *config) parseDevices(in []string) error {
	for _, id := range in {
		if !policy.IsDevice(id) || len(id) > policy.MaxIdentityLen {
			return invalid(
				"devices has invalid identity %q: want device-<name>-mesh, at most %d characters",
				id,
				policy.MaxIdentityLen,
			)
		}

		for _, machine := range cfg.machines {
			if machine.Identity == id {
				return invalid("devices lists agent identity %q", id)
			}
		}
	}

	cfg.devices = sortedUnique(in)

	return nil
}

func (cfg *config) parseGeneral(raw *rawConfig) error {
	cfg.viewerDomain = strings.ToLower(strings.TrimSuffix(raw.ViewerDomain, "."))
	if cfg.viewerDomain == "" {
		return invalid("viewerDomain is required")
	}

	for label := range strings.SplitSeq(cfg.viewerDomain, ".") {
		if !labelRe.MatchString(label) {
			return invalid("viewerDomain %q is not a valid domain", raw.ViewerDomain)
		}
	}

	for _, s := range raw.HomeCIDRs {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return invalid("homeCIDR %q: %v", s, err)
		}

		cfg.home = append(cfg.home, p.Masked())
	}

	if !versionRe.MatchString(raw.Release.Version) {
		return invalid("release.version %q must look like vX.Y.Z", raw.Release.Version)
	}

	cfg.release = proto.Release{
		Version:         raw.Release.Version,
		RollbackAllowed: raw.Release.RollbackAllowed,
	}
	cfg.release.Revision = jsonRevision(struct {
		Version         string `json:"version"`
		RollbackAllowed bool   `json:"rollbackAllowed"`
	}{cfg.release.Version, cfg.release.RollbackAllowed})

	cfg.issuer = Issuer(raw.Issuer)
	if (cfg.issuer != Issuer{}) && (cfg.issuer.Name == "" || cfg.issuer.Kind == "") {
		return invalid("issuer needs at least name and kind")
	}

	return nil
}

// parseAPI validates the hub API host and its caller set. The callers are a
// separate list, never a rule: rules admit only mesh-<svc>-<machine> entries.
func (cfg *config) parseAPI(raw *rawConfig) error {
	host := strings.ToLower(strings.TrimSuffix(raw.API.Host, "."))
	if host == "" {
		host = "hub." + cfg.viewerDomain
	}

	for label := range strings.SplitSeq(host, ".") {
		if !labelRe.MatchString(label) {
			return invalid("api.host %q is not a valid domain", raw.API.Host)
		}
	}

	if rest, ok := strings.CutSuffix(host, "."+cfg.viewerDomain); host == cfg.viewerDomain ||
		(ok && strings.Contains(rest, ".")) {
		return invalid("api.host %q collides with the agent endpoint or a viewer host", host)
	}

	for _, id := range raw.API.Identities {
		if strings.TrimSpace(id) == "" || strings.ContainsAny(id, " \t:/") {
			return invalid("api.identities has invalid identity %q", id)
		}

		if policy.IsAgent(id) {
			return invalid("api.identities lists agent identity %q", id)
		}
	}

	cfg.apiHost = host
	cfg.apiCallers = sortedUnique(raw.API.Identities)

	return nil
}

func (cfg *config) parsePolicy(raw *rawConfig) error {
	// Entry names are "mesh-<svc>-<machine>"; both parts may contain dashes, so
	// collect all configured pairs that could match each name.
	known := map[string][]string{}

	for machine, m := range cfg.machines {
		for svc := range m.Services {
			name := "mesh-" + svc + "-" + machine
			known[name] = append(known[name], policy.Target(svc, machine))
		}
	}

	allow := map[string][]string{}

	for name, entry := range raw.Policy.Entries {
		targets := known[name]
		if len(targets) == 0 {
			return invalid("policy entry %q matches no configured mesh-<svc>-<machine>", name)
		}

		if len(targets) > 1 {
			slices.Sort(targets)

			return invalid(
				"policy entry %q is ambiguous: matches %s",
				name,
				strings.Join(targets, ", "),
			)
		}

		if len(entry.Identities) == 0 {
			return invalid("policy entry %q has no identities", name)
		}

		for _, id := range entry.Identities {
			if strings.TrimSpace(id) == "" || strings.ContainsAny(id, " \t:/") {
				return invalid("policy entry %q has invalid identity %q", name, id)
			}
		}

		allow[targets[0]] = sortedUnique(entry.Identities)
	}

	cfg.rules = proto.Rules{Allow: allow, Revision: jsonRevision(allow)}

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
	cfg.revs = proto.Revocations{DisabledIdentities: disabled, BlockedFingerprints: blocked}
	cfg.revs.Revision = jsonRevision(struct {
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
	count := 0

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

		count++
	}

	if count == 0 {
		return proto.TrustBundle{}, nil, nil, invalid("trust bundle has no certificates")
	}

	return proto.TrustBundle{
		Revision: revision,
		PEM:      string(pemBytes),
	}, pool, append(
		pemBytes,
		rev...,
	), nil
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
func Load(paths Paths) (*Snapshot, error) {
	cfgBytes, err := readFile(paths.ConfigDir, ConfigFile)
	if err != nil {
		return nil, err
	}

	cfg, err := parseConfig(cfgBytes)
	if err != nil {
		return nil, err
	}

	bundle, pool, trustRaw, err := loadTrust(paths.TrustDir)
	if err != nil {
		return nil, err
	}

	cert, certRaw, err := loadCert(paths.CertDir)
	if err != nil {
		return nil, err
	}

	snap := &Snapshot{
		Machines:       cfg.machines,
		ViewerDomain:   cfg.viewerDomain,
		APIHost:        cfg.apiHost,
		APIIdentities:  cfg.apiCallers,
		Devices:        cfg.devices,
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
		snap.byIdentity[m.Identity] = name
	}

	return snap, nil
}
