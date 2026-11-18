// Package agentconfig parses and validates the agent YAML configuration.
package agentconfig

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/zekihan/t3-mesh/internal/agent/linkguard"
)

const (
	defaultHubPort = 443
	// DefaultDevicesPort is the device listener port when direct.devices names none.
	// It sits below the Linux and macOS ephemeral ranges like the other agent ports,
	// so an outgoing connection can never hold it and the unprivileged service user
	// can bind it.
	DefaultDevicesPort = 27443
	defaultCacheTTL    = 168 * time.Hour
	maxLoopbackPort    = 32767
	agentNamePrefix    = "agent-"
	defaultStateName   = "state"
	defaultInstall     = "install"
)

var (
	errMustBeAbsolute      = errors.New("must be absolute")
	errServiceNameInvalid  = errors.New("service name must be [A-Za-z0-9_-]+")
	errAgentNamePrefix     = errors.New("identity.name has the wrong prefix")
	errPortAboveRange      = errors.New("port above the loopback range")
	errPortShared          = errors.New("share a port")
	errCacheTTLNotPositive = errors.New("must be positive")
	errDirectPortRequired  = errors.New(
		"agentconfig: direct.port is required when direct is enabled",
	)
	errDirectPortRange     = errors.New("direct.port out of range")
	errDirectPortCollision = errors.New("collides with a link port")
	errDevicesPortRange    = errors.New("direct.devices.port out of range")
	errDevicesPortShared   = errors.New("direct.devices.port collides with")
	errDevicesNeedDirect   = errors.New("agentconfig: direct.devices needs direct.enabled")
	errKeyFormat           = errors.New("key must be <svc>.<machine>")
	errNotLoopback         = errors.New("must be a loopback address")
	errHostNotLoopbackIP   = errors.New("must use host 127.0.0.1")
	errInvalidPort         = errors.New("invalid port")
	errHubRequired         = errors.New("agentconfig: hub is required")
	errHubFormat           = errors.New("must be host or host:port")
	errHubIPv6Brackets     = errors.New("IPv6 literals must be bracketed")
	errHubNoHost           = errors.New("has no host")
	errOriginFormat        = errors.New("must be scheme://host[:port] with nothing after it")
)

// Config is a validated agent configuration.
type Config struct {
	Serve      map[string]string
	Links      map[string]string
	Identity   Identity
	StateDir   string
	InstallDir string
	Hub        string
	// LinkOrigins are the browser origins a link port accepts besides its own:
	// the T3 desktop app's renderer plus any configured linkOrigins.
	LinkOrigins []string
	Direct      Direct
}

// Identity names the agent and locates its key material.
type Identity struct {
	Name string
	Dir  string
}

// Direct configures the hub bypass listener and, under it, the device listener.
type Direct struct {
	Devices  Devices
	CacheTTL time.Duration
	Port     int
	Enabled  bool
}

// Devices configures the TLS listener enrolled devices (the Android app) connect
// to. It runs only while Direct is enabled, under the same home gate and cache
// window, and is on by default then: what it admits is decided by the hub's rules
// and device leaves, and there are none until a device has enrolled.
type Devices struct {
	Port    int
	Enabled bool
}

type file struct {
	Serve       map[string]string `yaml:"serve"`
	Links       map[string]string `yaml:"links"`
	Direct      *direct           `yaml:"direct"`
	Identity    identity          `yaml:"identity"`
	StateDir    string            `yaml:"stateDir"`
	InstallDir  string            `yaml:"installDir"`
	Hub         string            `yaml:"hub"`
	LinkOrigins []string          `yaml:"linkOrigins"`
}

type identity struct {
	Name string `yaml:"name"`
	Dir  string `yaml:"dir"`
}

type direct struct {
	CacheTTL *time.Duration `yaml:"cacheTTL"` //nolint:tagliatelle // key is fixed by the config format
	Devices  *devices       `yaml:"devices"`
	Port     int            `yaml:"port"`
	Enabled  bool           `yaml:"enabled"`
}

type devices struct {
	Enabled *bool `yaml:"enabled"`
	Port    int   `yaml:"port"`
}

// Load reads and validates the configuration file at path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("agentconfig: read %s: %w", path, err)
	}

	cfg, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("agentconfig: %s: %w", path, err)
	}

	return cfg, nil
}

// Parse decodes and validates a configuration document. Unknown fields are errors.
func Parse(data []byte) (*Config, error) {
	var doc file

	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)

	err := dec.Decode(&doc)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("agentconfig: decode: %w", err)
	}

	return doc.build()
}

func (doc *file) build() (*Config, error) {
	err := validateAgentName(doc.Identity.Name)
	if err != nil {
		return nil, err
	}

	if !filepath.IsAbs(doc.Identity.Dir) {
		return nil, fmt.Errorf(
			"agentconfig: identity.dir %q %w",
			doc.Identity.Dir,
			errMustBeAbsolute,
		)
	}

	parent := filepath.Dir(filepath.Clean(doc.Identity.Dir))

	stateDir, err := absOrDefault("stateDir", doc.StateDir, filepath.Join(parent, defaultStateName))
	if err != nil {
		return nil, err
	}

	installDir, err := absOrDefault(
		"installDir",
		doc.InstallDir,
		filepath.Join(parent, defaultInstall),
	)
	if err != nil {
		return nil, err
	}

	_, _, err = splitHub(doc.Hub)
	if err != nil {
		return nil, err
	}

	for key, target := range doc.Serve {
		if !validLabel(key) {
			return nil, fmt.Errorf("agentconfig: serve %q: %w", key, errServiceNameInvalid)
		}

		err = validateLoopbackAddr(target)
		if err != nil {
			return nil, fmt.Errorf("agentconfig: serve %q: %w", key, err)
		}
	}

	linkPorts, err := doc.validateLinks()
	if err != nil {
		return nil, err
	}

	direct, err := doc.validateDirect(linkPorts)
	if err != nil {
		return nil, err
	}

	origins, err := doc.validateLinkOrigins()
	if err != nil {
		return nil, err
	}

	return &Config{
		Identity: Identity{
			Name: doc.Identity.Name,
			Dir:  filepath.Clean(doc.Identity.Dir),
		},
		StateDir:    stateDir,
		InstallDir:  installDir,
		Hub:         doc.Hub,
		Serve:       doc.Serve,
		Links:       doc.Links,
		LinkOrigins: origins,
		Direct:      direct,
	}, nil
}

func validateAgentName(name string) error {
	if !strings.HasPrefix(name, agentNamePrefix) || len(name) == len(agentNamePrefix) {
		return fmt.Errorf(
			"agentconfig: identity.name %q must start with %q: %w",
			name,
			agentNamePrefix,
			errAgentNamePrefix,
		)
	}

	return nil
}

func absOrDefault(field, value, def string) (string, error) {
	if value == "" {
		return def, nil
	}

	if !filepath.IsAbs(value) {
		return "", fmt.Errorf("agentconfig: %s %q %w", field, value, errMustBeAbsolute)
	}

	return filepath.Clean(value), nil
}

// validateLinkOrigins returns the trusted link origins: the desktop app's plus the
// configured ones, each a bare scheme://host[:port] with no path.
func (doc *file) validateLinkOrigins() ([]string, error) {
	out := []string{linkguard.DesktopOrigin}

	for _, origin := range doc.LinkOrigins {
		u, err := url.Parse(origin)
		if err != nil || u.Scheme == "" || u.Host == "" || u.Path != "" || u.RawQuery != "" ||
			u.Fragment != "" || u.User != nil || origin != u.Scheme+"://"+u.Host {
			return nil, fmt.Errorf("agentconfig: linkOrigins %q: %w", origin, errOriginFormat)
		}

		out = append(out, origin)
	}

	return out, nil
}

// validateLinks checks link keys and values and returns the set of link ports.
func (doc *file) validateLinks() (map[int]bool, error) {
	ports := make(map[int]bool, len(doc.Links))
	owners := make(map[int]string, len(doc.Links))

	for key, value := range doc.Links {
		err := validateKey(key)
		if err != nil {
			return nil, fmt.Errorf("agentconfig: links %q: %w", key, err)
		}

		port, err := loopbackPort(value)
		if err != nil {
			return nil, fmt.Errorf("agentconfig: links %q: %w", key, err)
		}

		if port > maxLoopbackPort {
			return nil, fmt.Errorf("agentconfig: links %q: port %d must be below %d: %w",
				key, port, maxLoopbackPort+1, errPortAboveRange)
		}

		if other, dup := owners[port]; dup {
			return nil, fmt.Errorf(
				"agentconfig: links %q and %q %w %d",
				key,
				other,
				errPortShared,
				port,
			)
		}

		owners[port] = key
		ports[port] = true
	}

	return ports, nil
}

func (doc *file) validateDirect(linkPorts map[int]bool) (Direct, error) {
	if doc.Direct == nil {
		return Direct{CacheTTL: defaultCacheTTL, Devices: Devices{Port: DefaultDevicesPort}}, nil
	}

	directCfg := Direct{
		Enabled:  doc.Direct.Enabled,
		Port:     doc.Direct.Port,
		CacheTTL: defaultCacheTTL,
	}

	if doc.Direct.CacheTTL != nil {
		if *doc.Direct.CacheTTL <= 0 {
			return Direct{}, fmt.Errorf("agentconfig: direct.cacheTTL %s %w",
				*doc.Direct.CacheTTL, errCacheTTLNotPositive)
		}

		directCfg.CacheTTL = *doc.Direct.CacheTTL
	}

	if directCfg.Enabled && directCfg.Port == 0 {
		return Direct{}, errDirectPortRequired
	}

	if directCfg.Port != 0 {
		if directCfg.Port < 1 || directCfg.Port > maxLoopbackPort {
			return Direct{}, fmt.Errorf("agentconfig: direct.port %d must be between 1 and %d: %w",
				directCfg.Port, maxLoopbackPort, errDirectPortRange)
		}

		if linkPorts[directCfg.Port] {
			return Direct{}, fmt.Errorf(
				"agentconfig: direct.port %d %w",
				directCfg.Port,
				errDirectPortCollision,
			)
		}
	}

	devs, err := doc.Direct.validateDevices(&directCfg, linkPorts)
	if err != nil {
		return Direct{}, err
	}

	directCfg.Devices = devs

	return directCfg, nil
}

// validateDevices resolves direct.devices: on whenever direct is, unless it says
// otherwise, on DefaultDevicesPort unless it names a port. Its port is checked
// whenever one is configured or the listener is on, so a default that nothing
// uses cannot fail a configuration.
func (dir *direct) validateDevices(
	directCfg *Direct,
	linkPorts map[int]bool,
) (Devices, error) {
	devs := Devices{Enabled: directCfg.Enabled, Port: DefaultDevicesPort}
	explicit := false

	if dir.Devices != nil {
		if dir.Devices.Port != 0 {
			devs.Port, explicit = dir.Devices.Port, true
		}

		if dir.Devices.Enabled != nil {
			devs.Enabled = *dir.Devices.Enabled
		}
	}

	if devs.Enabled && !directCfg.Enabled {
		return Devices{}, errDevicesNeedDirect
	}

	if !devs.Enabled && !explicit {
		return devs, nil
	}

	if devs.Port < 1 || devs.Port > maxLoopbackPort {
		return Devices{}, fmt.Errorf(
			"agentconfig: direct.devices.port %d must be between 1 and %d: %w",
			devs.Port,
			maxLoopbackPort,
			errDevicesPortRange,
		)
	}

	if devs.Port == directCfg.Port {
		return Devices{}, fmt.Errorf(
			"agentconfig: %w direct.port %d",
			errDevicesPortShared,
			devs.Port,
		)
	}

	if linkPorts[devs.Port] {
		return Devices{}, fmt.Errorf(
			"agentconfig: %w a link port %d",
			errDevicesPortShared,
			devs.Port,
		)
	}

	return devs, nil
}

// validateKey checks a "<svc>.<machine>" link or serve key.
func validateKey(key string) error {
	svc, machine, ok := strings.Cut(key, ".")
	if !ok || !validLabel(svc) || !validLabel(machine) {
		return errKeyFormat
	}

	return nil
}

func validLabel(s string) bool {
	if s == "" {
		return false
	}

	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '-', r == '_':
		default:
			return false
		}
	}

	return true
}

// validateLoopbackAddr accepts a loopback host:port (IP literal or localhost).
func validateLoopbackAddr(addr string) error {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("address %q must be host:port: %w", addr, err)
	}

	_, err = parsePort(portStr)
	if err != nil {
		return err
	}

	if strings.EqualFold(host, "localhost") {
		return nil
	}

	ip, err := netip.ParseAddr(host)
	if err != nil || !ip.IsLoopback() {
		return fmt.Errorf("address %q %w", addr, errNotLoopback)
	}

	return nil
}

// loopbackPort validates a link value, which must be exactly 127.0.0.1:<port>.
func loopbackPort(value string) (int, error) {
	host, portStr, err := net.SplitHostPort(value)
	if err != nil {
		return 0, fmt.Errorf("value %q must be 127.0.0.1:<port>: %w", value, err)
	}

	if host != "127.0.0.1" {
		return 0, fmt.Errorf("value %q %w", value, errHostNotLoopbackIP)
	}

	port, err := parsePort(portStr)
	if err != nil {
		return 0, err
	}

	return port, nil
}

func parsePort(s string) (int, error) {
	port, err := strconv.Atoi(s)
	if err != nil || port < 1 || port > 65535 {
		return 0, fmt.Errorf("%w %q", errInvalidPort, s)
	}

	return port, nil
}

// splitHub parses the hub setting, host or host:port, defaulting the port to 443.
func splitHub(hub string) (string, int, error) {
	if hub == "" {
		return "", 0, errHubRequired
	}

	if strings.ContainsAny(hub, "/ ") {
		return "", 0, fmt.Errorf("agentconfig: hub %q %w", hub, errHubFormat)
	}

	host, port := hub, defaultHubPort

	if strings.HasPrefix(hub, "[") || strings.Count(hub, ":") == 1 {
		splitHost, portStr, err := net.SplitHostPort(hub)
		if err != nil {
			return "", 0, fmt.Errorf("agentconfig: hub %q: %w", hub, err)
		}

		splitPort, err := parsePort(portStr)
		if err != nil {
			return "", 0, fmt.Errorf("agentconfig: hub %q: %w", hub, err)
		}

		host, port = splitHost, splitPort
	} else if strings.Contains(hub, ":") {
		return "", 0, fmt.Errorf("agentconfig: hub %q: %w", hub, errHubIPv6Brackets)
	}

	if host == "" {
		return "", 0, fmt.Errorf("agentconfig: hub %q %w", hub, errHubNoHost)
	}

	return host, port, nil
}

// HubHost returns the hub host name or address, without port.
func (c *Config) HubHost() string {
	host, _, err := splitHub(c.Hub)
	if err != nil {
		return ""
	}

	return host
}

// HubAddr returns the hub as host:port, with port 443 when none is configured.
func (c *Config) HubAddr() string {
	host, port, err := splitHub(c.Hub)
	if err != nil {
		return ""
	}

	return net.JoinHostPort(host, strconv.Itoa(port))
}
