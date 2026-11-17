// Package agentconfig parses and validates the agent YAML configuration.
package agentconfig

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	defaultHubPort   = 443
	defaultCacheTTL  = 168 * time.Hour
	maxLoopbackPort  = 32767
	agentNamePrefix  = "agent-"
	defaultStateName = "state"
	defaultInstall   = "install"
)

// Config is a validated agent configuration.
type Config struct {
	Serve      map[string]string
	Links      map[string]string
	Identity   Identity
	Direct     Direct
	StateDir   string
	InstallDir string
	Hub        string
}

// Identity names the agent and locates its key material.
type Identity struct {
	Name string
	Dir  string
}

// Direct configures the hub bypass listener.
type Direct struct {
	Enabled  bool
	Port     int
	CacheTTL time.Duration
}

type file struct {
	Serve      map[string]string `yaml:"serve"`
	Links      map[string]string `yaml:"links"`
	Direct     *direct           `yaml:"direct"`
	Identity   identity          `yaml:"identity"`
	StateDir   string            `yaml:"stateDir"`
	InstallDir string            `yaml:"installDir"`
	Hub        string            `yaml:"hub"`
}

type identity struct {
	Name string `yaml:"name"`
	Dir  string `yaml:"dir"`
}

type direct struct {
	CacheTTL *time.Duration `yaml:"cacheTTL"` //nolint:tagliatelle // key is fixed by the config format
	Port     int            `yaml:"port"`
	Enabled  bool           `yaml:"enabled"`
}

// Load reads and validates the configuration file at path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path) //nolint:gosec // operator-supplied path
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
	var f file

	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)

	if err := dec.Decode(&f); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("agentconfig: decode: %w", err)
	}

	return f.build()
}

func (f *file) build() (*Config, error) {
	if err := validateAgentName(f.Identity.Name); err != nil {
		return nil, err
	}

	if !filepath.IsAbs(f.Identity.Dir) {
		return nil, fmt.Errorf("agentconfig: identity.dir %q must be absolute", f.Identity.Dir)
	}

	parent := filepath.Dir(filepath.Clean(f.Identity.Dir))

	stateDir, err := absOrDefault("stateDir", f.StateDir, filepath.Join(parent, defaultStateName))
	if err != nil {
		return nil, err
	}

	installDir, err := absOrDefault(
		"installDir",
		f.InstallDir,
		filepath.Join(parent, defaultInstall),
	)
	if err != nil {
		return nil, err
	}

	if _, _, err = splitHub(f.Hub); err != nil {
		return nil, err
	}

	for key, target := range f.Serve {
		if !validLabel(key) {
			return nil, fmt.Errorf(
				"agentconfig: serve %q: service name must be [A-Za-z0-9_-]+",
				key,
			)
		}

		if err = validateLoopbackAddr(target); err != nil {
			return nil, fmt.Errorf("agentconfig: serve %q: %w", key, err)
		}
	}

	linkPorts, err := f.validateLinks()
	if err != nil {
		return nil, err
	}

	direct, err := f.validateDirect(linkPorts)
	if err != nil {
		return nil, err
	}

	return &Config{
		Identity: Identity{
			Name: f.Identity.Name,
			Dir:  filepath.Clean(f.Identity.Dir),
		},
		StateDir:   stateDir,
		InstallDir: installDir,
		Hub:        f.Hub,
		Serve:      f.Serve,
		Links:      f.Links,
		Direct:     direct,
	}, nil
}

func validateAgentName(name string) error {
	if !strings.HasPrefix(name, agentNamePrefix) || len(name) == len(agentNamePrefix) {
		return fmt.Errorf("agentconfig: identity.name %q must start with %q", name, agentNamePrefix)
	}

	return nil
}

func absOrDefault(field, value, def string) (string, error) {
	if value == "" {
		return def, nil
	}

	if !filepath.IsAbs(value) {
		return "", fmt.Errorf("agentconfig: %s %q must be absolute", field, value)
	}

	return filepath.Clean(value), nil
}

// validateLinks checks link keys and values and returns the set of link ports.
func (f *file) validateLinks() (map[int]bool, error) {
	ports := make(map[int]bool, len(f.Links))
	owners := make(map[int]string, len(f.Links))

	for key, value := range f.Links {
		if err := validateKey(key); err != nil {
			return nil, fmt.Errorf("agentconfig: links %q: %w", key, err)
		}

		port, err := loopbackPort(value)
		if err != nil {
			return nil, fmt.Errorf("agentconfig: links %q: %w", key, err)
		}

		if port > maxLoopbackPort {
			return nil, fmt.Errorf("agentconfig: links %q: port %d must be below %d",
				key, port, maxLoopbackPort+1)
		}

		if other, dup := owners[port]; dup {
			return nil, fmt.Errorf("agentconfig: links %q and %q share port %d", key, other, port)
		}

		owners[port] = key
		ports[port] = true
	}

	return ports, nil
}

func (f *file) validateDirect(linkPorts map[int]bool) (Direct, error) {
	if f.Direct == nil {
		return Direct{CacheTTL: defaultCacheTTL}, nil
	}

	d := Direct{Enabled: f.Direct.Enabled, Port: f.Direct.Port, CacheTTL: defaultCacheTTL}

	if f.Direct.CacheTTL != nil {
		if *f.Direct.CacheTTL <= 0 {
			return Direct{}, fmt.Errorf("agentconfig: direct.cacheTTL %s must be positive",
				*f.Direct.CacheTTL)
		}

		d.CacheTTL = *f.Direct.CacheTTL
	}

	if d.Enabled && d.Port == 0 {
		return Direct{}, errors.New("agentconfig: direct.port is required when direct is enabled")
	}

	if d.Port != 0 {
		if d.Port < 1 || d.Port > maxLoopbackPort {
			return Direct{}, fmt.Errorf("agentconfig: direct.port %d must be between 1 and %d",
				d.Port, maxLoopbackPort)
		}

		if linkPorts[d.Port] {
			return Direct{}, fmt.Errorf(
				"agentconfig: direct.port %d collides with a link port",
				d.Port,
			)
		}
	}

	return d, nil
}

// validateKey checks a "<svc>.<machine>" link or serve key.
func validateKey(key string) error {
	svc, machine, ok := strings.Cut(key, ".")
	if !ok || !validLabel(svc) || !validLabel(machine) {
		return fmt.Errorf("key must be <svc>.<machine>")
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

	if _, err = parsePort(portStr); err != nil {
		return err
	}

	if strings.EqualFold(host, "localhost") {
		return nil
	}

	ip, err := netip.ParseAddr(host)
	if err != nil || !ip.IsLoopback() {
		return fmt.Errorf("address %q must be a loopback address", addr)
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
		return 0, fmt.Errorf("value %q must use host 127.0.0.1", value)
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
		return 0, fmt.Errorf("invalid port %q", s)
	}

	return port, nil
}

// splitHub parses the hub setting, host or host:port, defaulting the port to 443.
func splitHub(hub string) (string, int, error) {
	if hub == "" {
		return "", 0, errors.New("agentconfig: hub is required")
	}

	if strings.ContainsAny(hub, "/ ") {
		return "", 0, fmt.Errorf("agentconfig: hub %q must be host or host:port", hub)
	}

	host, port := hub, defaultHubPort

	if strings.HasPrefix(hub, "[") || strings.Count(hub, ":") == 1 {
		h, p, err := net.SplitHostPort(hub)
		if err != nil {
			return "", 0, fmt.Errorf("agentconfig: hub %q: %w", hub, err)
		}

		n, err := parsePort(p)
		if err != nil {
			return "", 0, fmt.Errorf("agentconfig: hub %q: %w", hub, err)
		}

		host, port = h, n
	} else if strings.Contains(hub, ":") {
		return "", 0, fmt.Errorf("agentconfig: hub %q: IPv6 literals must be bracketed", hub)
	}

	if host == "" {
		return "", 0, fmt.Errorf("agentconfig: hub %q has no host", hub)
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
