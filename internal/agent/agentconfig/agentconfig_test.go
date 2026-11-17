package agentconfig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const validDoc = `
identity:
  name: agent-z-arch
  dir: /var/lib/t3-mesh/identity
stateDir: /var/lib/t3-mesh/state
installDir: /var/lib/t3-mesh/install
hub: mesh.noqer.com
serve:
  t3: 127.0.0.1:3773
links:
  t3.devbox: 127.0.0.1:27301
  t3.z-mac:  127.0.0.1:27302
direct:
  enabled: true
  port: 27400
  cacheTTL: 168h
`

func TestParseValid(t *testing.T) {
	cfg, err := Parse([]byte(validDoc))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if cfg.Identity.Name != "agent-z-arch" || cfg.Identity.Dir != "/var/lib/t3-mesh/identity" {
		t.Fatalf("identity = %+v", cfg.Identity)
	}
	if cfg.StateDir != "/var/lib/t3-mesh/state" || cfg.InstallDir != "/var/lib/t3-mesh/install" {
		t.Fatalf("dirs = %q %q", cfg.StateDir, cfg.InstallDir)
	}
	if cfg.Serve["t3"] != "127.0.0.1:3773" {
		t.Fatalf("serve = %v", cfg.Serve)
	}
	if len(cfg.Links) != 2 || cfg.Links["t3.devbox"] != "127.0.0.1:27301" {
		t.Fatalf("links = %v", cfg.Links)
	}
	want := Direct{Enabled: true, Port: 27400, CacheTTL: 168 * time.Hour}
	if cfg.Direct != want {
		t.Fatalf("direct = %+v, want %+v", cfg.Direct, want)
	}
	if got := cfg.HubAddr(); got != "mesh.noqer.com:443" {
		t.Fatalf("HubAddr = %q", got)
	}
	if got := cfg.HubHost(); got != "mesh.noqer.com" {
		t.Fatalf("HubHost = %q", got)
	}
}

func TestParseDefaults(t *testing.T) {
	doc := `
identity:
  name: agent-z-mac
  dir: /Library/Application Support/t3-mesh/identity
hub: mesh.noqer.com:8443
`
	cfg, err := Parse([]byte(doc))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if cfg.StateDir != "/Library/Application Support/t3-mesh/state" {
		t.Fatalf("StateDir = %q", cfg.StateDir)
	}
	if cfg.InstallDir != "/Library/Application Support/t3-mesh/install" {
		t.Fatalf("InstallDir = %q", cfg.InstallDir)
	}
	if cfg.Direct.Enabled || cfg.Direct.CacheTTL != 168*time.Hour {
		t.Fatalf("direct defaults = %+v", cfg.Direct)
	}
	if cfg.HubAddr() != "mesh.noqer.com:8443" || cfg.HubHost() != "mesh.noqer.com" {
		t.Fatalf("hub = %q %q", cfg.HubAddr(), cfg.HubHost())
	}
}

func TestDefaultCacheTTLWhenOmitted(t *testing.T) {
	doc := validDoc
	doc = strings.Replace(doc, "  cacheTTL: 168h\n", "", 1)
	cfg, err := Parse([]byte(doc))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.Direct.CacheTTL != 168*time.Hour {
		t.Fatalf("CacheTTL = %v", cfg.Direct.CacheTTL)
	}
}

func TestHubForms(t *testing.T) {
	tests := []struct {
		hub      string
		wantAddr string
		wantHost string
	}{
		{"mesh.noqer.com", "mesh.noqer.com:443", "mesh.noqer.com"},
		{"mesh.noqer.com:9443", "mesh.noqer.com:9443", "mesh.noqer.com"},
		{"203.0.113.7", "203.0.113.7:443", "203.0.113.7"},
		{"[2001:db8::1]", "", ""},
		{"[2001:db8::1]:8443", "[2001:db8::1]:8443", "2001:db8::1"},
	}

	for _, tt := range tests {
		t.Run(tt.hub, func(t *testing.T) {
			cfg := &Config{Hub: tt.hub}
			if tt.wantAddr == "" {
				if _, _, err := splitHub(tt.hub); err == nil {
					t.Fatalf("splitHub(%q) accepted", tt.hub)
				}
				return
			}
			if got := cfg.HubAddr(); got != tt.wantAddr {
				t.Fatalf("HubAddr = %q, want %q", got, tt.wantAddr)
			}
			if got := cfg.HubHost(); got != tt.wantHost {
				t.Fatalf("HubHost = %q, want %q", got, tt.wantHost)
			}
		})
	}
}

func TestParseInvalid(t *testing.T) {
	tests := []struct {
		name string
		doc  string
	}{
		{"empty", ``},
		{"no identity name", "identity:\n  dir: /a/identity\nhub: h\n"},
		{"name without prefix", "identity:\n  name: z-arch\n  dir: /a/identity\nhub: h\n"},
		{"name only prefix", "identity:\n  name: agent-\n  dir: /a/identity\nhub: h\n"},
		{"relative identity dir", "identity:\n  name: agent-x\n  dir: identity\nhub: h\n"},
		{"missing hub", "identity:\n  name: agent-x\n  dir: /a/identity\n"},
		{"hub with scheme", "identity:\n  name: agent-x\n  dir: /a/identity\nhub: https://h\n"},
		{"hub bad port", "identity:\n  name: agent-x\n  dir: /a/identity\nhub: h:0\n"},
		{"hub unbracketed ipv6", "identity:\n  name: agent-x\n  dir: /a/identity\nhub: \"2001:db8::1\"\n"},
		{"relative stateDir", "identity:\n  name: agent-x\n  dir: /a/identity\nhub: h\nstateDir: state\n"},
		{"relative installDir", "identity:\n  name: agent-x\n  dir: /a/identity\nhub: h\ninstallDir: install\n"},
		{"serve public address", "identity:\n  name: agent-x\n  dir: /a/identity\nhub: h\nserve:\n  t3: 0.0.0.0:3773\n"},
		{"serve non-loopback ip", "identity:\n  name: agent-x\n  dir: /a/identity\nhub: h\nserve:\n  t3: 192.168.1.5:3773\n"},
		{"serve no port", "identity:\n  name: agent-x\n  dir: /a/identity\nhub: h\nserve:\n  t3: 127.0.0.1\n"},
		{"serve dotted key", "identity:\n  name: agent-x\n  dir: /a/identity\nhub: h\nserve:\n  t3.x: 127.0.0.1:3773\n"},
		{"link key without dot", "identity:\n  name: agent-x\n  dir: /a/identity\nhub: h\nlinks:\n  t3: 127.0.0.1:27301\n"},
		{"link key empty machine", "identity:\n  name: agent-x\n  dir: /a/identity\nhub: h\nlinks:\n  t3.: 127.0.0.1:27301\n"},
		{"link key empty svc", "identity:\n  name: agent-x\n  dir: /a/identity\nhub: h\nlinks:\n  .z: 127.0.0.1:27301\n"},
		{"link localhost value", "identity:\n  name: agent-x\n  dir: /a/identity\nhub: h\nlinks:\n  t3.z: localhost:27301\n"},
		{"link other loopback", "identity:\n  name: agent-x\n  dir: /a/identity\nhub: h\nlinks:\n  t3.z: 127.0.0.2:27301\n"},
		{"link public address", "identity:\n  name: agent-x\n  dir: /a/identity\nhub: h\nlinks:\n  t3.z: 0.0.0.0:27301\n"},
		{"link port at ephemeral floor", "identity:\n  name: agent-x\n  dir: /a/identity\nhub: h\nlinks:\n  t3.z: 127.0.0.1:32768\n"},
		{"link port zero", "identity:\n  name: agent-x\n  dir: /a/identity\nhub: h\nlinks:\n  t3.z: 127.0.0.1:0\n"},
		{"link port too big", "identity:\n  name: agent-x\n  dir: /a/identity\nhub: h\nlinks:\n  t3.z: 127.0.0.1:70000\n"},
		{"link port not a number", "identity:\n  name: agent-x\n  dir: /a/identity\nhub: h\nlinks:\n  t3.z: 127.0.0.1:abc\n"},
		{"duplicate link port", "identity:\n  name: agent-x\n  dir: /a/identity\nhub: h\nlinks:\n  t3.a: 127.0.0.1:27301\n  t3.b: 127.0.0.1:27301\n"},
		{"direct port at ephemeral floor", "identity:\n  name: agent-x\n  dir: /a/identity\nhub: h\ndirect:\n  enabled: true\n  port: 40000\n"},
		{"direct enabled without port", "identity:\n  name: agent-x\n  dir: /a/identity\nhub: h\ndirect:\n  enabled: true\n"},
		{"direct port collides with link", "identity:\n  name: agent-x\n  dir: /a/identity\nhub: h\nlinks:\n  t3.z: 127.0.0.1:27400\ndirect:\n  enabled: true\n  port: 27400\n"},
		{"direct disabled port collides", "identity:\n  name: agent-x\n  dir: /a/identity\nhub: h\nlinks:\n  t3.z: 127.0.0.1:27400\ndirect:\n  enabled: false\n  port: 27400\n"},
		{"direct port out of range", "identity:\n  name: agent-x\n  dir: /a/identity\nhub: h\ndirect:\n  enabled: true\n  port: 99999\n"},
		{"cacheTTL zero", "identity:\n  name: agent-x\n  dir: /a/identity\nhub: h\ndirect:\n  enabled: true\n  port: 27400\n  cacheTTL: 0s\n"},
		{"cacheTTL negative", "identity:\n  name: agent-x\n  dir: /a/identity\nhub: h\ndirect:\n  enabled: true\n  port: 27400\n  cacheTTL: -1h\n"},
		{"unknown top-level field", "identity:\n  name: agent-x\n  dir: /a/identity\nhub: h\nbogus: 1\n"},
		{"unknown identity field", "identity:\n  name: agent-x\n  dir: /a/identity\n  extra: 1\nhub: h\n"},
		{"unknown direct field", "identity:\n  name: agent-x\n  dir: /a/identity\nhub: h\ndirect:\n  enabled: true\n  port: 27400\n  ttl: 1h\n"},
		{"malformed yaml", "identity: [\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Parse([]byte(tt.doc)); err == nil {
				t.Fatal("Parse accepted invalid config")
			}
		})
	}
}

func TestParseDirectDisabledWithoutPort(t *testing.T) {
	doc := "identity:\n  name: agent-x\n  dir: /a/identity\nhub: h\ndirect:\n  enabled: false\n"
	if _, err := Parse([]byte(doc)); err != nil {
		t.Fatalf("Parse: %v", err)
	}
}

func TestLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.yaml")
	if err := os.WriteFile(path, []byte(validDoc), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Identity.Name != "agent-z-arch" {
		t.Fatalf("name = %q", cfg.Identity.Name)
	}
}

func TestLoadErrors(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "missing.yaml")); err == nil {
		t.Fatal("Load accepted missing file")
	}

	path := filepath.Join(t.TempDir(), "bad.yaml")
	if err := os.WriteFile(path, []byte("identity:\n  name: x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("Load accepted invalid file")
	}
}
