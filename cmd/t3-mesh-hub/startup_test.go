package main

import (
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/zekihan/t3-mesh/internal/hub/hubconfig"
	"github.com/zekihan/t3-mesh/internal/pki/pkitest"
)

func TestServeRejectsInvalidStartupInputs(t *testing.T) {
	const config = `machines:
  devbox: {identity: agent-devbox, services: {t3: {kind: http}}}
viewerDomain: mesh.example.com
release: {version: v1.2.3}
`

	const issuer = `issuer: {namespace: mtls-pki, name: clients, kind: Issuer, group: cert-manager.io}
`

	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	t.Setenv("KUBERNETES_SERVICE_PORT", "")

	ca := pkitest.NewCA(t, "clients")
	_, cert, key := ca.IssueIdentity(t, "agent-devbox", true, time.Now().Add(24*time.Hour))

	tests := []struct {
		name     string
		file     string
		stage    string
		detail   string
		contents []byte
	}{
		{"missing config", hubconfig.ConfigFile, "load configuration", "read config.yaml", nil},
		{
			"malformed config",
			hubconfig.ConfigFile,
			"load configuration",
			"parse config.yaml",
			[]byte("machines: ["),
		},
		{
			"empty trust revision",
			hubconfig.RevFile,
			"load configuration",
			"trust bundle revision is empty",
			[]byte("\n"),
		},
		{
			"bad serving key",
			hubconfig.KeyFile,
			"load configuration",
			"serving certificate",
			[]byte("invalid PEM"),
		},
		{
			"missing issuer",
			hubconfig.ConfigFile,
			"build issuer",
			"namespace is required",
			[]byte(config),
		},
		{"missing Kubernetes API", "", "build issuer", "no API server configured", nil},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			files := map[string][]byte{
				hubconfig.ConfigFile: []byte(config + issuer),
				hubconfig.TrustFile:  ca.CertPEM,
				hubconfig.RevFile:    []byte("rev-1\n"),
				hubconfig.CertFile:   cert,
				hubconfig.KeyFile:    key,
			}

			if tc.file != "" {
				files[tc.file] = tc.contents
			}

			for name, data := range files {
				if data == nil {
					continue
				}

				err := os.WriteFile(filepath.Join(dir, name), data, 0o600)
				if err != nil {
					t.Fatal(err)
				}
			}

			err := run([]string{
				"serve", "--config-dir", dir, "--trust-dir", dir, "--cert-dir", dir,
				"--tunnel-addr", "127.0.0.1:0", "--viewer-addr", "127.0.0.1:0",
				"--ops-addr", "127.0.0.1:0", "--admin-socket", filepath.Join(dir, "admin.sock"),
			})
			if err == nil || !strings.HasPrefix(err.Error(), tc.stage+": ") ||
				!strings.Contains(err.Error(), tc.detail) {
				t.Fatalf("serve = %v, want %q containing %q", err, tc.stage, tc.detail)
			}
		})
	}
}

func TestServeHTTPReportsBindFailure(t *testing.T) {
	t.Parallel()

	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = listener.Close() })

	addr := listener.Addr().String()
	server := &http.Server{Addr: addr, ReadHeaderTimeout: httpHeaderTimeout}
	log := slog.New(slog.DiscardHandler)

	err = serveHTTP(t.Context(), log, server)
	if !errors.Is(err, syscall.EADDRINUSE) || !strings.Contains(err.Error(), addr) {
		t.Fatalf("serveHTTP = %v, want EADDRINUSE at %s", err, addr)
	}
}
