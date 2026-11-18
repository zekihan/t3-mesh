package main

import (
	"errors"
	"flag"
	"log/slog"
	"strings"
	"testing"

	"github.com/zekihan/t3-mesh/internal/hub/enroll"
)

func TestRunUnknownSubcommand(t *testing.T) {
	err := run([]string{"bogus"})
	if err == nil || !strings.Contains(err.Error(), `unknown subcommand "bogus"`) {
		t.Fatalf("run(bogus) = %v, want unknown subcommand error", err)
	}
}

func TestRunDefaultsToServeFlags(t *testing.T) {
	// A leading flag selects serve, so an invalid serve flag is reported as such
	// before any listener or configuration is touched.
	err := run([]string{"--log-level", "loud"})
	if err == nil || !strings.Contains(err.Error(), "--log-level") {
		t.Fatalf("run(--log-level loud) = %v, want log-level error", err)
	}
}

func TestRunServeRejectsUnknownFlag(t *testing.T) {
	err := run([]string{"serve", "--no-such-flag"})
	if err == nil {
		t.Fatal("run(serve --no-such-flag) returned nil")
	}
}

func TestRunServeRejectsPositionalArguments(t *testing.T) {
	err := run([]string{"serve", "extra"})
	if err == nil {
		t.Fatal("run(serve extra) returned nil")
	}
}

func TestRunHelpIsNotAnError(t *testing.T) {
	for _, args := range [][]string{{"serve", "-h"}, {"enroll-token", "-h"}} {
		err := run(args)
		if err != nil {
			t.Fatalf("run(%v) = %v, want nil", args, err)
		}
	}
}

func TestRunEnrollTokenRequiresOneIdentity(t *testing.T) {
	for _, args := range [][]string{
		{"enroll-token"},
		{"enroll-token", "a", "b"},
	} {
		err := run(args)
		if !errors.Is(err, errUsage) {
			t.Fatalf("run(%v) = %v, want usage error", args, err)
		}
	}
}

func TestParseEnrollToken(t *testing.T) {
	cases := []struct {
		want enrollTokenArgs
		name string
		args []string
	}{
		{
			name: "agent",
			args: []string{"agent-z-mac"},
			want: enrollTokenArgs{
				socket: enroll.DefaultAdminSocket, kind: enroll.KindAgent, identity: "agent-z-mac",
			},
		},
		{
			name: "device",
			args: []string{"--device", "device-z-phone-mesh"},
			want: enrollTokenArgs{
				socket: enroll.DefaultAdminSocket, kind: enroll.KindDevice,
				identity: "device-z-phone-mesh",
			},
		},
		{
			name: "socket",
			args: []string{"--admin-socket", "/tmp/a.sock", "--device=device-z-tablet-mesh"},
			want: enrollTokenArgs{
				socket: "/tmp/a.sock", kind: enroll.KindDevice, identity: "device-z-tablet-mesh",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseEnrollToken(tc.args)
			if err != nil || got != tc.want {
				t.Fatalf("parseEnrollToken(%v) = %+v, %v; want %+v", tc.args, got, err, tc.want)
			}
		})
	}
}

func TestParseEnrollTokenUsage(t *testing.T) {
	for _, args := range [][]string{
		nil,
		{"--device", "device-z-phone-mesh", "agent-z-mac"},
		{"--device", "device-z-phone-mesh", "extra"},
		{"agent-z-mac", "agent-z-arch"},
		{"--admin-socket", "/tmp/a.sock"},
	} {
		_, err := parseEnrollToken(args)
		if !errors.Is(err, errUsage) {
			t.Errorf("parseEnrollToken(%v) = %v, want usage error", args, err)
		}
	}
}

func TestRunVersionRejectsArguments(t *testing.T) {
	err := run([]string{"version", "extra"})
	if !errors.Is(err, errArguments) {
		t.Fatalf("run(version extra) = %v, want argument error", err)
	}
}

func TestParseServeDefaults(t *testing.T) {
	opts, err := parseServe(nil)
	if err != nil {
		t.Fatal(err)
	}

	want := serveOptions{
		configDir:     "/etc/t3-mesh/config",
		trustDir:      "/etc/t3-mesh/trust",
		certDir:       "/etc/t3-mesh/tls",
		tunnelAddr:    ":8443",
		viewerAddr:    ":8080",
		opsAddr:       ":9090",
		adminSocket:   enroll.DefaultAdminSocket,
		proxyProtocol: true,
		logLevel:      slog.LevelInfo,
	}
	if opts != want {
		t.Fatalf("parseServe(nil) = %+v, want %+v", opts, want)
	}
}

func TestParseServeOverrides(t *testing.T) {
	opts, err := parseServe([]string{
		"--tunnel-addr", "127.0.0.1:1", "--proxy-protocol=false", "--log-level", "DEBUG",
	})
	if err != nil {
		t.Fatal(err)
	}

	if opts.tunnelAddr != "127.0.0.1:1" || opts.proxyProtocol || opts.logLevel != slog.LevelDebug {
		t.Fatalf("parseServe overrides = %+v", opts)
	}
}

func TestParseServeHelp(t *testing.T) {
	_, err := parseServe([]string{"-h"})
	if !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("parseServe(-h) = %v, want flag.ErrHelp", err)
	}
}
