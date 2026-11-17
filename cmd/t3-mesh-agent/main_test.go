package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zekihan/t3-mesh/internal/launcher"
)

func TestRunUnknownSubcommand(t *testing.T) {
	err := run([]string{"bogus"})
	if !errors.Is(err, errSubcommand) || !strings.Contains(err.Error(), `"bogus"`) {
		t.Fatalf("run(bogus) = %v, want unknown subcommand error", err)
	}
}

func TestRunWithoutSubcommand(t *testing.T) {
	if err := run(nil); !errors.Is(err, errUsage) {
		t.Fatalf("run() = %v, want usage error", err)
	}
}

func TestRunHelpIsNotAnError(t *testing.T) {
	for _, args := range [][]string{
		{"help"},
		{"-h"},
		{"run", "-h"},
		{"launcher", "-h"},
		{"enroll", "-h"},
		{"fallback", "-h"},
	} {
		if err := run(args); err != nil {
			t.Fatalf("run(%v) = %v, want nil", args, err)
		}
	}
}

func TestRunRequiresFlags(t *testing.T) {
	tests := []struct {
		want error
		args []string
	}{
		{errRequired, []string{"run"}},
		{errRequired, []string{"launcher"}},
		{errRequired, []string{"enroll", "--token", "t"}},
		{errRequired, []string{"enroll", "--config", "agent.yaml"}},
		{errRequired, []string{"fallback"}},
		{errMaxAgeFlag, []string{"fallback", "--install-dir", "d", "--heartbeat-max-age", "1m"}},
		{errMaxAge, []string{
			"fallback", "--install-dir", "d", "--heartbeat", "h", "--heartbeat-max-age", "0s",
		}},
		{errSelfTest, []string{"launcher", "--self-test", "--config", "agent.yaml"}},
	}

	for _, tt := range tests {
		if err := run(tt.args); !errors.Is(err, tt.want) {
			t.Errorf("run(%v) = %v, want %v", tt.args, err, tt.want)
		}
	}
}

func TestRunRejectsUnknownFlags(t *testing.T) {
	for _, args := range [][]string{
		{"run", "--bogus"},
		{"launcher", "--bogus"},
		{"enroll", "--bogus"},
		{"fallback", "--bogus"},
	} {
		if err := run(args); err == nil {
			t.Fatalf("run(%v) returned nil", args)
		}
	}
}

func TestRunRejectsPositionalArguments(t *testing.T) {
	for _, args := range [][]string{
		{"run", "--config", "agent.yaml", "extra"},
		{"launcher", "--config", "agent.yaml", "extra"},
		{"enroll", "--config", "agent.yaml", "--token", "t", "extra"},
		{"fallback", "--install-dir", "d", "extra"},
	} {
		if err := run(args); !errors.Is(err, errArguments) {
			t.Fatalf("run(%v) = %v, want argument error", args, err)
		}
	}
}

func TestRunVersion(t *testing.T) {
	if err := run([]string{"version"}); err != nil {
		t.Fatalf("run(version) = %v", err)
	}
}

func TestRunVersionRejectsArguments(t *testing.T) {
	if err := run([]string{"version", "extra"}); !errors.Is(err, errArguments) {
		t.Fatalf("run(version extra) = %v, want argument error", err)
	}
}

func TestSelfTestChildRequiresBehaviour(t *testing.T) {
	if err := run([]string{launcher.SelfTestChildArg}); err == nil {
		t.Fatal("run(launcher-selftest-child) returned nil")
	}
}

func TestSelfTestChildRejectsUnknownBehaviour(t *testing.T) {
	err := run([]string{launcher.SelfTestChildArg, "bogus"})
	if err == nil || !strings.Contains(err.Error(), "bogus") {
		t.Fatalf("run(selftest-child bogus) = %v, want error naming it", err)
	}
}

func TestCheckInstalledRejectsFreshDir(t *testing.T) {
	err := checkInstalled(launcher.Layout{Dir: t.TempDir()})
	if !errors.Is(err, errNotSetUp) {
		t.Fatalf("checkInstalled(empty) = %v, want not set up error", err)
	}
}

// newInstall builds an install layout with v1 as previous-good and v2 as
// known-good and current.
func newInstall(t *testing.T) launcher.Layout {
	t.Helper()

	dir := t.TempDir()
	layout := launcher.Layout{Dir: dir}

	for _, v := range []string{"v1", "v2"} {
		if err := os.MkdirAll(filepath.Join(dir, "versions", v), 0o700); err != nil {
			t.Fatal(err)
		}

		if err := os.WriteFile(layout.Binary(v), []byte("binary"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	links := map[string]string{"known-good": "v2", "previous-good": "v1", "current": "v2"}
	for name, v := range links {
		if err := os.Symlink(filepath.Join("versions", v), filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}

	return layout
}

func TestFallbackUnconditional(t *testing.T) {
	layout := newInstall(t)

	if err := run([]string{"fallback", "--install-dir", layout.Dir}); err != nil {
		t.Fatalf("fallback: %v", err)
	}

	if kg, err := layout.KnownGood(); err != nil || kg != "v1" {
		t.Fatalf("known-good = %q, %v; want v1", kg, err)
	}

	if cur, err := layout.Current(); err != nil || cur != "v1" {
		t.Fatalf("current = %q, %v; want v1", cur, err)
	}
}

func TestFallbackWithoutPreviousGood(t *testing.T) {
	layout := newInstall(t)

	if err := os.Remove(filepath.Join(layout.Dir, "previous-good")); err != nil {
		t.Fatal(err)
	}

	if err := run([]string{"fallback", "--install-dir", layout.Dir}); err == nil {
		t.Fatal("fallback without previous-good returned nil")
	}

	if kg, err := layout.KnownGood(); err != nil || kg != "v2" {
		t.Fatalf("known-good = %q, %v; want unchanged v2", kg, err)
	}
}

func TestFallbackHeartbeatNoChange(t *testing.T) {
	layout := newInstall(t)
	heartbeat := filepath.Join(t.TempDir(), launcher.HeartbeatFile)
	args := []string{"fallback", "--install-dir", layout.Dir, "--heartbeat", heartbeat}

	// A missing heartbeat is only recorded as suspect on the first reading.
	if err := run(args); err != nil {
		t.Fatalf("fallback with missing heartbeat: %v", err)
	}

	// A fresh heartbeat means the launcher is alive.
	if err := os.WriteFile(heartbeat, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := run(args); err != nil {
		t.Fatalf("fallback with fresh heartbeat: %v", err)
	}

	if kg, err := layout.KnownGood(); err != nil || kg != "v2" {
		t.Fatalf("known-good = %q, %v; want unchanged v2", kg, err)
	}
}
