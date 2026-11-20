// Command t3-mesh-agent runs the t3-mesh agent, the launcher that supervises it
// from the install layout, the enrollment command and the fallback that
// repoints the install after a failed launcher.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/zekihan/t3-mesh/internal/agent"
	"github.com/zekihan/t3-mesh/internal/agent/agentconfig"
	"github.com/zekihan/t3-mesh/internal/launcher"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

// fault is set only for deliberately broken test releases (scripts/build-release.sh
// reads a FAULT file at the repository root), to prove rollback and the launcher
// fallback on real machines. Empty in every normal build.
var fault string

// Injected faults.
const (
	faultAgentCrash    = "agent-crash"    // the agent exits at once: the launcher rolls back
	faultLauncherCrash = "launcher-crash" // a promoted launcher exits at once: the fallback repoints
)

const (
	// Enrollment, including the wait for the hub, ends after this time.
	enrollTimeout = 60 * time.Second
	// The macOS fallback daemon treats a heartbeat this old as stale.
	defaultHeartbeatMaxAge = 5 * time.Minute
)

const usage = `usage: t3-mesh-agent <subcommand> [flags]

  run --config <path>                       run the agent
  launcher --config <path>                  supervise the agent from the install layout
  launcher --self-test                      check the launcher and exit
  enroll --config <path> --token <token>    obtain an identity from the hub
  fallback --install-dir <dir> [--heartbeat <path> [--heartbeat-max-age <dur>]]
                                            repoint known-good at previous-good
  version                                   print the version
`

var (
	errUsage      = errors.New("missing subcommand (see -h)")
	errSubcommand = errors.New("unknown subcommand")
	errArguments  = errors.New("unexpected arguments")
	errRequired   = errors.New("is required")
	errSelfTest   = errors.New("--self-test takes no --config")
	errNotSetUp   = errors.New("install dir is not set up, run the installer first")
	errHeartbeat  = errors.New("--heartbeat needs a non-empty path")
	errMaxAgeFlag = errors.New("--heartbeat-max-age needs --heartbeat")
	errMaxAge     = errors.New("--heartbeat-max-age must be positive")
	errFault      = errors.New("injected fault")
)

func main() {
	err := run(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "t3-mesh-agent: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return errUsage
	}

	switch args[0] {
	case "run":
		return runAgent(args[1:])
	case "launcher":
		return launcherCmd(args)
	case "enroll":
		return enrollCmd(args[1:])
	case "fallback":
		return fallbackCmd(args[1:])
	case launcher.SelfTestChildArg:
		err := launcher.SelfTestChild(args[1:])
		if err != nil {
			return fmt.Errorf("selftest child: %w", err)
		}

		return nil
	case "version":
		if len(args) > 1 {
			return fmt.Errorf("version: %w", errArguments)
		}

		fmt.Fprintln(os.Stdout, version)

		return nil
	case "help", "-h", "-help", "--help":
		fmt.Fprint(os.Stdout, usage)

		return nil
	default:
		return fmt.Errorf("%w %q (want run, launcher, enroll, fallback or version)",
			errSubcommand, args[0])
	}
}

func runAgent(args []string) error {
	if fault == faultAgentCrash {
		return fmt.Errorf("run: %w: %s", errFault, fault)
	}

	fs := newFlagSet("run")
	configPath := fs.String("config", "", "agent configuration file")
	level := fs.String("log-level", "info", "log level: debug, info, warn or error")

	err := fs.Parse(args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}

		return fmt.Errorf("run: %w", err)
	}

	if fs.NArg() > 0 {
		return fmt.Errorf("run: %w %q", errArguments, fs.Args())
	}

	err = requireFlag("config", *configPath)
	if err != nil {
		return fmt.Errorf("run: %w", err)
	}

	logLevel, err := parseLogLevel(*level)
	if err != nil {
		return fmt.Errorf("run: %w", err)
	}

	cfg, err := agentconfig.Load(*configPath)
	if err != nil {
		return fmt.Errorf("run: %w", err)
	}

	log := newLogger(logLevel)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	agt, err := agent.New(agent.Options{Config: cfg, Version: version, Log: log})
	if err != nil {
		return fmt.Errorf("run: %w", err)
	}

	log.Info(
		"Agent starting",
		slog.String("version", version),
		slog.String("name", cfg.Identity.Name),
	)

	err = agt.Run(ctx)
	if err != nil {
		return fmt.Errorf("run: %w", err)
	}

	return nil
}

// The launcher command runs the launcher, or with --self-test the launcher
// self-test. Args starts with the subcommand name, since the launcher re-executes
// itself with them after a promotion.
func launcherCmd(args []string) error {
	fs := newFlagSet("launcher")
	configPath := fs.String("config", "", "agent configuration file")
	selfTest := fs.Bool("self-test", false, "supervise dummy children through every path and exit")
	level := fs.String("log-level", "info", "launcher log level: debug, info, warn or error")

	err := fs.Parse(args[1:])
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}

		return fmt.Errorf("launcher: %w", err)
	}

	if fs.NArg() > 0 {
		return fmt.Errorf("launcher: %w %q", errArguments, fs.Args())
	}

	logLevel, err := parseLogLevel(*level)
	if err != nil {
		return fmt.Errorf("launcher: %w", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if *selfTest {
		if *configPath != "" {
			return fmt.Errorf("launcher: %w", errSelfTest)
		}

		return selfTestCmd(ctx)
	}

	// The self-test above still passes, so a release with this fault is promoted
	// and only then fails, as a launcher bug that the self-test misses would.
	if fault == faultLauncherCrash {
		return fmt.Errorf("launcher: %w: %s", errFault, fault)
	}

	err = requireFlag("config", *configPath)
	if err != nil {
		return fmt.Errorf("launcher: %w", err)
	}

	cfg, err := agentconfig.Load(*configPath)
	if err != nil {
		return fmt.Errorf("launcher: %w", err)
	}

	layout := launcher.Layout{Dir: cfg.InstallDir}

	err = checkInstalled(layout)
	if err != nil {
		return fmt.Errorf("launcher: %w", err)
	}

	err = launcher.Run(ctx, launcher.Config{
		Layout:     layout,
		StateDir:   cfg.StateDir,
		Args:       []string{"run", "--config", *configPath},
		Log:        newLogger(logLevel),
		ReexecArgs: args,
	})
	if err != nil {
		return fmt.Errorf("launcher: %w", err)
	}

	return nil
}

func selfTestCmd(ctx context.Context) error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("launcher: locate binary: %w", err)
	}

	err = launcher.SelfTest(ctx, exe)
	if err != nil {
		return fmt.Errorf("self-test: %w", err)
	}

	fmt.Fprintln(os.Stdout, "launcher self-test passed")

	return nil
}

// checkInstalled reports an install layout that lacks the links the launcher
// starts from, as on a fresh manual install that was never staged by install.sh.
func checkInstalled(layout launcher.Layout) error {
	_, err := layout.KnownGood()
	if err != nil {
		return fmt.Errorf("%w %s: %w", errNotSetUp, layout.Dir, err)
	}

	_, err = layout.Current()
	if err != nil {
		return fmt.Errorf("%w %s: %w", errNotSetUp, layout.Dir, err)
	}

	return nil
}

func enrollCmd(args []string) error {
	fs := newFlagSet("enroll")
	configPath := fs.String("config", "", "agent configuration file")
	token := fs.String("token", "", "single-use enrollment token from the hub")

	err := fs.Parse(args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}

		return fmt.Errorf("enroll: %w", err)
	}

	if fs.NArg() > 0 {
		return fmt.Errorf("enroll: %w %q", errArguments, fs.Args())
	}

	err = requireFlag("config", *configPath)
	if err != nil {
		return fmt.Errorf("enroll: %w", err)
	}

	err = requireFlag("token", *token)
	if err != nil {
		return fmt.Errorf("enroll: %w", err)
	}

	cfg, err := agentconfig.Load(*configPath)
	if err != nil {
		return fmt.Errorf("enroll: %w", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	ctx, cancel := context.WithTimeout(ctx, enrollTimeout)
	defer cancel()

	err = agent.Enroll(ctx, cfg, *token, nil)
	if err != nil {
		return fmt.Errorf("enroll: %w", err)
	}

	fmt.Fprintf(os.Stdout, "enrolled %s with %s\n", cfg.Identity.Name, cfg.Hub)

	return nil
}

// fallbackCmd repoints known-good at previous-good. With --heartbeat it does so
// only once the launcher heartbeat has been stale for long enough; without it,
// unconditionally, as systemd's OnFailure= unit needs.
func fallbackCmd(args []string) error {
	fs := newFlagSet("fallback")
	installDir := fs.String("install-dir", "", "install directory holding the version links")
	heartbeat := fs.String("heartbeat", "", "launcher heartbeat; fall back only while it is stale")
	stateDir := fs.String(
		"state-dir",
		"",
		"agent state directory for the failure record (default: \"state\" next to --install-dir)",
	)
	maxAge := fs.Duration(
		"heartbeat-max-age",
		defaultHeartbeatMaxAge,
		"age after which the heartbeat counts as stale",
	)

	err := fs.Parse(args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}

		return fmt.Errorf("fallback: %w", err)
	}

	if fs.NArg() > 0 {
		return fmt.Errorf("fallback: %w %q", errArguments, fs.Args())
	}

	err = requireFlag("install-dir", *installDir)
	if err != nil {
		return fmt.Errorf("fallback: %w", err)
	}

	flagsSet := make(map[string]bool)

	fs.Visit(func(f *flag.Flag) { flagsSet[f.Name] = true })

	layout := launcher.Layout{Dir: *installDir}
	log := newLogger(slog.LevelInfo)

	if *stateDir == "" {
		*stateDir = filepath.Join(filepath.Dir(filepath.Clean(*installDir)), "state")
	}

	if *heartbeat == "" {
		switch {
		case flagsSet["heartbeat"]:
			return fmt.Errorf("fallback: %w", errHeartbeat)
		case flagsSet["heartbeat-max-age"]:
			return fmt.Errorf("fallback: %w", errMaxAgeFlag)
		}

		err = launcher.FallbackAndRecord(layout, *stateDir, time.Now())
		if err != nil {
			return fmt.Errorf("fallback: %w", err)
		}

		log.Info(
			"Known-good and current now point at previous-good",
			slog.String("install", layout.Dir),
		)

		return nil
	}

	if *maxAge <= 0 {
		return fmt.Errorf("fallback: %w", errMaxAge)
	}

	repointed, err := launcher.Fallback(layout, *stateDir, *heartbeat, *maxAge, time.Now())
	if err != nil {
		return fmt.Errorf("fallback: %w", err)
	}

	if !repointed {
		log.Info(
			"Nothing to do",
			slog.String("install", layout.Dir),
			slog.String("heartbeat", *heartbeat),
		)

		return nil
	}

	log.Info(
		"Known-good and current now point at previous-good",
		slog.String("install", layout.Dir),
		slog.String("heartbeat", *heartbeat),
	)

	return nil
}

func newLogger(level slog.Level) *slog.Logger {
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
}

func parseLogLevel(s string) (slog.Level, error) {
	var level slog.Level

	err := level.UnmarshalText([]byte(s))
	if err != nil {
		return 0, fmt.Errorf("--log-level: %w", err)
	}

	return level, nil
}

func requireFlag(name, value string) error {
	if value == "" {
		return fmt.Errorf("--%s %w", name, errRequired)
	}

	return nil
}

func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	return fs
}
