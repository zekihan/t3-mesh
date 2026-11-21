package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"maps"
	"net"
	"os"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/zekihan/t3-mesh/internal/agent"
	"github.com/zekihan/t3-mesh/internal/agent/agentconfig"
	"github.com/zekihan/t3-mesh/internal/launcher"
	"github.com/zekihan/t3-mesh/internal/pki"
)

const (
	checkPass         = "pass"
	checkFail         = "fail"
	checkWarn         = "warn"
	checkSkip         = "skipped"
	certWarningWindow = 14 * 24 * time.Hour
	doctorDNSTimeout  = 5 * time.Second
)

var (
	errDoctor             = errors.New("one or more doctor checks failed")
	errCertificateExpired = errors.New("identity certificate expired")
)

type doctorCheck struct {
	Name   string `json:"name"`
	State  string `json:"state"`
	Detail string `json:"detail"`
}

func defaultConfigPath() string {
	if runtime.GOOS == "darwin" {
		return "/Library/Application Support/t3-mesh/agent.yaml"
	}

	return "/etc/t3-mesh/agent.yaml"
}

func doctorCmd(args []string) error {
	flags := newFlagSet("doctor")
	asJSON := flags.Bool("json", false, "print JSON")
	config := flags.String("config", defaultConfigPath(), "agent configuration file")

	err := flags.Parse(args)
	if errors.Is(err, flag.ErrHelp) {
		return nil
	}

	if err != nil {
		return fmt.Errorf("doctor: %w", err)
	}

	if flags.NArg() != 0 {
		return fmt.Errorf("doctor: %w", errArguments)
	}

	checks := runDoctor(context.Background(), *config, agent.DefaultStatusSocket())

	if *asJSON {
		err = printJSON(checks)
		if err != nil {
			return err
		}
	} else {
		for _, check := range checks {
			fmt.Fprintln(os.Stdout, check.Name, check.State, "-", check.Detail)
		}
	}

	if slices.ContainsFunc(
		checks,
		func(check doctorCheck) bool { return check.State == checkFail },
	) {
		return errDoctor
	}

	return nil
}

func checkResult(name, detail string, err error) doctorCheck {
	if err == nil {
		return doctorCheck{Name: name, State: checkPass, Detail: detail}
	}

	if os.Geteuid() != 0 && errors.Is(err, os.ErrPermission) {
		return doctorCheck{Name: name, State: checkSkip, Detail: "skipped (needs root)"}
	}

	return doctorCheck{Name: name, State: checkFail, Detail: err.Error()}
}

func runDoctor(ctx context.Context, configPath, socket string) []doctorCheck {
	cfg, configErr := agentconfig.Load(configPath)
	status, socketErr := agent.ReadLocalStatus(ctx, socket)

	checks := []doctorCheck{
		checkResult("config", configPath, configErr),
		checkResult("status socket", socket, socketErr),
	}
	if configErr != nil {
		return checks
	}

	if status != nil && status.Identity != cfg.Identity.Name {
		status = nil
	}

	for _, name := range slices.Sorted(maps.Keys(cfg.Serve)) {
		target := cfg.Serve[name]
		err := agent.ProbeService(ctx, name, target)
		checks = append(checks, checkResult("serve "+name, target, err))
	}

	if os.Geteuid() != 0 && errors.Is(socketErr, os.ErrPermission) {
		checks = append(checks, checkResult("port ownership", "", socketErr))
	} else {
		checks = append(checks, checkPorts(cfg, status)...)
	}

	layout := launcher.Layout{Dir: cfg.InstallDir}
	current, currentErr := layout.Current()
	good, goodErr := layout.KnownGood()

	dnsCtx, cancel := context.WithTimeout(ctx, doctorDNSTimeout)
	defer cancel()

	addrs, dnsErr := net.DefaultResolver.LookupHost(dnsCtx, cfg.HubHost())

	return append(checks,
		checkCertificate(cfg.Identity.Dir, time.Now()),
		checkInstalledVersion(layout, "current version", current, currentErr),
		checkInstalledVersion(layout, "known-good version", good, goodErr),
		checkResult("hub DNS", strings.Join(addrs, ", "), dnsErr),
	)
}

func checkInstalledVersion(layout launcher.Layout, name, version string, err error) doctorCheck {
	if err != nil {
		return checkResult(name, "", err)
	}

	info, err := os.Stat(layout.Binary(version))
	if err == nil && (!info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0) {
		err = errNotSetUp
	}

	return checkResult(name, version, err)
}

func checkCertificate(dir string, now time.Time) doctorCheck {
	const name = "identity certificate"

	store := pki.Store{Dir: dir}

	leaf, err := store.ReadLeaf()
	if err != nil {
		return checkResult(name, "", err)
	}

	expiry := leaf.NotAfter.UTC().Format(time.RFC3339)
	if !now.Before(leaf.NotAfter) {
		return checkResult(name, "", fmt.Errorf("%w at %s", errCertificateExpired, expiry))
	}

	if leaf.NotAfter.Sub(now) < certWarningWindow {
		return doctorCheck{Name: name, State: checkWarn, Detail: "expires " + expiry}
	}

	return checkResult(name, "expires "+expiry, nil)
}
