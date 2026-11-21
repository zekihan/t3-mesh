package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/zekihan/t3-mesh/internal/agent"
)

func statusCmd(args []string) error {
	flags := newFlagSet("status")
	asJSON := flags.Bool("json", false, "print JSON")
	socket := flags.String("socket", agent.DefaultStatusSocket(), "agent status socket")

	err := flags.Parse(args)
	if errors.Is(err, flag.ErrHelp) {
		return nil
	}

	if err != nil {
		return fmt.Errorf("status: %w", err)
	}

	if flags.NArg() != 0 {
		return fmt.Errorf("status: %w", errArguments)
	}

	status, err := agent.ReadLocalStatus(context.Background(), *socket)
	if err != nil {
		return fmt.Errorf("status: %w", err)
	}

	if *asJSON {
		return printJSON(status)
	}

	printStatus(os.Stdout, status)

	return nil
}

func printJSON(value any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")

	err := enc.Encode(value)
	if err != nil {
		return fmt.Errorf("write JSON: %w", err)
	}

	return nil
}

func printStatus(out io.Writer, status *agent.LocalStatus) {
	report := &status.Report
	fmt.Fprintln(out, "Agent", status.Identity, report.Version)

	if status.ConnectedSince != nil {
		fmt.Fprintln(out, "Tunnel connected via", status.TunnelPath,
			"since", status.ConnectedSince.Format(time.RFC3339))
	} else {
		fmt.Fprintln(out, "Tunnel disconnected")
	}

	if status.DirectActive {
		fmt.Fprintln(out, "Direct path on. Listeners", status.DirectListeners)
	} else {
		fmt.Fprintln(out, "Direct path off.", status.DirectReason)
	}

	fmt.Fprintln(out, "Gateway MAC", status.GatewayMACVerdict)
	fmt.Fprintln(out, "Direct cache time remaining", status.CacheRemaining)

	for _, link := range status.Links {
		binding := "unbound"
		if link.Bound {
			binding = "bound"
		}

		fmt.Fprintln(out, "Link", link.Name, link.Address, binding)
	}

	if listener := report.DeviceListener; listener != nil {
		fmt.Fprintln(out, "Device listener bound on port", listener.Port, listener.Addrs)
	} else {
		fmt.Fprintln(out, "Device listener unbound")
	}

	revs := status.Revisions
	fmt.Fprintln(out, "Cached revisions", "release="+revs.Release, "rules="+revs.Rules,
		"revocations="+revs.Revocations, "trustBundle="+revs.TrustBundle,
		"deviceLeaves="+revs.DeviceLeaves, "peers="+revs.Peers)
	fmt.Fprintln(out, "Identity certificate expires", report.CertNotAfter)

	printUpdateStatus(out, status)

	for _, health := range report.Services {
		fmt.Fprintln(out, "Service", health.Name, health.State, "checked", health.CheckedAt)
	}

	for _, warning := range report.Warnings {
		fmt.Fprintln(out, "Warning", warning)
	}
}

func printUpdateStatus(out io.Writer, status *agent.LocalStatus) {
	probation := status.ProbationVersion
	if probation == "" {
		probation = "none"
	}

	fmt.Fprintln(out, "Version on probation", probation)

	if len(status.Report.FailedUpdates) == 0 {
		fmt.Fprintln(out, "Failed versions none")
	}

	for _, failure := range status.Report.FailedUpdates {
		fmt.Fprintln(out, "Failed version", failure.Version, failure.Reason)
	}
}
