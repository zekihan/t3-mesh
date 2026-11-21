package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"
	"unicode"

	qrcode "github.com/piglig/go-qr"

	"github.com/zekihan/t3-mesh/internal/hub/enroll"
)

func runAdmin(command string, args []string) error {
	fs := newFlagSet(command)
	socket := fs.String(
		"admin-socket",
		enroll.DefaultAdminSocket,
		"admin unix socket of the running hub",
	)

	err := fs.Parse(args)
	if errors.Is(err, flag.ErrHelp) {
		return nil
	}

	if err != nil {
		return fmt.Errorf("%s: %w", command, err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	return executeAdmin(ctx, command, *socket, fs.Args())
}

func executeAdmin(ctx context.Context, command, socket string, args []string) error {
	const columnPadding = 2

	columns := tabwriter.NewWriter(os.Stdout, 0, 0, columnPadding, ' ', 0)

	switch {
	case command == "status" && len(args) == 0:
		machines, err := enroll.RequestStatus(ctx, socket)
		if err != nil {
			return fmt.Errorf("status: %w", err)
		}

		printStatus(columns, machines)
	case command == "tokens" && len(args) == 0:
		tokens, err := enroll.RequestTokens(ctx, socket)
		if err != nil {
			return fmt.Errorf("tokens: %w", err)
		}

		printTokens(columns, tokens)
	case command == "tokens" && len(args) == 2 && args[0] == "revoke":
		return revokeToken(ctx, socket, args[1])
	case command == "disconnect" && len(args) == 1:
		return disconnectMachine(ctx, socket, args[0])
	default:
		return fmt.Errorf("%s: %w", command, errArguments)
	}

	err := columns.Flush()
	if err != nil {
		return fmt.Errorf("write %s: %w", command, err)
	}

	return nil
}

func revokeToken(ctx context.Context, socket, prefix string) error {
	err := enroll.RevokeToken(ctx, socket, prefix)
	if err != nil {
		return fmt.Errorf("tokens revoke: %w", err)
	}

	return nil
}

func disconnectMachine(ctx context.Context, socket, machine string) error {
	err := enroll.Disconnect(ctx, socket, machine)
	if err != nil {
		return fmt.Errorf("disconnect: %w", err)
	}

	return nil
}

func printStatus(w io.Writer, machines []enroll.MachineStatus) {
	fmt.Fprintln(
		w,
		"MACHINE\tONLINE\tPATH\tAGENT VERSION\tDESIRED VERSION\t"+
			"CERT EXPIRY\tSERVICE HEALTH\tALERTS\tLAST SEEN",
	)

	for _, machine := range machines {
		services := make([]string, 0, len(machine.Services))
		for _, service := range slices.Sorted(maps.Keys(machine.Services)) {
			services = append(services, service+"="+machine.Services[service])
		}

		fmt.Fprintf(
			w,
			"%s\t%t\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			machine.Name,
			machine.Online,
			dash(machine.Path),
			dash(printableVersion(machine.Version)),
			dash(machine.DesiredVersion),
			adminTime(machine.CertNotAfter),
			dash(strings.Join(services, ", ")),
			dash(strings.Join(machine.Alerts, ", ")),
			adminTime(machine.LastSeen),
		)
	}
}

func printTokens(w io.Writer, tokens []enroll.TokenInfo) {
	fmt.Fprintln(w, "ID PREFIX\tIDENTITY\tKIND\tEXPIRY")

	for _, token := range tokens {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
			token.ID, token.Identity, token.Kind, adminTime(&token.Expires))
	}
}

func printableVersion(version string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return '?'
		}

		return r
	}, version)
}

func adminTime(value *time.Time) string {
	if value == nil {
		return "-"
	}

	return value.UTC().Format(time.RFC3339)
}

func dash(value string) string {
	if value == "" {
		return "-"
	}

	return value
}

func printTokenQR(w io.Writer, token string) error {
	code, err := qrcode.EncodeText(token, qrcode.Low)
	if err != nil {
		return fmt.Errorf("encode enrollment token QR: %w", err)
	}

	const margin = 4

	var out strings.Builder
	// Explicit black and white cells make the code scan on either terminal theme.
	for row := -margin; row < code.Size()+margin; row++ {
		for col := -margin; col < code.Size()+margin; col++ {
			if code.Module(col, row) {
				out.WriteString("\x1b[40m  ")
			} else {
				out.WriteString("\x1b[47m  ")
			}
		}

		out.WriteString("\x1b[0m\n")
	}

	_, err = io.WriteString(w, out.String())
	if err != nil {
		return fmt.Errorf("print enrollment token QR: %w", err)
	}

	return nil
}
