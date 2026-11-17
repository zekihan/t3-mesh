// Command t3-mesh-hub runs the t3-mesh hub and its admin commands.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/zekihan/t3-mesh/internal/hub"
	"github.com/zekihan/t3-mesh/internal/hub/enroll"
	"github.com/zekihan/t3-mesh/internal/hub/hubconfig"
	"github.com/zekihan/t3-mesh/internal/hub/issuer"
	"github.com/zekihan/t3-mesh/internal/hub/proxyproto"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

const (
	// Agent certificates last this long.
	issuerDuration = 8760 * time.Hour
	// The PROXY v2 header Traefik sends on the tunnel port must arrive within this time.
	proxyHeaderTimeout = 5 * time.Second
	// Request headers on the HTTP listeners must arrive within this time.
	httpHeaderTimeout = 10 * time.Second
	// Graceful shutdown of the HTTP listeners ends after this time.
	shutdownTimeout = 10 * time.Second
)

var (
	errUsage      = errors.New("usage: t3-mesh-hub enroll-token [--admin-socket path] <identity>")
	errStopped    = errors.New("stopped unexpectedly")
	errSubcommand = errors.New("unknown subcommand")
	errArguments  = errors.New("unexpected arguments")
)

func main() {
	err := run(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "t3-mesh-hub: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return serve(args)
	}

	switch args[0] {
	case "serve":
		return serve(args[1:])
	case "enroll-token":
		return enrollToken(args[1:])
	case "version":
		if len(args) > 1 {
			return fmt.Errorf("version: %w", errArguments)
		}

		fmt.Fprintln(os.Stdout, version)

		return nil
	default:
		return fmt.Errorf("%w %q (want serve, enroll-token or version)", errSubcommand, args[0])
	}
}

type serveOptions struct {
	configDir     string
	trustDir      string
	certDir       string
	tunnelAddr    string
	viewerAddr    string
	opsAddr       string
	adminSocket   string
	proxyProtocol bool
	logLevel      slog.Level
}

func parseServe(args []string) (serveOptions, error) {
	var opts serveOptions

	fs := newFlagSet("serve")
	fs.StringVar(
		&opts.configDir,
		"config-dir",
		"/etc/t3-mesh/config",
		"directory of the mounted config.yaml",
	)
	fs.StringVar(
		&opts.trustDir,
		"trust-dir",
		"/etc/t3-mesh/trust",
		"directory of the mounted clients CA bundle",
	)
	fs.StringVar(
		&opts.certDir,
		"cert-dir",
		"/etc/t3-mesh/tls",
		"directory of the mounted serving certificate",
	)
	fs.StringVar(
		&opts.tunnelAddr,
		"tunnel-addr",
		":8443",
		"agent tunnel and enrollment listen address",
	)
	fs.StringVar(&opts.viewerAddr, "viewer-addr", ":8080", "viewer HTTP listen address")
	fs.StringVar(
		&opts.opsAddr,
		"ops-addr",
		":9090",
		"ops listen address (/status, /alerts, /healthz, /readyz)",
	)
	fs.StringVar(
		&opts.adminSocket,
		"admin-socket",
		enroll.DefaultAdminSocket,
		"unix socket for enroll-token",
	)
	fs.BoolVar(
		&opts.proxyProtocol,
		"proxy-protocol",
		true,
		"expect a PROXY v2 header on the tunnel listener",
	)
	level := fs.String("log-level", "info", "log level: debug, info, warn or error")

	err := fs.Parse(args)
	if err != nil {
		return serveOptions{}, fmt.Errorf("serve: %w", err)
	}

	if fs.NArg() > 0 {
		return serveOptions{}, fmt.Errorf("serve: %w %q", errArguments, fs.Args())
	}

	err = opts.logLevel.UnmarshalText([]byte(*level))
	if err != nil {
		return serveOptions{}, fmt.Errorf("--log-level: %w", err)
	}

	return opts, nil
}

func serve(args []string) error {
	opts, err := parseServe(args)
	if errors.Is(err, flag.ErrHelp) {
		return nil
	}

	if err != nil {
		return err
	}

	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: opts.logLevel}))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	watcher, err := hubconfig.NewWatcher(hubconfig.Paths{
		ConfigDir: opts.configDir,
		TrustDir:  opts.trustDir,
		CertDir:   opts.certDir,
	}, log)
	if err != nil {
		return fmt.Errorf("load configuration: %w", err)
	}

	// The issuer is built once from the settings of the startup snapshot. Changes
	// to them on reload are logged and need a restart to take effect.
	startIssuer := watcher.Current().Issuer

	iss, err := issuer.New(issuer.Config{
		Namespace: startIssuer.Namespace,
		Issuer: issuer.IssuerRef{
			Name:  startIssuer.Name,
			Kind:  startIssuer.Kind,
			Group: startIssuer.Group,
		},
		Duration: issuerDuration,
		Logger:   log,
	})
	if err != nil {
		return fmt.Errorf("build issuer: %w", err)
	}

	tokens := enroll.NewTokens(time.Now)

	srv, err := hub.New(hub.Options{
		Config:             watcher,
		Issuer:             iss,
		Tokens:             tokens,
		Log:                log,
		Now:                time.Now,
		ProxyHeaderTimeout: proxyHeaderTimeout,
	})
	if err != nil {
		return fmt.Errorf("build hub: %w", err)
	}

	var lc net.ListenConfig

	tunnelLn, err := lc.Listen(ctx, "tcp", opts.tunnelAddr)
	if err != nil {
		return fmt.Errorf("listen tunnels: %w", err)
	}

	if opts.proxyProtocol {
		tunnelLn = proxyproto.Listen(tunnelLn, srv.ProxyHeaderTimeout())
	}

	viewer := &http.Server{
		Addr:              opts.viewerAddr,
		Handler:           srv.ViewerHandler(),
		ReadHeaderTimeout: httpHeaderTimeout,
	}
	ops := &http.Server{
		Addr:              opts.opsAddr,
		Handler:           srv.OpsHandler(),
		ReadHeaderTimeout: httpHeaderTimeout,
	}
	admin := &enroll.Admin{
		Path:    opts.adminSocket,
		Tokens:  tokens,
		Allowed: srv.EnrollAllowed,
		Log:     log,
	}

	onChange := func(old, next *hubconfig.Snapshot) {
		if next.Issuer != startIssuer {
			log.Warn("Issuer settings changed; restart the hub to apply them")
		}

		srv.OnConfigChange(old, next)
	}

	log.Info(
		"Hub starting",
		slog.String("version", version),
		slog.String("tunnels", opts.tunnelAddr),
		slog.String("viewers", opts.viewerAddr),
		slog.String("ops", opts.opsAddr),
		slog.String("adminSocket", opts.adminSocket),
	)

	return runAll(ctx, log,
		component{name: "config watcher", run: func(ctx context.Context) error {
			return watcher.Run(ctx, onChange)
		}},
		component{name: "tunnel listener", run: func(ctx context.Context) error {
			return srv.ServeTunnels(ctx, tunnelLn)
		}},
		component{name: "admin socket", run: admin.Serve},
		component{name: "viewer http", run: func(ctx context.Context) error {
			return serveHTTP(ctx, log, viewer)
		}},
		component{name: "ops http", run: func(ctx context.Context) error {
			return serveHTTP(ctx, log, ops)
		}},
	)
}

type component struct {
	run  func(context.Context) error
	name string
}

// runAll runs every component until ctx is done. A component that fails, or that
// returns before ctx is done, cancels the others, and the first such error is
// returned. A clean shutdown returns nil.
func runAll(ctx context.Context, log *slog.Logger, components ...component) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var (
		wg    sync.WaitGroup
		once  sync.Once
		first error
	)

	for _, comp := range components {
		wg.Go(func() {
			err := comp.run(ctx)
			if err == nil && ctx.Err() == nil {
				err = fmt.Errorf("%s: %w", comp.name, errStopped)
			}

			if err != nil {
				log.ErrorContext(
					ctx,
					"Component failed",
					slog.String("component", comp.name),
					slog.Any("err", err),
				)
				once.Do(func() { first = err })
				cancel()
			}
		})
	}

	wg.Wait()

	return first
}

// serveHTTP serves srv until ctx is done, then shuts it down within shutdownTimeout.
func serveHTTP(ctx context.Context, log *slog.Logger, srv *http.Server) error {
	errc := make(chan error, 1)

	go func() { errc <- srv.ListenAndServe() }()

	select {
	case err := <-errc:
		return httpResult(srv.Addr, err)
	case <-ctx.Done():
	}

	sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownTimeout)
	defer cancel()

	err := srv.Shutdown(sctx)
	if err != nil {
		log.WarnContext(
			ctx,
			"Http shutdown timed out; closing connections",
			slog.String("addr", srv.Addr),
			slog.Any("err", err),
		)

		_ = srv.Close()
	}

	return httpResult(srv.Addr, <-errc)
}

// httpResult maps the result of ListenAndServe: the ErrServerClosed of a shutdown
// is not a failure.
func httpResult(addr string, err error) error {
	if err == nil || errors.Is(err, http.ErrServerClosed) {
		return nil
	}

	return fmt.Errorf("serve %s: %w", addr, err)
}

func enrollToken(args []string) error {
	var socket string

	fs := newFlagSet("enroll-token")
	fs.StringVar(
		&socket,
		"admin-socket",
		enroll.DefaultAdminSocket,
		"admin unix socket of the running hub",
	)

	err := fs.Parse(args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}

		return fmt.Errorf("enroll-token: %w", err)
	}

	if fs.NArg() != 1 {
		return errUsage
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	token, expires, err := enroll.RequestToken(ctx, socket, fs.Arg(0))
	if err != nil {
		return fmt.Errorf("enroll-token: %w", err)
	}

	fmt.Fprintln(os.Stdout, token)
	fmt.Fprintf(os.Stdout, "expires %s\n", expires.UTC().Format(time.RFC3339))

	return nil
}

func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	return fs
}
