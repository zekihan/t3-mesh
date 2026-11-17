package enroll

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"sync"
	"time"
)

const (
	// DefaultAdminSocket is the admin socket path inside the hub pod.
	DefaultAdminSocket = "/run/t3-mesh/admin.sock"

	adminDeadline    = 10 * time.Second
	adminMaxLineSize = 4 << 10
	adminSocketMode  = 0o600
)

var (
	errAdminRefused   = errors.New("enroll: hub refused")
	errMalformedReply = errors.New("enroll: malformed reply")
)

type adminRequest struct {
	Op       string `json:"op"`
	Identity string `json:"identity"`
}

type adminReply struct {
	Token   string `json:"token,omitempty"`
	Expires string `json:"expires,omitempty"`
	Error   string `json:"error,omitempty"`
}

// Admin serves the enroll-token admin protocol on a unix socket.
type Admin struct {
	Tokens  *Tokens
	Allowed func(identity string) error
	Log     *slog.Logger
	Path    string
}

// Serve listens on Path (mode 0600, replacing a stale socket) until ctx ends.
func (admin *Admin) Serve(ctx context.Context) error {
	err := os.Remove(admin.Path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("enroll: remove stale admin socket: %w", err)
	}

	var lc net.ListenConfig

	ln, err := lc.Listen(ctx, "unix", admin.Path)
	if err != nil {
		return fmt.Errorf("enroll: listen admin socket: %w", err)
	}

	defer func() { _ = os.Remove(admin.Path) }()

	err = os.Chmod(admin.Path, adminSocketMode)
	if err != nil {
		_ = ln.Close()

		return fmt.Errorf("enroll: chmod admin socket: %w", err)
	}

	go func() {
		<-ctx.Done()

		_ = ln.Close()
	}()

	var wg sync.WaitGroup
	defer wg.Wait()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}

			return fmt.Errorf("enroll: accept admin connection: %w", err)
		}

		wg.Go(func() {
			admin.handle(conn)
		})
	}
}

func (admin *Admin) log() *slog.Logger {
	if admin.Log != nil {
		return admin.Log
	}

	return slog.New(slog.DiscardHandler)
}

func (admin *Admin) handle(conn net.Conn) {
	defer func() { _ = conn.Close() }()

	//nolint:errcheck // best-effort deadline; a dead connection fails the next read or write
	_ = conn.SetDeadline(
		time.Now().Add(adminDeadline),
	)

	line, err := bufio.NewReaderSize(io.LimitReader(conn, adminMaxLineSize), adminMaxLineSize).
		ReadBytes('\n')
	if err != nil {
		admin.reply(conn, adminReply{Error: "bad request"})

		return
	}

	var req adminRequest

	err = json.Unmarshal(
		line,
		&req,
	)
	if err != nil || req.Op != "enroll-token" ||
		req.Identity == "" {
		admin.reply(conn, adminReply{Error: "bad request"})

		return
	}

	if admin.Allowed != nil {
		err = admin.Allowed(req.Identity)
		if err != nil {
			admin.log().Warn(
				"Enroll token refused",
				slog.Any("identity", req.Identity),
				slog.Any("error", err),
			)
			admin.reply(conn, adminReply{Error: err.Error()})

			return
		}
	}

	token, expires, err := admin.Tokens.Create(req.Identity)
	if err != nil {
		admin.log().Error(
			"Enroll token creation failed",
			slog.Any("identity", req.Identity),
			slog.Any("error", err),
		)
		admin.reply(conn, adminReply{Error: "internal error"})

		return
	}

	admin.log().Info(
		"Enroll token created",
		slog.Any("identity", req.Identity),
		slog.Any("expires", expires),
	)
	admin.reply(conn, adminReply{Token: token, Expires: expires.UTC().Format(time.RFC3339)})
}

func (admin *Admin) reply(conn net.Conn, r adminReply) {
	data, err := json.Marshal(r)
	if err != nil {
		// The reply holds only strings, so marshaling cannot fail.
		return
	}

	//nolint:errcheck // best-effort response; the client may already be gone
	_, _ = conn.Write(
		append(data, '\n'),
	)
}

// RequestToken asks the running hub for an enrollment token for identity.
func RequestToken(ctx context.Context, socketPath, identity string) (string, time.Time, error) {
	ctx, cancel := context.WithTimeout(ctx, adminDeadline)
	defer cancel()

	var d net.Dialer

	conn, err := d.DialContext(ctx, "unix", socketPath)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("enroll: dial admin socket: %w", err)
	}

	defer func() { _ = conn.Close() }()

	if dl, ok := ctx.Deadline(); ok {
		//nolint:errcheck // best-effort deadline; a dead connection fails the next read or write
		_ = conn.SetDeadline(
			dl,
		)
	}

	data, err := json.Marshal(adminRequest{Op: "enroll-token", Identity: identity})
	if err != nil {
		return "", time.Time{}, fmt.Errorf("enroll: marshal request: %w", err)
	}

	_, err = conn.Write(append(data, '\n'))
	if err != nil {
		return "", time.Time{}, fmt.Errorf("enroll: send request: %w", err)
	}

	line, err := bufio.NewReaderSize(io.LimitReader(conn, adminMaxLineSize), adminMaxLineSize).
		ReadBytes('\n')
	if err != nil {
		return "", time.Time{}, fmt.Errorf("enroll: read reply: %w", err)
	}

	var rep adminReply

	err = json.Unmarshal(line, &rep)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("enroll: parse reply: %w", err)
	}

	if rep.Error != "" {
		return "", time.Time{}, fmt.Errorf("%w: %s", errAdminRefused, rep.Error)
	}

	expires, err := time.Parse(time.RFC3339, rep.Expires)
	if err != nil || rep.Token == "" {
		return "", time.Time{}, errMalformedReply
	}

	return rep.Token, expires, nil
}
