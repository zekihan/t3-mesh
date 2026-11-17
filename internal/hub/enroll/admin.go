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
	Path    string
	Tokens  *Tokens
	Allowed func(identity string) error
	Log     *slog.Logger
}

func (a *Admin) log() *slog.Logger {
	if a.Log != nil {
		return a.Log
	}

	return slog.New(slog.DiscardHandler)
}

// Serve listens on Path (mode 0600, replacing a stale socket) until ctx ends.
func (a *Admin) Serve(ctx context.Context) error {
	if err := os.Remove(a.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("enroll: remove stale admin socket: %w", err)
	}

	var lc net.ListenConfig

	ln, err := lc.Listen(ctx, "unix", a.Path)
	if err != nil {
		return fmt.Errorf("enroll: listen admin socket: %w", err)
	}

	defer func() { _ = os.Remove(a.Path) }()

	if err = os.Chmod(a.Path, 0o600); err != nil {
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

		wg.Add(1)

		go func() {
			defer wg.Done()
			a.handle(conn)
		}()
	}
}

func (a *Admin) handle(conn net.Conn) {
	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(adminDeadline))

	line, err := bufio.NewReaderSize(io.LimitReader(conn, adminMaxLineSize), adminMaxLineSize).
		ReadBytes('\n')
	if err != nil {
		a.reply(conn, adminReply{Error: "bad request"})

		return
	}

	var req adminRequest
	if err = json.Unmarshal(
		line,
		&req,
	); err != nil || req.Op != "enroll-token" ||
		req.Identity == "" {
		a.reply(conn, adminReply{Error: "bad request"})

		return
	}

	if a.Allowed != nil {
		if err = a.Allowed(req.Identity); err != nil {
			a.log().Warn("enroll token refused", "identity", req.Identity, "error", err)
			a.reply(conn, adminReply{Error: err.Error()})

			return
		}
	}

	token, expires, err := a.Tokens.Create(req.Identity)
	if err != nil {
		a.log().Error("enroll token creation failed", "identity", req.Identity, "error", err)
		a.reply(conn, adminReply{Error: "internal error"})

		return
	}

	a.log().Info("enroll token created", "identity", req.Identity, "expires", expires)
	a.reply(conn, adminReply{Token: token, Expires: expires.UTC().Format(time.RFC3339)})
}

func (a *Admin) reply(conn net.Conn, r adminReply) {
	data, _ := json.Marshal(r)
	_, _ = conn.Write(append(data, '\n'))
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
		_ = conn.SetDeadline(dl)
	}

	data, err := json.Marshal(adminRequest{Op: "enroll-token", Identity: identity})
	if err != nil {
		return "", time.Time{}, fmt.Errorf("enroll: marshal request: %w", err)
	}

	if _, err = conn.Write(append(data, '\n')); err != nil {
		return "", time.Time{}, fmt.Errorf("enroll: send request: %w", err)
	}

	line, err := bufio.NewReaderSize(io.LimitReader(conn, adminMaxLineSize), adminMaxLineSize).
		ReadBytes('\n')
	if err != nil {
		return "", time.Time{}, fmt.Errorf("enroll: read reply: %w", err)
	}

	var rep adminReply
	if err = json.Unmarshal(line, &rep); err != nil {
		return "", time.Time{}, fmt.Errorf("enroll: parse reply: %w", err)
	}

	if rep.Error != "" {
		return "", time.Time{}, fmt.Errorf("enroll: hub refused: %s", rep.Error)
	}

	expires, err := time.Parse(time.RFC3339, rep.Expires)
	if err != nil || rep.Token == "" {
		return "", time.Time{}, errors.New("enroll: malformed reply")
	}

	return rep.Token, expires, nil
}
