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

	adminDeadline     = 10 * time.Second
	adminMaxLineSize  = 4 << 10
	adminMaxReplySize = 1 << 20
	adminSocketMode   = 0o600
)

// Token kinds. A token is bound to one identity of its kind; the kind decides
// which identities the hub agrees to mint a token for.
const (
	KindAgent  = "agent"
	KindDevice = "device"
)

var (
	errAdminPathNotSocket = errors.New("enroll: admin socket path is not a socket")
	errAdminRefused       = errors.New("enroll: hub refused")
	errMalformedReply     = errors.New("enroll: malformed reply")
)

const (
	opEnroll     = "enroll-token"
	opStatus     = "status"
	opTokens     = "tokens"
	opRevoke     = "revoke-token"
	opDisconnect = "disconnect"
)

type adminRequest struct {
	Op       string `json:"op"`
	Identity string `json:"identity,omitempty"`
	// Kind is KindAgent or KindDevice; absent means KindAgent for enroll-token.
	Kind    string `json:"kind,omitempty"`
	Machine string `json:"machine,omitempty"`
	Prefix  string `json:"prefix,omitempty"`
}

func (req *adminRequest) valid() bool {
	if req.Op == opEnroll {
		return req.validEnrollment()
	}

	if req.Identity != "" || req.Kind != "" {
		return false
	}

	switch req.Op {
	case opStatus, opTokens:
		return req.Machine == "" && req.Prefix == ""
	case opRevoke:
		return req.Machine == "" && tokenPrefix.MatchString(req.Prefix)
	case opDisconnect:
		return req.Machine != "" && req.Prefix == ""
	default:
		return false
	}
}

func (req *adminRequest) validEnrollment() bool {
	return req.Identity != "" && (req.Kind == KindAgent || req.Kind == KindDevice) &&
		req.Machine == "" && req.Prefix == ""
}

// MachineStatus is the machine summary returned by the admin socket.
type MachineStatus struct {
	CertNotAfter   *time.Time        `json:"certNotAfter,omitempty"`
	LastSeen       *time.Time        `json:"lastSeen,omitempty"`
	Services       map[string]string `json:"services"`
	Name           string            `json:"name"`
	Path           string            `json:"path"`
	Version        string            `json:"version"`
	DesiredVersion string            `json:"desiredVersion"`
	Alerts         []string          `json:"alerts"`
	Online         bool              `json:"online"`
}

type adminReply struct {
	Token    string          `json:"token,omitempty"`
	Expires  string          `json:"expires,omitempty"`
	Error    string          `json:"error,omitempty"`
	Machines []MachineStatus `json:"machines,omitempty"`
	Tokens   []TokenInfo     `json:"tokens,omitempty"`
}

// Admin serves the local admin protocol on a unix socket.
type Admin struct {
	Tokens *Tokens
	// Allowed decides whether a token may be minted for identity of the given kind.
	Allowed    func(kind, identity string) error
	Status     func() []MachineStatus
	Disconnect func(machine string) error
	Log        *slog.Logger
	Path       string
}

// Serve listens on Path (mode 0600, replacing a stale socket) until ctx ends.
func (admin *Admin) Serve(ctx context.Context) error {
	err := removeStaleAdminSocket(admin.Path)
	if err != nil {
		return err
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

func removeStaleAdminSocket(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}

	if err != nil {
		return fmt.Errorf("enroll: inspect admin socket: %w", err)
	}

	if info.Mode().Type() != os.ModeSocket {
		return fmt.Errorf("%w: %q", errAdminPathNotSocket, path)
	}

	err = os.Remove(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("enroll: remove stale admin socket: %w", err)
	}

	return nil
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
		admin.reply(conn, &adminReply{Error: "bad request"})

		return
	}

	var req adminRequest

	err = json.Unmarshal(
		line,
		&req,
	)
	if err != nil {
		admin.reply(conn, &adminReply{Error: "bad request"})

		return
	}

	if req.Op == opEnroll && req.Kind == "" {
		req.Kind = KindAgent
	}

	if !req.valid() {
		admin.reply(conn, &adminReply{Error: "bad request"})

		return
	}

	reply := admin.execute(&req)
	admin.reply(conn, &reply)
}

func (admin *Admin) execute(req *adminRequest) adminReply {
	switch req.Op {
	case opEnroll:
		return admin.enrollToken(req)
	case opStatus:
		if admin.Status != nil {
			return adminReply{Machines: admin.Status()}
		}
	case opTokens:
		return adminReply{Tokens: admin.Tokens.List()}
	case opRevoke:
		return adminResult(admin.Tokens.Revoke(req.Prefix))
	case opDisconnect:
		if admin.Disconnect != nil {
			return adminResult(admin.Disconnect(req.Machine))
		}
	}

	return adminReply{Error: "unsupported operation"}
}

func adminResult(err error) adminReply {
	if err != nil {
		return adminReply{Error: err.Error()}
	}

	return adminReply{}
}

func (admin *Admin) enrollToken(req *adminRequest) adminReply {
	if admin.Allowed != nil {
		err := admin.Allowed(req.Kind, req.Identity)
		if err != nil {
			admin.log().Warn(
				"Enroll token refused",
				slog.Any("identity", req.Identity),
				slog.String("kind", req.Kind),
				slog.Any("error", err),
			)

			return adminResult(err)
		}
	}

	token, expires, err := admin.Tokens.Create(req.Identity)
	if err != nil {
		admin.log().Error(
			"Enroll token creation failed",
			slog.Any("identity", req.Identity),
			slog.String("kind", req.Kind),
			slog.Any("error", err),
		)

		return adminReply{Error: "internal error"}
	}

	admin.log().Info(
		"Enroll token created",
		slog.Any("identity", req.Identity),
		slog.String("kind", req.Kind),
		slog.Any("expires", expires),
	)

	return adminReply{Token: token, Expires: expires.UTC().Format(time.RFC3339)}
}

func (admin *Admin) reply(conn net.Conn, r *adminReply) {
	data, err := json.Marshal(r)
	if err != nil {
		// Marshaling only fails if a time is out of range.
		return
	}

	//nolint:errcheck // best-effort response; the client may already be gone
	_, _ = conn.Write(
		append(data, '\n'),
	)
}

// RequestToken asks the running hub for an enrollment token for identity of the
// given kind (KindAgent or KindDevice).
func RequestToken(
	ctx context.Context,
	socketPath, kind, identity string,
) (string, time.Time, error) {
	rep, err := requestAdmin(
		ctx,
		socketPath,
		&adminRequest{Op: opEnroll, Identity: identity, Kind: kind},
	)
	if err != nil {
		return "", time.Time{}, err
	}

	expires, err := time.Parse(time.RFC3339, rep.Expires)
	if err != nil || rep.Token == "" {
		return "", time.Time{}, errMalformedReply
	}

	return rep.Token, expires, nil
}

func RequestStatus(ctx context.Context, socketPath string) ([]MachineStatus, error) {
	rep, err := requestAdmin(ctx, socketPath, &adminRequest{Op: opStatus})

	return rep.Machines, err
}

func RequestTokens(ctx context.Context, socketPath string) ([]TokenInfo, error) {
	rep, err := requestAdmin(ctx, socketPath, &adminRequest{Op: opTokens})

	return rep.Tokens, err
}

func RevokeToken(ctx context.Context, socketPath, prefix string) error {
	_, err := requestAdmin(ctx, socketPath, &adminRequest{Op: opRevoke, Prefix: prefix})

	return err
}

func Disconnect(ctx context.Context, socketPath, machine string) error {
	_, err := requestAdmin(ctx, socketPath, &adminRequest{Op: opDisconnect, Machine: machine})

	return err
}

func requestAdmin(ctx context.Context, socketPath string, req *adminRequest) (adminReply, error) {
	ctx, cancel := context.WithTimeout(ctx, adminDeadline)
	defer cancel()

	var d net.Dialer

	conn, err := d.DialContext(ctx, "unix", socketPath)
	if err != nil {
		return adminReply{}, fmt.Errorf("enroll: dial admin socket: %w", err)
	}

	defer func() { _ = conn.Close() }()

	if dl, ok := ctx.Deadline(); ok {
		//nolint:errcheck // best-effort deadline; a dead connection fails the next read or write
		_ = conn.SetDeadline(
			dl,
		)
	}

	data, err := json.Marshal(req)
	if err != nil {
		return adminReply{}, fmt.Errorf("enroll: marshal request: %w", err)
	}

	_, err = conn.Write(append(data, '\n'))
	if err != nil {
		return adminReply{}, fmt.Errorf("enroll: send request: %w", err)
	}

	line, err := bufio.NewReaderSize(io.LimitReader(conn, adminMaxReplySize), adminMaxLineSize).
		ReadBytes('\n')
	if err != nil {
		return adminReply{}, fmt.Errorf("enroll: read reply: %w", err)
	}

	var rep adminReply

	err = json.Unmarshal(line, &rep)
	if err != nil {
		return adminReply{}, fmt.Errorf("enroll: parse reply: %w", err)
	}

	if rep.Error != "" {
		return adminReply{}, fmt.Errorf("%w: %s", errAdminRefused, rep.Error)
	}

	return rep, nil
}
