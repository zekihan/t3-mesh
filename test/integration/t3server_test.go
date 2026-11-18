package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// t3BinaryEnv names the t3 executable the compatibility test runs against. Without
// it the test is skipped, so a plain `go test ./...` needs no T3.
const t3BinaryEnv = "T3_COMPAT_BINARY"

const (
	t3ReadyTimeout = 120 * time.Second
	t3StopTimeout  = 15 * time.Second
	t3LogTail      = 8192
)

var errT3NotReady = errors.New("t3 serve did not become ready")

// logBuffer collects a process's output while tests read it.
type logBuffer struct {
	buf bytes.Buffer
	mu  sync.Mutex
}

func (lb *logBuffer) Write(p []byte) (int, error) {
	lb.mu.Lock()
	defer lb.mu.Unlock()

	return lb.buf.Write(p) //nolint:wrapcheck // bytes.Buffer
}

func (lb *logBuffer) tail() string {
	lb.mu.Lock()
	defer lb.mu.Unlock()

	out := lb.buf.String()
	if len(out) > t3LogTail {
		out = "..." + out[len(out)-t3LogTail:]
	}

	return out
}

// t3Server is a real upstream `t3 serve` on loopback, with its own data directory
// and project, apart from any T3 the machine runs.
type t3Server struct {
	log     *logBuffer
	bin     string
	baseDir string
	addr    string
	version string
}

// startT3 runs `t3 serve` from bin and waits until it answers.
func startT3(t *testing.T, bin string) *t3Server {
	t.Helper()

	srv := &t3Server{
		bin:     bin,
		baseDir: t.TempDir(),
		log:     &logBuffer{},
	}
	project := t.TempDir()

	for _, args := range [][]string{
		{"init", "-q"},
		{"-c", "user.name=compat", "-c", "user.email=compat@example.test", "commit", "-q", "--allow-empty", "-m", "init"},
	} {
		cmd := exec.CommandContext(t.Context(), "git", args...)
		cmd.Dir = project

		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %s: %v\n%s", args[0], err, out)
		}
	}

	port := freePort(t, "127.0.0.1")
	srv.addr = "127.0.0.1:" + strconv.Itoa(port)

	//nolint:gosec // bin is the executable the operator chose to test
	cmd := exec.CommandContext(
		t.Context(), bin, "serve", "--port", strconv.Itoa(port), "--host", "127.0.0.1",
		"--base-dir", srv.baseDir, project,
	)
	cmd.Dir = project
	cmd.Env = t3Env()
	cmd.Stdout = srv.log
	cmd.Stderr = srv.log
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	// Stop the whole group, which holds anything a launcher script started.
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM) }
	cmd.WaitDelay = t3StopTimeout

	err := cmd.Start()
	if err != nil {
		t.Fatalf("start %s serve: %v", bin, err)
	}

	exited := make(chan struct{})

	go func() {
		_ = cmd.Wait()

		close(exited)
	}()

	t.Cleanup(func() {
		stopGroup(cmd.Process.Pid, exited)

		if t.Failed() {
			t.Logf("t3 serve output (tail):\n%s", srv.log.tail())
		}
	})

	err = srv.waitReady(t.Context(), exited)
	if err != nil {
		t.Fatalf("%v\n%s", err, srv.log.tail())
	}

	return srv
}

// t3Env is the environment of the T3 under test: the caller's, minus anything that
// would point it at another T3's data.
func t3Env() []string {
	var env []string

	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "T3CODE_") || strings.HasPrefix(kv, "VITE_") {
			continue
		}

		env = append(env, kv)
	}

	return env
}

// stopGroup ends the process group of pid, which includes any child a launcher
// script started.
func stopGroup(pid int, exited <-chan struct{}) {
	_ = syscall.Kill(-pid, syscall.SIGTERM)

	select {
	case <-exited:
	case <-time.After(t3StopTimeout):
		_ = syscall.Kill(-pid, syscall.SIGKILL)

		<-exited
	}
}

func (srv *t3Server) waitReady(ctx context.Context, exited <-chan struct{}) error {
	ctx, cancel := context.WithTimeout(ctx, t3ReadyTimeout)
	defer cancel()

	url := "http://" + srv.addr + "/.well-known/t3/environment"

	for {
		select {
		case <-exited:
			return fmt.Errorf("%w: the process exited", errT3NotReady)
		case <-ctx.Done():
			return fmt.Errorf("%w within %s", errT3NotReady, t3ReadyTimeout)
		case <-time.After(250 * time.Millisecond):
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
		if err != nil {
			return fmt.Errorf("request: %w", err)
		}

		resp, err := httpc.Do(req)
		if err != nil {
			continue
		}

		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()

		var env struct {
			ServerVersion string `json:"serverVersion"`
		}

		if resp.StatusCode == http.StatusOK && json.Unmarshal(body, &env) == nil &&
			env.ServerVersion != "" {
			srv.version = env.ServerVersion

			return nil
		}
	}
}

// pairingCredential mints a one-time pairing credential with the t3 CLI, as an
// operator does to add a device.
func (srv *t3Server) pairingCredential(t *testing.T) string {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()

	//nolint:gosec // bin is the executable the operator chose to test
	cmd := exec.CommandContext(
		ctx, srv.bin, "auth", "pairing", "create",
		"--base-dir", srv.baseDir, "--ttl", "1h", "--json",
	)
	cmd.Env = t3Env()

	var stderr bytes.Buffer

	cmd.Stderr = &stderr

	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("t3 auth pairing create: %v\n%s", err, stderr.String())
	}

	var doc struct {
		Credential string `json:"credential"`
	}

	err = json.Unmarshal(out, &doc)
	if err != nil || doc.Credential == "" {
		t.Fatalf("t3 auth pairing create printed no credential: %q (%v)", out, err)
	}

	return doc.Credential
}
