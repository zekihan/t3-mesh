package launcher

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"sync"
)

// HealthFDEnv names the environment variable that carries the health pipe's
// file descriptor into the child.
const HealthFDEnv = "T3_MESH_HEALTH_FD"

// Failure kinds for Health.Fail and the outcome file.
const (
	KindRelease    = "release"
	KindDependency = "dependency"
)

// Message is one JSON line on the health pipe.
type Message struct {
	Type   string `json:"type"`
	Reason string `json:"reason,omitempty"`
	Kind   string `json:"kind,omitempty"`
}

// Health is the child's end of the health pipe. The zero value is a no-op.
type Health struct {
	mu sync.Mutex
	f  *os.File
}

// OpenHealth opens the health pipe named by the environment. Outside a
// launcher it returns a Health whose methods do nothing.
func OpenHealth() (*Health, error) {
	v := os.Getenv(HealthFDEnv)
	if v == "" {
		return &Health{}, nil
	}
	fd, err := strconv.Atoi(v)
	if err != nil || fd < 3 {
		return nil, fmt.Errorf("launcher: invalid %s %q", HealthFDEnv, v)
	}
	f := os.NewFile(uintptr(fd), "health")
	if f == nil {
		return nil, fmt.Errorf("launcher: bad health fd %d", fd)
	}
	return &Health{f: f}, nil
}

func (h *Health) send(m Message) error {
	if h == nil || h.f == nil {
		return nil
	}
	b, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("launcher: encode health message: %w", err)
	}
	b = append(b, '\n')
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, err := h.f.Write(b); err != nil {
		return fmt.Errorf("launcher: write health message: %w", err)
	}
	return nil
}

// Ready reports that the local startup check passed.
func (h *Health) Ready() error { return h.send(Message{Type: "ready"}) }

// Alive reports liveness; send it at least every 10 seconds.
func (h *Health) Alive() error { return h.send(Message{Type: "alive"}) }

// Restart asks the launcher to stop this child and start the binary that
// current points at, for example after the agent staged a new version.
func (h *Health) Restart() error { return h.send(Message{Type: "restart"}) }

// Promote reports that probation passed.
func (h *Health) Promote() error { return h.send(Message{Type: "promote"}) }

// Fail asks the launcher to roll back. kind is KindRelease or KindDependency.
func (h *Health) Fail(reason, kind string) error {
	return h.send(Message{Type: "fail", Reason: reason, Kind: kind})
}
