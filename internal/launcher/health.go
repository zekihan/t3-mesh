package launcher

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"sync"
)

// Message types written by a child on the health pipe.
const (
	msgReady   = "ready"
	msgRestart = "restart"
	msgPromote = "promote"
	msgFail    = "fail"
)

var errBadHealthFD = errors.New("bad health fd")

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
	f  *os.File
	mu sync.Mutex
}

// OpenHealth opens the health pipe named by the environment. Outside a
// launcher it returns a Health whose methods do nothing.
func OpenHealth() (*Health, error) {
	val := os.Getenv(HealthFDEnv)
	if val == "" {
		return &Health{}, nil
	}

	fd, err := strconv.Atoi(val)
	if err != nil || fd < 3 {
		return nil, fmt.Errorf("launcher: %w %s %q", errInvalid, HealthFDEnv, val)
	}

	f := os.NewFile(uintptr(fd), "health")
	if f == nil {
		return nil, fmt.Errorf("launcher: %w %d", errBadHealthFD, fd)
	}

	return &Health{f: f}, nil
}

// Ready reports that the local startup check passed.
func (health *Health) Ready() error { return health.send(Message{Type: msgReady}) }

// Alive reports liveness; send it at least every 10 seconds.
func (health *Health) Alive() error { return health.send(Message{Type: "alive"}) }

// Restart asks the launcher to stop this child and start the binary that
// current points at, for example after the agent staged a new version.
func (health *Health) Restart() error { return health.send(Message{Type: msgRestart}) }

// Promote reports that probation passed.
func (health *Health) Promote() error { return health.send(Message{Type: msgPromote}) }

// Fail asks the launcher to roll back; the kind is KindRelease or KindDependency.
func (health *Health) Fail(reason, kind string) error {
	return health.send(Message{Type: msgFail, Reason: reason, Kind: kind})
}

func (health *Health) send(m Message) error {
	if health == nil || health.f == nil {
		return nil
	}

	data, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("launcher: encode health message: %w", err)
	}

	data = append(data, '\n')

	health.mu.Lock()
	defer health.mu.Unlock()

	_, err = health.f.Write(data)
	if err != nil {
		return fmt.Errorf("launcher: write health message: %w", err)
	}

	return nil
}
