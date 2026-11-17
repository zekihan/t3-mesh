package release

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/zekihan/t3-mesh/internal/proto"
)

// File names in the agent state directory.
const (
	StateFile           = "update-state.json"
	LauncherOutcomeFile = "launcher-outcome.json"
)

// Failure kinds.
const (
	KindRelease    = "release"
	KindDependency = "dependency"
)

// Retry policy for dependency failures.
const (
	DependencyRetryDelay  = time.Hour
	DependencyMaxAttempts = 3
)

// Failure records why a version was refused or rolled back.
type Failure struct {
	Reason      string    `json:"reason"`
	Kind        string    `json:"kind"`
	Attempts    int       `json:"attempts"`
	LastAttempt time.Time `json:"lastAttempt"`
	Final       bool      `json:"final"`
}

// State is the persistent update state (update-state.json).
type State struct {
	MinStateVersion string             `json:"minStateVersion,omitempty"`
	Failed          map[string]Failure `json:"failed,omitempty"`
}

// RecordFailure records a failed attempt of version at time at. Release
// failures are final at once; dependency failures become final after
// DependencyMaxAttempts attempts. A final failure stays final.
func (s *State) RecordFailure(version, reason, kind string, at time.Time) {
	if s.Failed == nil {
		s.Failed = map[string]Failure{}
	}
	f := s.Failed[version]
	f.Attempts++
	f.Reason = reason
	f.Kind = kind
	f.LastAttempt = at.UTC()
	if kind != KindDependency || f.Attempts >= DependencyMaxAttempts {
		f.Final = true
	}
	s.Failed[version] = f
}

// RaiseMinStateVersion raises the floor to v if v is higher; it never lowers it.
func (s *State) RaiseMinStateVersion(v string) error {
	nv, err := ParseVersion(v)
	if err != nil {
		return err
	}
	if s.MinStateVersion != "" {
		cur, err := ParseVersion(s.MinStateVersion)
		if err == nil && cur.Compare(nv) >= 0 {
			return nil
		}
	}
	s.MinStateVersion = v
	return nil
}

// FailedUpdates returns the failures for the Status message, sorted by version string.
func (s State) FailedUpdates() []proto.FailedUpdate {
	out := make([]proto.FailedUpdate, 0, len(s.Failed))
	for v, f := range s.Failed {
		out = append(
			out,
			proto.FailedUpdate{Version: v, Reason: f.Reason, Attempts: f.Attempts, Final: f.Final},
		)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Version < out[j].Version })
	return out
}

// LoadState reads the state from stateDir; a missing file is an empty state.
func LoadState(stateDir string) (State, error) {
	var s State
	b, err := os.ReadFile(filepath.Join(stateDir, StateFile))
	if errors.Is(err, fs.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return s, fmt.Errorf("read update state: %w", err)
	}
	if err := json.Unmarshal(b, &s); err != nil {
		return State{}, fmt.Errorf("parse update state: %w", err)
	}
	return s, nil
}

// SaveState writes the state atomically.
func SaveState(stateDir string, s State) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("encode update state: %w", err)
	}
	return writeFileAtomic(filepath.Join(stateDir, StateFile), append(b, '\n'), 0o600)
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	name := tmp.Name()
	fail := func(err error) error {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		return fail(fmt.Errorf("write %s: %w", path, err))
	}
	if err := tmp.Chmod(mode); err != nil {
		return fail(fmt.Errorf("chmod %s: %w", path, err))
	}
	if err := tmp.Sync(); err != nil {
		return fail(fmt.Errorf("sync %s: %w", path, err))
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return fmt.Errorf("close %s: %w", path, err)
	}
	if err := os.Rename(name, path); err != nil {
		os.Remove(name)
		return fmt.Errorf("rename to %s: %w", path, err)
	}
	return nil
}

// RecordFailure loads the state in stateDir, records the failure and saves it.
func RecordFailure(stateDir, version, reason, kind string, at time.Time) error {
	if err := checkKind(kind); err != nil {
		return err
	}
	if _, err := ParseVersion(version); err != nil {
		return err
	}
	s, err := LoadState(stateDir)
	if err != nil {
		return err
	}
	s.RecordFailure(version, reason, kind, at)
	return SaveState(stateDir, s)
}

// RecordMinStateVersion raises the persisted minStateVersion floor.
func RecordMinStateVersion(stateDir, v string) error {
	s, err := LoadState(stateDir)
	if err != nil {
		return err
	}
	if err := s.RaiseMinStateVersion(v); err != nil {
		return err
	}
	return SaveState(stateDir, s)
}

func checkKind(kind string) error {
	if kind != KindRelease && kind != KindDependency {
		return fmt.Errorf("unknown failure kind %q", kind)
	}
	return nil
}

// LauncherOutcome is the content of launcher-outcome.json, written by the
// launcher after a rollback.
type LauncherOutcome struct {
	Version string    `json:"version"`
	Reason  string    `json:"reason"`
	Kind    string    `json:"kind"`
	At      time.Time `json:"at"`
}

// IngestLauncherOutcome records a pending launcher outcome into the state and
// deletes the file. A missing file is not an error. A malformed file is
// deleted and reported as an error so it cannot wedge the agent.
func IngestLauncherOutcome(stateDir string) error {
	path := filepath.Join(stateDir, LauncherOutcomeFile)
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read launcher outcome: %w", err)
	}
	var o LauncherOutcome
	err = json.Unmarshal(b, &o)
	if err == nil {
		err = checkKind(o.Kind)
	}
	if err == nil {
		_, err = ParseVersion(o.Version)
	}
	if err != nil {
		_ = os.Remove(path)
		return fmt.Errorf("invalid launcher outcome (discarded): %w", err)
	}
	if o.At.IsZero() {
		o.At = time.Now()
	}
	if err := RecordFailure(stateDir, o.Version, o.Reason, o.Kind, o.At); err != nil {
		return err
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("remove launcher outcome: %w", err)
	}
	return nil
}
