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

const (
	stateFileMode = 0o600
)

var errUnknownKind = errors.New("unknown failure kind")

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
type Failure struct { //nolint:govet // JSON field order is the file format
	Reason      string    `json:"reason"`
	Kind        string    `json:"kind"`
	Attempts    int       `json:"attempts"`
	LastAttempt time.Time `json:"lastAttempt"`
	Final       bool      `json:"final"`
}

// State is the persistent update state (update-state.json).
type State struct { //nolint:govet,recvcheck // JSON order is the file format; one read-only method
	MinStateVersion string             `json:"minStateVersion,omitempty"`
	Failed          map[string]Failure `json:"failed,omitempty"`
}

// RecordFailure records a failed attempt of version at time at. Release
// failures are final at once; dependency failures become final after
// DependencyMaxAttempts attempts. A final failure stays final.
func (st *State) RecordFailure(version, reason, kind string, at time.Time) {
	if st.Failed == nil {
		st.Failed = map[string]Failure{}
	}

	fail := st.Failed[version]
	fail.Attempts++
	fail.Reason = reason
	fail.Kind = kind

	fail.LastAttempt = at.UTC()
	if kind != KindDependency || fail.Attempts >= DependencyMaxAttempts {
		fail.Final = true
	}

	st.Failed[version] = fail
}

// RaiseMinStateVersion raises the floor to v if v is higher; it never lowers it.
func (st *State) RaiseMinStateVersion(ver string) error {
	nv, err := ParseVersion(ver)
	if err != nil {
		return err
	}

	if st.MinStateVersion != "" {
		cur, err := ParseVersion(st.MinStateVersion)
		if err == nil && cur.Compare(nv) >= 0 {
			return nil
		}
	}

	st.MinStateVersion = ver

	return nil
}

// FailedUpdates returns the failures for the Status message, sorted by version string.
func (st State) FailedUpdates() []proto.FailedUpdate {
	out := make([]proto.FailedUpdate, 0, len(st.Failed))
	for v, f := range st.Failed {
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
	var st State

	data, err := os.ReadFile(filepath.Join(stateDir, StateFile))
	if errors.Is(err, fs.ErrNotExist) {
		return st, nil
	}

	if err != nil {
		return st, fmt.Errorf("read update state: %w", err)
	}

	err = json.Unmarshal(data, &st)
	if err != nil {
		return State{}, fmt.Errorf("parse update state: %w", err)
	}

	return st, nil
}

// SaveState writes the state atomically.
func SaveState(stateDir string, s State) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("encode update state: %w", err)
	}

	return writeFileAtomic(filepath.Join(stateDir, StateFile), append(b, '\n'), stateFileMode)
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)

	err := os.MkdirAll(dir, dirMode)
	if err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}

	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}

	name := tmp.Name()

	fail := func(err error) error {
		_ = tmp.Close()
		_ = os.Remove(name)

		return err
	}

	_, err = tmp.Write(data)
	if err != nil {
		return fail(fmt.Errorf("write %s: %w", path, err))
	}

	err = tmp.Chmod(mode)
	if err != nil {
		return fail(fmt.Errorf("chmod %s: %w", path, err))
	}

	err = tmp.Sync()
	if err != nil {
		return fail(fmt.Errorf("sync %s: %w", path, err))
	}

	err = tmp.Close()
	if err != nil {
		_ = os.Remove(name)

		return fmt.Errorf("close %s: %w", path, err)
	}

	err = os.Rename(name, path)
	if err != nil {
		_ = os.Remove(name)

		return fmt.Errorf("rename to %s: %w", path, err)
	}

	return nil
}

// RecordFailure loads the state in stateDir, records the failure and saves it.
func RecordFailure(stateDir, version, reason, kind string, at time.Time) error {
	err := checkKind(kind)
	if err != nil {
		return err
	}

	_, err = ParseVersion(version)
	if err != nil {
		return err
	}

	st, err := LoadState(stateDir)
	if err != nil {
		return err
	}

	st.RecordFailure(version, reason, kind, at)

	return SaveState(stateDir, st)
}

// RecordMinStateVersion raises the persisted minStateVersion floor.
func RecordMinStateVersion(stateDir, v string) error {
	st, err := LoadState(stateDir)
	if err != nil {
		return err
	}

	err = st.RaiseMinStateVersion(v)
	if err != nil {
		return err
	}

	return SaveState(stateDir, st)
}

func checkKind(kind string) error {
	if kind != KindRelease && kind != KindDependency {
		return fmt.Errorf("%w %q", errUnknownKind, kind)
	}

	return nil
}

// LauncherOutcome is the content of launcher-outcome.json, written by the
// launcher after a rollback.
type LauncherOutcome struct { //nolint:govet // JSON field order is the file format
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

	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}

	if err != nil {
		return fmt.Errorf("read launcher outcome: %w", err)
	}

	var out LauncherOutcome

	err = json.Unmarshal(data, &out)
	if err == nil {
		err = checkKind(out.Kind)
	}

	if err == nil {
		_, err = ParseVersion(out.Version)
	}

	if err != nil {
		_ = os.Remove(path)

		return fmt.Errorf("invalid launcher outcome (discarded): %w", err)
	}

	if out.At.IsZero() {
		out.At = time.Now()
	}

	err = RecordFailure(stateDir, out.Version, out.Reason, out.Kind, out.At)
	if err != nil {
		return err
	}

	err = os.Remove(path)
	if err != nil {
		return fmt.Errorf("remove launcher outcome: %w", err)
	}

	return nil
}
