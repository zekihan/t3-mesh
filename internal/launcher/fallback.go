package launcher

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// fallbackReason is recorded for a version the fallback abandons.
const fallbackReason = "launcher failed after promotion; fallback to previous-good"

// Fallback repoints known-good and current at previous-good when the launcher
// heartbeat has been stale (older than maxAge, or missing) on two calls at
// least maxAge apart, with no heartbeat in between. One stale reading is not
// enough: right after a wake from sleep the heartbeat is old although the
// launcher is healthy and about to touch it. It reports whether it repointed.
// It is a no-op when previous-good is already known-good. The abandoned version is
// recorded in stateDir as a failed release (see FallbackAndRecord).
func Fallback(
	lay Layout,
	stateDir, heartbeatPath string,
	maxAge time.Duration,
	now time.Time,
) (bool, error) {
	beat, err := heartbeatTime(heartbeatPath)
	if err != nil {
		return false, err
	}

	suspectPath := heartbeatPath + ".suspect"

	if !beat.IsZero() && now.Sub(beat) <= maxAge {
		_ = os.Remove(suspectPath)

		return false, nil
	}

	suspect, err := os.Stat(suspectPath)
	if err != nil || (!beat.IsZero() && beat.After(suspect.ModTime())) {
		err = touchAt(suspectPath, now)
		if err != nil {
			return false, fmt.Errorf("launcher: record stale heartbeat: %w", err)
		}

		return false, nil
	}

	if now.Sub(suspect.ModTime()) < maxAge {
		return false, nil
	}

	pg, err := lay.PreviousGood()
	if err != nil {
		return false, fmt.Errorf("launcher: fallback: %w", err)
	}

	if alreadyAt(lay, pg) {
		return false, nil
	}

	err = FallbackAndRecord(lay, stateDir, now)
	if err != nil {
		return false, err
	}

	_ = os.Remove(suspectPath)

	return true, nil
}

// FallbackAndRecord points known-good and current at previous-good and, when that
// abandons a different version, writes a launcher outcome to stateDir marking it a
// failed release. Without the record, the agent running previous-good would
// install the abandoned version again as soon as the hub advertises it. An empty
// stateDir skips the record.
func FallbackAndRecord(lay Layout, stateDir string, now time.Time) error {
	abandoned, err := lay.KnownGood()
	if err != nil {
		return fmt.Errorf("launcher: fallback: %w", err)
	}

	pg, err := lay.PreviousGood()
	if err != nil {
		return fmt.Errorf("launcher: fallback: %w", err)
	}

	err = lay.FallbackToPrevious()
	if err != nil {
		return err
	}

	if stateDir == "" || abandoned == pg {
		return nil
	}

	out := Outcome{
		Version: abandoned,
		Reason:  fallbackReason,
		Kind:    KindRelease,
		At:      now.UTC().Format(time.RFC3339),
	}

	return writeJSONAtomic(filepath.Join(stateDir, OutcomeFile), out)
}

// heartbeatTime returns the heartbeat's modification time, zero when missing.
func heartbeatTime(path string) (time.Time, error) {
	info, err := os.Stat(path)

	switch {
	case err == nil:
		return info.ModTime(), nil
	case errors.Is(err, os.ErrNotExist):
		return time.Time{}, nil
	default:
		return time.Time{}, fmt.Errorf("launcher: stat heartbeat: %w", err)
	}
}

// alreadyAt reports whether known-good and current both point at version.
func alreadyAt(l Layout, version string) bool {
	kg, err := l.KnownGood()
	if err != nil || kg != version {
		return false
	}

	cur, err := l.Current()

	return err == nil && cur == version
}
