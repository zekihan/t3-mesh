package launcher

import (
	"errors"
	"fmt"
	"os"
	"time"
)

// Fallback repoints known-good and current at previous-good when the launcher
// heartbeat has been stale (older than maxAge, or missing) on two calls at
// least maxAge apart, with no heartbeat in between. One stale reading is not
// enough: right after a wake from sleep the heartbeat is old although the
// launcher is healthy and about to touch it. It reports whether it repointed.
// It is a no-op when previous-good is already known-good.
func Fallback(lay Layout, heartbeatPath string, maxAge time.Duration, now time.Time) (bool, error) {
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

	err = lay.FallbackToPrevious()
	if err != nil {
		return false, err
	}

	_ = os.Remove(suspectPath)

	return true, nil
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
