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
func Fallback(l Layout, heartbeatPath string, maxAge time.Duration, now time.Time) (bool, error) {
	var beat time.Time

	info, err := os.Stat(heartbeatPath)
	switch {
	case err == nil:
		beat = info.ModTime()
	case errors.Is(err, os.ErrNotExist):
	default:
		return false, fmt.Errorf("launcher: stat heartbeat: %w", err)
	}

	suspectPath := heartbeatPath + ".suspect"

	if !beat.IsZero() && now.Sub(beat) <= maxAge {
		_ = os.Remove(suspectPath)

		return false, nil
	}

	suspect, err := os.Stat(suspectPath)
	if err != nil || (!beat.IsZero() && beat.After(suspect.ModTime())) {
		if err := touchAt(suspectPath, now); err != nil {
			return false, fmt.Errorf("launcher: record stale heartbeat: %w", err)
		}

		return false, nil
	}

	if now.Sub(suspect.ModTime()) < maxAge {
		return false, nil
	}
	pg, err := l.PreviousGood()
	if err != nil {
		return false, fmt.Errorf("launcher: fallback: %w", err)
	}
	kg, err := l.KnownGood()
	if err == nil && kg == pg {
		cur, cerr := l.Current()
		if cerr == nil && cur == pg {
			return false, nil
		}
	}
	if err := l.FallbackToPrevious(); err != nil {
		return false, err
	}
	_ = os.Remove(suspectPath)
	return true, nil
}
