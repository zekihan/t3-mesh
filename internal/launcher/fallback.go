package launcher

import (
	"errors"
	"fmt"
	"os"
	"time"
)

// Fallback repoints known-good and current at previous-good when the launcher
// heartbeat is older than maxAge (or missing). It reports whether it did so.
// It is a no-op when previous-good is already known-good.
func Fallback(l Layout, heartbeatPath string, maxAge time.Duration, now time.Time) (bool, error) {
	info, err := os.Stat(heartbeatPath)
	switch {
	case err == nil:
		if now.Sub(info.ModTime()) <= maxAge {
			return false, nil
		}
	case errors.Is(err, os.ErrNotExist):
	default:
		return false, fmt.Errorf("launcher: stat heartbeat: %w", err)
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
	return true, nil
}
