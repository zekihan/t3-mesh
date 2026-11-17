package release

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/zekihan/t3-mesh/internal/proto"
)

// Decision is the outcome of Decide.
type Decision int

// Decisions.
const (
	Skip Decision = iota
	Install
)

func (d Decision) String() string {
	if d == Install {
		return "install"
	}
	return "skip"
}

// Decide says whether to install the hub's advertised release while running
// the given version. The returned string is a human-readable reason.
func Decide(running Version, rel proto.Release, st State, now time.Time) (Decision, string) {
	target, err := ParseVersion(rel.Version)
	if err != nil {
		return Skip, fmt.Sprintf("invalid release version: %v", err)
	}
	cmp := target.Compare(running)
	if cmp == 0 {
		return Skip, "already running " + rel.Version
	}
	if st.MinStateVersion != "" {
		floor, err := ParseVersion(st.MinStateVersion)
		if err != nil {
			return Skip, fmt.Sprintf("invalid recorded minStateVersion %q: %v", st.MinStateVersion, err)
		}
		if target.Compare(floor) < 0 {
			return Skip, fmt.Sprintf("%s is older than minStateVersion %s", rel.Version, st.MinStateVersion)
		}
	}
	if cmp < 0 && !rel.RollbackAllowed {
		return Skip, fmt.Sprintf("%s is older than running %s and rollback is not allowed", rel.Version, running)
	}
	if f, ok := st.Failed[target.String()]; ok {
		if f.Final {
			return Skip, fmt.Sprintf("%s failed permanently: %s", rel.Version, f.Reason)
		}
		if f.Kind == KindDependency {
			if next := f.LastAttempt.Add(DependencyRetryDelay); now.Before(next) {
				return Skip, fmt.Sprintf("%s failed on a dependency (attempt %d); retry after %s", rel.Version, f.Attempts, next.UTC().Format(time.RFC3339))
			}
		}
	}
	return Install, "install " + rel.Version
}

// Preconditions limits.
const (
	HelloAckMaxAge = time.Minute
	DialTimeout    = 2 * time.Second
)

// Preconditions returns nil only if every serve target accepts a TCP
// connection and a HelloAck was received within the last minute.
func Preconditions(ctx context.Context, serveTargets []string, lastHelloAck, now time.Time) error {
	if lastHelloAck.IsZero() {
		return errors.New("no HelloAck received yet")
	}
	if age := now.Sub(lastHelloAck); age > HelloAckMaxAge {
		return fmt.Errorf("last HelloAck was %s ago", age.Round(time.Second))
	}
	d := net.Dialer{Timeout: DialTimeout}
	for _, t := range serveTargets {
		c, err := d.DialContext(ctx, "tcp", t)
		if err != nil {
			return fmt.Errorf("serve target %s: %w", t, err)
		}
		_ = c.Close()
	}
	return nil
}
