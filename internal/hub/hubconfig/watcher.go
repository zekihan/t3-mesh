package hubconfig

import (
	"context"
	"crypto/x509"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fsnotify/fsnotify"
)

// Stale-config thresholds.
const (
	StalePolicyAfter = 10 * time.Minute
	StaleCertWindow  = 14 * 24 * time.Hour
)

// Paths are the three mounted directories.
type Paths struct{ ConfigDir, TrustDir, CertDir string }

// Watcher keeps the current Snapshot up to date.
type Watcher struct {
	paths Paths
	log   *slog.Logger
	cur   atomic.Pointer[Snapshot]

	debounce time.Duration
	poll     time.Duration
	now      func() time.Time

	mu            sync.Mutex
	diskPolicyRev string
	diffSince     time.Time
	diskCertEnd   time.Time
	lastErr       error
}

// NewWatcher loads the configuration once and fails if that load fails.
func NewWatcher(p Paths, log *slog.Logger) (*Watcher, error) {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}

	w := &Watcher{
		paths:    p,
		log:      log,
		debounce: 200 * time.Millisecond,
		poll:     60 * time.Second,
		now:      time.Now,
	}

	s, err := Load(p)
	if err != nil {
		return nil, fmt.Errorf("hubconfig: initial load: %w", err)
	}

	w.cur.Store(s)
	w.observe(s, nil)

	return w, nil
}

// Current returns the loaded snapshot.
func (w *Watcher) Current() *Snapshot { return w.cur.Load() }

// LastError returns the error of the most recent failed reload, or nil.
func (w *Watcher) LastError() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	return w.lastErr
}

// Run watches the mounted directories until ctx is done. onChange (may be nil)
// is called after a changed snapshot is installed.
func (w *Watcher) Run(ctx context.Context, onChange func(old, next *Snapshot)) error {
	fw, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("hubconfig: create watcher: %w", err)
	}
	defer fw.Close()

	seen := map[string]bool{}

	for _, d := range []string{w.paths.ConfigDir, w.paths.TrustDir, w.paths.CertDir} {
		if seen[d] {
			continue
		}

		seen[d] = true

		if err := fw.Add(d); err != nil {
			return fmt.Errorf("hubconfig: watch %s: %w", d, err)
		}
	}

	ticker := time.NewTicker(w.poll)
	defer ticker.Stop()

	timer := time.NewTimer(time.Hour)
	if !timer.Stop() {
		<-timer.C
	}

	pending := false

	// Cover changes that landed between the initial load and the watches.
	w.Reload(onChange)

	for {
		select {
		case <-ctx.Done():
			timer.Stop()

			return nil
		case ev, ok := <-fw.Events:
			if !ok {
				return nil
			}

			w.log.Debug("config event", "name", ev.Name, "op", ev.Op.String())

			if !pending {
				pending = true

				timer.Reset(w.debounce)
			}
		case err, ok := <-fw.Errors:
			if !ok {
				return nil
			}

			w.log.Error("config watcher error", "err", err)
		case <-timer.C:
			pending = false

			w.Reload(onChange)
		case <-ticker.C:
			w.Reload(onChange)
		}
	}
}

// Reload re-reads everything. On failure the previous snapshot stays.
func (w *Watcher) Reload(onChange func(old, next *Snapshot)) {
	old := w.cur.Load()

	next, err := Load(w.paths)
	if err != nil {
		w.observe(old, err)
		w.log.Error("config reload failed; keeping previous snapshot", "err", err)

		return
	}

	w.observe(next, nil)

	if next.Fingerprint == old.Fingerprint {
		return
	}

	w.cur.Store(next)
	w.log.Info("config reloaded",
		"policyRevision", next.PolicyRevision,
		"release", next.Release.Version,
		"trustRevision", next.TrustBundle.Revision,
		"certNotAfter", next.CertNotAfter)

	if onChange != nil {
		onChange(old, next)
	}
}

// observe records what is mounted on disk right now, independent of whether the
// full load succeeded. loadErr is the result of the load attempt.
func (w *Watcher) observe(loaded *Snapshot, loadErr error) {
	diskRev := ""

	if data, err := readFile(w.paths.ConfigDir, ConfigFile); err == nil {
		if cfg, perr := parseConfig(data); perr == nil {
			diskRev = cfg.policyRevision()
		} else {
			diskRev = "invalid:" + shortHash(string(data))
		}
	}

	var certEnd time.Time

	if crt, err := readFile(w.paths.CertDir, CertFile); err == nil {
		if b, _ := nextCert(crt); b != nil {
			if c, perr := x509.ParseCertificate(b.Bytes); perr == nil {
				certEnd = c.NotAfter
			}
		}
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	w.lastErr = loadErr

	if diskRev != "" {
		w.diskPolicyRev = diskRev
	}

	w.diskCertEnd = certEnd

	if w.diskPolicyRev == loaded.PolicyRevision {
		w.diffSince = time.Time{}
	} else if w.diffSince.IsZero() {
		w.diffSince = w.now()
	}
}

// Stale reports whether the loaded configuration has lagged the mounted one for
// too long, with a human-readable reason.
func (w *Watcher) Stale(now time.Time) (bool, string) {
	cur := w.cur.Load()

	w.mu.Lock()
	defer w.mu.Unlock()

	if !w.diffSince.IsZero() && now.Sub(w.diffSince) > StalePolicyAfter {
		return true, fmt.Sprintf("mounted policy revision %s differs from loaded %s since %s",
			w.diskPolicyRev, cur.PolicyRevision, w.diffSince.UTC().Format(time.RFC3339))
	}

	if now.Add(StaleCertWindow).After(cur.CertNotAfter) && w.diskCertEnd.After(cur.CertNotAfter) {
		return true, fmt.Sprintf(
			"serving certificate expires %s and a newer one (until %s) is mounted but not loaded",
			cur.CertNotAfter.UTC().Format(time.RFC3339),
			w.diskCertEnd.UTC().Format(time.RFC3339),
		)
	}

	return false, ""
}
