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

const (
	defaultDebounce = 200 * time.Millisecond
	defaultPoll     = 60 * time.Second
)

// Paths are the three mounted directories.
type Paths struct{ ConfigDir, TrustDir, CertDir string }

// Watcher keeps the current Snapshot up to date.
type Watcher struct {
	diskCertEnd     time.Time
	diffSince       time.Time
	configSource    configSource
	lastErr         error
	trustSource     configSource
	log             *slog.Logger
	cur             atomic.Pointer[Snapshot]
	now             func() time.Time
	paths           Paths
	sourcePolicyRev string
	poll            time.Duration
	debounce        time.Duration
	mu              sync.Mutex
	reloadMu        sync.Mutex
}

// NewWatcher loads the configuration once and fails if that load fails.
func NewWatcher(paths Paths, log *slog.Logger) (*Watcher, error) {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}

	watcher := &Watcher{
		paths:    paths,
		log:      log,
		debounce: defaultDebounce,
		poll:     defaultPoll,
		now:      time.Now,
	}

	s, err := Load(paths)
	if err != nil {
		return nil, fmt.Errorf("hubconfig: initial load: %w", err)
	}

	watcher.cur.Store(s)
	watcher.observe(s, nil, nil)

	return watcher, nil
}

// Current returns the loaded snapshot.
func (watcher *Watcher) Current() *Snapshot { return watcher.cur.Load() }

// LastError returns the error of the most recent failed reload, or nil.
func (watcher *Watcher) LastError() error {
	watcher.mu.Lock()
	defer watcher.mu.Unlock()

	return watcher.lastErr
}

// Run watches the mounted directories until ctx is done. OnChange (may be nil)
// is called after a changed snapshot is installed.
func (watcher *Watcher) Run(ctx context.Context, onChange func(old, next *Snapshot)) error {
	fw, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("hubconfig: create watcher: %w", err)
	}
	defer fw.Close()

	err = watcher.watchDirs(fw)
	if err != nil {
		return err
	}

	ticker := time.NewTicker(watcher.poll)
	defer ticker.Stop()

	timer := time.NewTimer(time.Hour)
	if !timer.Stop() {
		<-timer.C
	}

	pending := false

	// Cover changes that landed between the initial load and the watches.
	watcher.Reload(onChange)

	for {
		select {
		case <-ctx.Done():
			timer.Stop()

			return nil
		case ev, ok := <-fw.Events:
			if !ok {
				return nil
			}

			watcher.log.DebugContext(
				ctx,
				"Config event",
				slog.Any("name", ev.Name),
				slog.String("op", ev.Op.String()),
			)

			if !pending {
				pending = true

				timer.Reset(watcher.debounce)
			}
		case err, ok := <-fw.Errors:
			if !ok {
				return nil
			}

			watcher.log.ErrorContext(
				ctx,
				"Config watcher error",
				slog.Any("err", err),
			)
		case <-timer.C:
			pending = false

			watcher.Reload(onChange)
		case <-ticker.C:
			watcher.Reload(onChange)
		}
	}
}

// Reload re-reads everything. On failure the previous snapshot stays.
func (watcher *Watcher) Reload(onChange func(old, next *Snapshot)) {
	watcher.reloadMu.Lock()
	defer watcher.reloadMu.Unlock()

	watcher.reload(onChange)
}

// Stale reports whether the loaded configuration has lagged the mounted one for
// too long, with a human-readable reason.
func (watcher *Watcher) Stale(now time.Time) (bool, string) {
	cur := watcher.cur.Load()

	watcher.mu.Lock()
	defer watcher.mu.Unlock()

	if !watcher.diffSince.IsZero() && now.Sub(watcher.diffSince) > StalePolicyAfter {
		return true, fmt.Sprintf(
			"source policy revision %s differs from loaded %s since %s",
			watcher.sourcePolicyRev,
			cur.PolicyRevision,
			watcher.diffSince.UTC().Format(time.RFC3339),
		)
	}

	if now.Add(StaleCertWindow).After(cur.CertNotAfter) &&
		watcher.diskCertEnd.After(cur.CertNotAfter) {
		return true, fmt.Sprintf(
			"serving certificate expires %s and a newer one (until %s) is mounted but not loaded",
			cur.CertNotAfter.UTC().Format(time.RFC3339),
			watcher.diskCertEnd.UTC().Format(time.RFC3339),
		)
	}

	return false, ""
}

func (watcher *Watcher) reload(onChange func(old, next *Snapshot)) {
	old := watcher.cur.Load()
	cfg, cfgErr := watcher.configSource.selectData(readMount(watcher.paths.ConfigDir, ConfigFile))
	trust, trustErr := watcher.trustSource.selectData(
		readMount(watcher.paths.TrustDir, TrustFile, RevFile),
	)

	next, err := loadSelected(cfg, trust, watcher.paths.CertDir, cfgErr, trustErr)
	if err != nil {
		watcher.observe(old, err, cfg)
		watcher.log.Error(
			"Config reload failed; keeping previous snapshot",
			slog.Any("err", err),
		)

		return
	}

	if watcher.configSource.live != nil {
		watcher.configSource.applied = cfg
	}

	if watcher.trustSource.live != nil {
		watcher.trustSource.applied = trust
	}

	watcher.observe(next, nil, cfg)

	if next.Fingerprint == old.Fingerprint {
		return
	}

	watcher.cur.Store(next)
	watcher.log.Info(
		"Config reloaded",
		slog.Any("policyRevision", next.PolicyRevision),
		slog.String("release", next.Release.Version),
		slog.Any("trustRevision", next.TrustBundle.Revision),
		slog.Any("certNotAfter", next.CertNotAfter),
	)

	if onChange != nil {
		onChange(old, next)
	}
}

func loadSelected(
	cfg, trust map[string]string,
	certDir string,
	cfgErr, trustErr error,
) (*Snapshot, error) {
	if cfgErr != nil {
		return nil, cfgErr
	}

	if trustErr != nil {
		return nil, trustErr
	}

	return load(cfg, trust, certDir)
}

// observe records what is mounted on disk right now, independent of whether the
// full load succeeded. LoadErr is the result of the load attempt.
func (watcher *Watcher) observe(loaded *Snapshot, loadErr error, source map[string]string) {
	diskRev := ""

	data, err := readFile(watcher.paths.ConfigDir, ConfigFile)
	if source != nil {
		data, err = []byte(source[ConfigFile]), nil
	}

	if err == nil {
		cfg, perr := parseConfig(data)
		if perr == nil {
			diskRev = cfg.policyRevision()
		} else {
			diskRev = "invalid:" + shortHash(string(data))
		}
	}

	var certEnd time.Time

	crt, err := readFile(watcher.paths.CertDir, CertFile)
	if err == nil {
		if b, _ := nextCert(crt); b != nil {
			c, perr := x509.ParseCertificate(b.Bytes)
			if perr == nil {
				certEnd = c.NotAfter
			}
		}
	}

	watcher.mu.Lock()
	defer watcher.mu.Unlock()

	watcher.lastErr = loadErr

	if diskRev != "" {
		watcher.sourcePolicyRev = diskRev
	}

	watcher.diskCertEnd = certEnd

	if watcher.sourcePolicyRev == loaded.PolicyRevision {
		watcher.diffSince = time.Time{}
	} else if watcher.diffSince.IsZero() {
		watcher.diffSince = watcher.now()
	}
}

// watchDirs adds each distinct mounted directory to fw.
func (watcher *Watcher) watchDirs(fw *fsnotify.Watcher) error {
	seen := map[string]bool{}

	for _, dir := range []string{
		watcher.paths.ConfigDir,
		watcher.paths.TrustDir,
		watcher.paths.CertDir,
	} {
		if seen[dir] {
			continue
		}

		seen[dir] = true

		err := fw.Add(dir)
		if err != nil {
			return fmt.Errorf("hubconfig: watch %s: %w", dir, err)
		}
	}

	return nil
}
