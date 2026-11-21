package hubconfig

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/zekihan/t3-mesh/internal/hub/kube"
)

const watchGracePeriod = 2 * time.Minute

// configSource arbitrates between a watch and the mounted projection.
type configSource struct {
	disconnectedAt time.Time
	live           map[string]string
	applied        map[string]string
}

func (source *configSource) selectData(
	now time.Time,
	mounted map[string]string,
	err error,
) (map[string]string, error) {
	if source.live != nil {
		return source.live, nil
	}

	if source.applied != nil && now.Sub(source.disconnectedAt) < watchGracePeriod {
		return source.applied, nil
	}

	source.applied = nil

	return mounted, err
}

// WatchConfigMaps runs the optional API watches alongside the mount watcher.
func (watcher *Watcher) WatchConfigMaps(ctx context.Context, client *kube.Client,
	namespace, configName, trustName string, onChange func(old, next *Snapshot),
) error {
	var wg sync.WaitGroup
	for source, name := range map[*configSource]string{
		&watcher.configSource: configName,
		&watcher.trustSource:  trustName,
	} {
		wg.Go(func() {
			watcher.watchConfigMap(ctx, client, namespace, name, source, onChange)
		})
	}

	wg.Wait()

	return nil
}

func (watcher *Watcher) watchConfigMap(ctx context.Context, client *kube.Client,
	namespace, name string, source *configSource, onChange func(old, next *Snapshot),
) {
	update := func(data map[string]string) {
		watcher.reloadMu.Lock()
		defer watcher.reloadMu.Unlock()

		source.live = data
		if data != nil {
			source.disconnectedAt = time.Time{}
			if source == &watcher.configSource {
				source.live = map[string]string{ConfigFile: data[ConfigFile]}
			} else {
				source.live = map[string]string{TrustFile: data[TrustFile], RevFile: data[RevFile]}
			}
		} else if source.disconnectedAt.IsZero() {
			source.disconnectedAt = watcher.now()
		}

		watcher.reload(onChange)
	}

	const (
		maxBackoff    = time.Minute
		backoffFactor = 2
	)

	backoff := time.Second
	warned := false

	for ctx.Err() == nil {
		err := client.WatchConfigMap(ctx, namespace, name, func(data map[string]string) {
			warned = false
			backoff = time.Second

			if data == nil {
				data = map[string]string{}
			}

			update(data)
		})
		if ctx.Err() != nil {
			return
		}

		update(nil)

		if err != nil && !warned {
			watcher.log.WarnContext(
				ctx,
				"ConfigMap watch unavailable",
				slog.String("configMap", name),
				slog.Any("error", err),
			)

			warned = true
		}

		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()

			return
		case <-timer.C:
		}

		backoff = min(backoff*backoffFactor, maxBackoff)
	}
}
