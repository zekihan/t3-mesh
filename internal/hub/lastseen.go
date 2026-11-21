package hub

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"time"

	"github.com/zekihan/t3-mesh/internal/hub/kube"
)

const (
	lastSeenConfigMap     = "t3-mesh-hub-state"
	lastSeenKey           = "lastSeen.json"
	lastSeenInterval      = time.Minute
	lastSeenWriteAttempts = 2
)

var (
	errStateVersion = errors.New("hub: state ConfigMap has no resourceVersion")
	errLastSeenData = errors.New("hub: invalid last-seen data")
)

// LastSeenStore persists the hub's last-seen timestamps. Its methods are run
// serially by the caller, outside the hub's request and session paths.
type LastSeenStore struct {
	server *Server
	client *kube.Client
	saved  map[string]time.Time
	path   string
	dirty  bool
}

func NewLastSeenStore(server *Server, client *kube.Client, namespace string) *LastSeenStore {
	return &LastSeenStore{
		server: server,
		client: client,
		path:   kube.ConfigMapsPath(namespace) + "/" + lastSeenConfigMap,
	}
}

// Load restores the saved last-seen timestamps without starting any sessions.
func (store *LastSeenStore) Load(ctx context.Context) {
	state, err := store.read(ctx)
	if err != nil {
		store.server.log.WarnContext(ctx, "Load last seen failed", slog.Any("error", err))

		return
	}

	store.saved = state.seen

	store.dirty = state.decodeErr != nil
	if store.dirty {
		store.server.log.WarnContext(
			ctx,
			"Invalid saved last seen",
			slog.Any("error", state.decodeErr),
		)
	}

	store.server.mu.Lock()
	defer store.server.mu.Unlock()

	for name := range store.server.cfg.Current().Machines {
		if last := state.seen[name]; !last.IsZero() {
			ms := store.server.machineLocked(name)
			if last.After(ms.lastSeen) {
				ms.lastSeen = last
			}
		}
	}
}

// Run writes changed state periodically until shutdown. The caller flushes once
// more after the tunnel listener has finished closing its sessions.
func (store *LastSeenStore) Run(ctx context.Context) error {
	timer := time.NewTimer(lastSeenInterval)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-timer.C:
			store.Flush(ctx)
			timer.Reset(lastSeenInterval)
		}
	}
}

func (store *LastSeenStore) Flush(ctx context.Context) {
	snapshot := store.snapshot()
	if !store.dirty && maps.EqualFunc(store.saved, snapshot, time.Time.Equal) {
		return
	}

	err := store.save(ctx, snapshot)
	if err != nil {
		store.server.log.WarnContext(ctx, "Save last seen failed", slog.Any("error", err))

		return
	}

	store.saved = snapshot
	store.dirty = false
}

func (store *LastSeenStore) snapshot() map[string]time.Time {
	server := store.server
	now := server.now()
	snap := server.cfg.Current()
	seen := make(map[string]time.Time, len(snap.Machines))

	server.mu.Lock()
	defer server.mu.Unlock()

	for name := range snap.Machines {
		if ms := server.machines[name]; ms != nil {
			last := ms.lastSeen
			if ms.newestLive() != nil && now.After(last) {
				last = now
			}

			if !last.IsZero() {
				seen[name] = last.UTC()
			}
		}
	}

	return seen
}

type lastSeenState struct {
	decodeErr error
	object    map[string]json.RawMessage
	data      map[string]string
	seen      map[string]time.Time
}

func (store *LastSeenStore) read(ctx context.Context) (lastSeenState, error) {
	var state lastSeenState

	_, err := store.client.ConfigMapRequest(ctx, http.MethodGet, store.path, nil, &state.object)
	if err != nil {
		return lastSeenState{}, fmt.Errorf("get state ConfigMap: %w", err)
	}

	var metadata kube.Metadata

	err = json.Unmarshal(state.object["metadata"], &metadata)
	if err != nil {
		return lastSeenState{}, fmt.Errorf("decode state metadata: %w", err)
	}

	if metadata.ResourceVersion == "" {
		return lastSeenState{}, errStateVersion
	}

	state.data = map[string]string{}
	if raw := state.object["data"]; len(raw) != 0 {
		err := json.Unmarshal(raw, &state.data)
		if err != nil {
			return lastSeenState{}, fmt.Errorf("decode state data: %w", err)
		}
	}

	if raw, ok := state.data[lastSeenKey]; ok {
		state.seen, state.decodeErr = decodeLastSeen(raw)
	}

	return state, nil
}

func decodeLastSeen(raw string) (map[string]time.Time, error) {
	var entries map[string]json.RawMessage

	err := json.Unmarshal([]byte(raw), &entries)
	if err != nil {
		return nil, fmt.Errorf("decode last seen: %w", err)
	}

	if entries == nil {
		return nil, fmt.Errorf("%w: expected a JSON object", errLastSeenData)
	}

	seen := make(map[string]time.Time, len(entries))
	skipped := 0

	for name, value := range entries {
		var last *time.Time

		decodeErr := json.Unmarshal(value, &last)
		if decodeErr != nil || last == nil {
			skipped++

			continue
		}

		seen[name] = *last
	}

	if skipped > 0 {
		return seen, fmt.Errorf("%w: skipped %d malformed timestamps", errLastSeenData, skipped)
	}

	return seen, nil
}

func (store *LastSeenStore) save(ctx context.Context, snapshot map[string]time.Time) error {
	var err error

	for range lastSeenWriteAttempts {
		var code int

		code, err = store.saveAttempt(ctx, snapshot)
		if code != http.StatusConflict {
			break
		}
	}

	return err
}

func (store *LastSeenStore) saveAttempt(
	ctx context.Context,
	snapshot map[string]time.Time,
) (int, error) {
	state, err := store.read(ctx)
	if err != nil {
		return 0, err
	}

	seen := make(map[string]time.Time, len(snapshot))
	maps.Copy(seen, state.seen)

	for name, last := range snapshot {
		if last.After(seen[name]) {
			seen[name] = last
		}
	}

	if state.decodeErr == nil && maps.EqualFunc(state.seen, seen, time.Time.Equal) {
		return 0, nil
	}

	body, err := state.encode(seen)
	if err != nil {
		return 0, err
	}

	var reply kube.ConfigMap

	code, err := store.client.ConfigMapRequest(
		ctx,
		http.MethodPut,
		store.path,
		bytes.NewReader(body),
		&reply,
	)
	if err != nil {
		return code, fmt.Errorf("update state ConfigMap: %w", err)
	}

	return code, nil
}

func (state lastSeenState) encode(seen map[string]time.Time) ([]byte, error) {
	values, err := json.Marshal(seen)
	if err != nil {
		return nil, fmt.Errorf("encode last seen: %w", err)
	}

	if state.data == nil {
		state.data = map[string]string{}
	}

	state.data[lastSeenKey] = string(values)

	data, err := json.Marshal(state.data)
	if err != nil {
		return nil, fmt.Errorf("encode state data: %w", err)
	}

	state.object["data"] = data

	body, err := json.Marshal(state.object)
	if err != nil {
		return nil, fmt.Errorf("encode state ConfigMap: %w", err)
	}

	return body, nil
}
