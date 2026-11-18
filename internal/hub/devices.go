package hub

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/zekihan/t3-mesh/internal/hub/hubconfig"
	"github.com/zekihan/t3-mesh/internal/policy"
	"github.com/zekihan/t3-mesh/internal/proto"
)

const (
	// The issuer lookup for one device while a session is being set up is bounded,
	// so that a slow API server cannot hold a HelloAck past the agent's wait for it.
	deviceLookupTimeout = 3 * time.Second
	// A session waits this long before asking again after a lookup failed.
	deviceLeavesRetry = 30 * time.Second
)

var (
	errDeviceNotConfigured = errors.New("hub: device identity is not configured")
	errDeviceSuperseded    = errors.New("hub: a newer certificate was issued for this device")
	errDeviceCheck         = errors.New("hub: device certificate check unavailable")
)

// admitDevice applies the rules of an enrolled-device identity to a viewer or
// API request and leaves every other identity alone: the device must still be
// configured, and fp must be the newest leaf the hub issued for it (the issuer
// is asked when the hub's own record disagrees, as for agents). An identity the
// issuer has no record of at all is admitted, as an agent is, and logged.
func (server *Server) admitDevice(
	ctx context.Context,
	snap *hubconfig.Snapshot,
	identity, fp string,
) error {
	if !policy.IsDevice(identity) {
		return nil
	}

	if !snap.Device(identity) {
		return fmt.Errorf("%w: %s", errDeviceNotConfigured, identity)
	}

	ok, noRecord, err := server.checkNewest(ctx, identity, fp)

	switch {
	case err != nil:
		return fmt.Errorf("%w: %w", errDeviceCheck, err)
	case !ok:
		return fmt.Errorf("%w: %s", errDeviceSuperseded, identity)
	case noRecord:
		server.log.WarnContext(
			ctx,
			"No issuance record for device leaf; admitting",
			slog.String("identity", identity),
			slog.String("fingerprint", fp),
		)
	}

	return nil
}

// deviceCurrent is the check for streams that are already open: it uses only
// what the hub knows, never the issuer, so the sweep stays cheap. A device that
// is no longer configured, or whose newest known leaf is another one, may not
// keep a stream.
func (server *Server) deviceCurrent(snap *hubconfig.Snapshot, identity, fp string) error {
	if !policy.IsDevice(identity) {
		return nil
	}

	if !snap.Device(identity) {
		return fmt.Errorf("%w: %s", errDeviceNotConfigured, identity)
	}

	server.nmu.Lock()
	newest := server.newest[identity]
	server.nmu.Unlock()

	if newest != "" && newest != fp {
		return fmt.Errorf("%w: %s", errDeviceSuperseded, identity)
	}

	return nil
}

// noteIssued records a certificate the hub has just issued. A new device leaf
// supersedes the old one at once: the old leaf's open streams are closed, and
// every agent is sent the new fingerprint.
func (server *Server) noteIssued(identity, fp string) {
	server.setNewest(identity, fp)
	server.pruneAsync(identity)

	if policy.IsDevice(identity) {
		server.enforce()
		server.kickAll()
	}
}

// knowDevice makes sure the hub has asked the issuer for the newest leaf of a
// configured device once since it started. What the hub has issued since then is
// already recorded, so later calls cost nothing.
func (server *Server) knowDevice(ctx context.Context, identity string) error {
	server.nmu.Lock()
	known := server.deviceKnown[identity]
	server.nmu.Unlock()

	if known {
		return nil
	}

	ctx, cancel := context.WithTimeout(ctx, deviceLookupTimeout)
	defer cancel()

	got, err := server.issuer.Newest(ctx, identity)
	if err != nil {
		return fmt.Errorf("hub: newest leaf lookup: %w", err)
	}

	server.nmu.Lock()
	defer server.nmu.Unlock()

	// Never replace a leaf issued while the lookup ran.
	if got != "" && server.newest[identity] == "" {
		server.newest[identity] = got
	}

	server.deviceKnown[identity] = true

	return nil
}

// deviceLeaves is the newest leaf of every configured device that has one. It
// returns nil when the issuer could not say for some device, so that an agent
// keeps what it has rather than losing a device's leaf to a lookup failure.
func (server *Server) deviceLeaves(
	ctx context.Context,
	snap *hubconfig.Snapshot,
) *proto.DeviceLeaves {
	for _, identity := range snap.Devices {
		err := server.knowDevice(ctx, identity)
		if err != nil {
			server.log.WarnContext(
				ctx,
				"Device leaves unavailable",
				slog.String("identity", identity),
				slog.Any("error", err),
			)

			return nil
		}
	}

	return server.deviceLeavesKnown(snap)
}

// deviceLeavesKnown builds the list from what the hub already knows, in the
// sorted order of the configured devices.
func (server *Server) deviceLeavesKnown(snap *hubconfig.Snapshot) *proto.DeviceLeaves {
	leaves := make([]proto.DeviceLeaf, 0, len(snap.Devices))

	server.nmu.Lock()
	for _, identity := range snap.Devices {
		if fp := server.newest[identity]; fp != "" {
			leaves = append(leaves, proto.DeviceLeaf{Identity: identity, Fingerprint: fp})
		}
	}
	server.nmu.Unlock()

	//nolint:errcheck,errchkjson // DeviceLeaf holds only strings, so Marshal cannot fail
	data, _ := json.Marshal(leaves)
	sum := sha256.Sum256(data)

	return &proto.DeviceLeaves{Revision: hex.EncodeToString(sum[:8]), Leaves: leaves}
}

// refuse answers a refused viewer or API request: 403 for an admission failure,
// 503 while the issuer cannot say which leaf is the newest.
func refuse(w http.ResponseWriter, err error) {
	if errors.Is(err, errDeviceCheck) {
		http.Error(w, "temporarily unavailable", http.StatusServiceUnavailable)

		return
	}

	http.Error(w, "forbidden", http.StatusForbidden)
}
