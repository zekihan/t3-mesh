package hub

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/zekihan/t3-mesh/internal/hub/hubconfig"
	"github.com/zekihan/t3-mesh/internal/policy"
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
// supersedes the old one at once: the old leaf's open streams are closed.
func (server *Server) noteIssued(identity, fp string) {
	server.setNewest(identity, fp)
	server.pruneAsync(identity)

	if policy.IsDevice(identity) {
		server.enforce()
	}
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
