package hub

import (
	"errors"
	"fmt"
	"maps"
	"slices"

	"github.com/zekihan/t3-mesh/internal/hub/enroll"
)

var (
	errAdminDisconnect = errors.New("hub: disconnected by operator")
	errUnknownMachine  = errors.New("hub: unknown machine")
)

// AdminStatus returns the same machine state used by /status, in name order.
func (server *Server) AdminStatus() []enroll.MachineStatus {
	snap := server.cfg.Current()
	now := server.now()
	names := slices.Sorted(maps.Keys(snap.Machines))
	out := make([]enroll.MachineStatus, 0, len(names))

	server.mu.Lock()
	defer server.mu.Unlock()

	for _, name := range names {
		status := server.machineStatusLocked(snap, name, snap.Machines[name], now)

		row := enroll.MachineStatus{
			Name: name, Online: status.Connected, Path: status.Path,
			Version: status.Version, DesiredVersion: status.DesiredVersion,
			CertNotAfter: status.CertNotAfter, LastSeen: status.LastSeen,
			Services: make(map[string]string, len(status.ServiceHealth)),
		}
		for svc, health := range status.ServiceHealth {
			row.Services[svc] = health.State
		}

		for alert, active := range status.Alerts {
			if active {
				row.Alerts = append(row.Alerts, alert)
			}
		}

		slices.Sort(row.Alerts)
		out = append(out, row)
	}

	return out
}

// Disconnect closes a machine's current sessions and lets the agent reconnect.
func (server *Server) Disconnect(machine string) error {
	if _, ok := server.cfg.Current().Machines[machine]; !ok {
		return fmt.Errorf("%w: %s", errUnknownMachine, machine)
	}

	server.mu.Lock()

	var sessions []*session
	if state := server.machines[machine]; state != nil {
		sessions = slices.Clone(state.sessions)
	}
	server.mu.Unlock()

	if len(sessions) == 0 {
		return errNoSession
	}

	for _, conn := range sessions {
		conn.close(errAdminDisconnect)
	}

	return nil
}
