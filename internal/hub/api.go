package hub

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/zekihan/t3-mesh/internal/hub/hubconfig"
	"github.com/zekihan/t3-mesh/internal/policy"
)

// apiSvc is the service whose policy entry decides which machines a caller may
// see: a machine is listed only when its mesh-t3-<machine> entry lists the caller.
const apiSvc = "t3"

type apiMachine struct {
	LastSeen  *string `json:"lastSeen"`
	Name      string  `json:"name"`
	ViewerURL string  `json:"viewerUrl"`
	Online    bool    `json:"online"`
}

type apiMachines struct {
	Machines []apiMachine `json:"machines"`
}

type apiTunnel struct {
	Path           *string `json:"path"`
	ConnectedSince *string `json:"connectedSince"`
}

// apiFleetMachine is the /machines entry plus the /status state of the machine.
type apiFleetMachine struct {
	apiMachine

	AgentVersion *string   `json:"agentVersion"`
	CertNotAfter *string   `json:"certNotAfter"`
	Tunnel       apiTunnel `json:"tunnel"`
	Alerts       []string  `json:"alerts"`
}

type apiCaller struct {
	Path *string `json:"path"`
}

type apiFleet struct {
	Caller   apiCaller         `json:"caller"`
	Machines []apiFleetMachine `json:"machines"`
}

// serveAPI serves the hub API host. It requires the same viewer headers as a
// viewer stream and a caller listed under api.identities, so a valid client
// certificate that is not an API identity gets nothing.
func (server *Server) serveAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")

	caller, fp, notAfter, ok := viewerIdentity(r)
	if !ok {
		server.rejectAPI(r, "", "missing or invalid viewer headers")
		http.Error(w, "forbidden", http.StatusForbidden)

		return
	}

	snap := server.cfg.Current()

	err := policy.CheckLeaf(
		snap.Revocations,
		policy.Session{Identity: caller, Fingerprint: fp, NotAfter: notAfter},
		server.now(),
	)
	if err == nil && !snap.APICaller(caller) {
		err = errNotAPICaller
	}

	if err == nil {
		// An enrolled device is admitted only with its newest leaf.
		err = server.admitDevice(r.Context(), snap, caller, fp)
	}

	if err != nil {
		server.rejectAPI(r, caller, err.Error())
		refuse(w, err)

		return
	}

	switch r.URL.Path {
	case "/api/v1/machines":
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)

			return
		}

		server.serveMachines(w, r, snap, caller)
	case "/api/v1/fleet":
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)

			return
		}

		server.serveFleet(w, r, snap, caller)
	default:
		http.NotFound(w, r)
	}
}

func (server *Server) rejectAPI(r *http.Request, caller, reason string) {
	server.log.InfoContext(
		r.Context(),
		"Reject",
		slog.String("kind", "api"),
		slog.String("caller", caller),
		slog.String("reason", reason),
		slog.Any("host", r.Host),
	)
}

// visibleMachines is the one filter every /api/v1 endpoint applies: the sorted
// names of the machines whose mesh-t3-<machine> policy entry lists caller.
func visibleMachines(snap *hubconfig.Snapshot, caller string) []string {
	out := make([]string, 0, len(snap.Machines))

	for name := range snap.Machines {
		if policy.Allowed(snap.Rules, caller, apiSvc, name) {
			out = append(out, name)
		}
	}

	slices.Sort(out)

	return out
}

// apiMachineOf is the base object /machines and /fleet share, taken from the
// machine's /status state: online means a live tunnel session, and lastSeen is
// the current time while online and the last disconnect otherwise.
func apiMachineOf(snap *hubconfig.Snapshot, name string, st *machineStatus) apiMachine {
	entry := apiMachine{
		Name:      name,
		Online:    st.Connected,
		ViewerURL: "https://" + policy.Target(apiSvc, name) + "." + snap.ViewerDomain,
	}

	if st.LastSeen != nil {
		entry.LastSeen = formatTime(st.LastSeen)
	}

	return entry
}

func formatTime(t *time.Time) *string {
	if t == nil {
		return nil
	}

	out := t.UTC().Format(time.RFC3339)

	return &out
}

func (server *Server) serveMachines(
	w http.ResponseWriter,
	r *http.Request,
	snap *hubconfig.Snapshot,
	caller string,
) {
	now := server.now()
	names := visibleMachines(snap, caller)
	doc := apiMachines{Machines: make([]apiMachine, 0, len(names))}

	server.mu.Lock()
	for _, name := range names {
		st := server.machineStatusLocked(snap, name, snap.Machines[name], now)
		doc.Machines = append(doc.Machines, apiMachineOf(snap, name, &st))
	}
	server.mu.Unlock()

	server.writeAPI(w, r, doc)
}

func (server *Server) serveFleet(
	w http.ResponseWriter,
	r *http.Request,
	snap *hubconfig.Snapshot,
	caller string,
) {
	now := server.now()
	names := visibleMachines(snap, caller)
	doc := apiFleet{
		Caller:   apiCaller{Path: callerPath(snap, r)},
		Machines: make([]apiFleetMachine, 0, len(names)),
	}

	server.mu.Lock()
	for _, name := range names {
		st := server.machineStatusLocked(snap, name, snap.Machines[name], now)
		entry := apiFleetMachine{
			apiMachine:   apiMachineOf(snap, name, &st),
			CertNotAfter: formatTime(st.CertNotAfter),
			Tunnel:       apiTunnel{ConnectedSince: formatTime(st.ConnectedSince)},
			Alerts:       firingAlerts(st.Alerts),
		}

		if st.Version != "" {
			entry.AgentVersion = &st.Version
		}

		if st.Path != "" {
			entry.Tunnel.Path = &st.Path
		}

		doc.Machines = append(doc.Machines, entry)
	}
	server.mu.Unlock()

	server.writeAPI(w, r, doc)
}

// firingAlerts is the sorted names of the alerts that are currently true.
func firingAlerts(alerts map[string]bool) []string {
	out := []string{}

	for name, firing := range alerts {
		if firing {
			out = append(out, name)
		}
	}

	slices.Sort(out)

	return out
}

// callerPath is the path of the API request itself, from the X-Real-IP header
// Traefik's traefik-real-ip middleware sets at the entrypoint. The TCP peer is
// a Traefik pod and says nothing. A missing or unparsable header is unknown.
func callerPath(snap *hubconfig.Snapshot, r *http.Request) *string {
	addr, err := netip.ParseAddr(strings.TrimSpace(r.Header.Get("X-Real-IP")))
	if err != nil {
		return nil
	}

	path := pathName(snap.IsHome(addr))

	return &path
}

func (server *Server) writeAPI(w http.ResponseWriter, r *http.Request, doc any) {
	w.Header().Set("Content-Type", "application/json")

	err := json.NewEncoder(w).Encode(doc)
	if err != nil {
		server.log.DebugContext(
			r.Context(),
			"API response write failed",
			slog.String("error", err.Error()),
		)
	}
}
