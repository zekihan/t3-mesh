package hub

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"slices"
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

	if err != nil {
		server.rejectAPI(r, caller, err.Error())
		http.Error(w, "forbidden", http.StatusForbidden)

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
		m := server.machines[name]
		last := time.Time{}
		online := false

		if m != nil {
			last = m.lastSeen
			online = m.newestLive() != nil
		}

		if online {
			last = now
		}

		entry := apiMachine{
			Name:      name,
			Online:    online,
			ViewerURL: "https://" + policy.Target(apiSvc, name) + "." + snap.ViewerDomain,
		}

		if !last.IsZero() {
			seen := last.UTC().Format(time.RFC3339)
			entry.LastSeen = &seen
		}

		doc.Machines = append(doc.Machines, entry)
	}
	server.mu.Unlock()

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
