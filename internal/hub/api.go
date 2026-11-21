package hub

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/zekihan/t3-mesh/internal/hub/hubconfig"
	"github.com/zekihan/t3-mesh/internal/policy"
	"github.com/zekihan/t3-mesh/internal/proto"
)

// apiSvc is the service whose policy entry decides which machines a caller may
// see: a machine is listed only when its mesh-t3-<machine> entry lists the caller.
const (
	apiSvc    = "t3"
	renewPath = "/api/v1/renew"
)

// apiDirect is where an enrolled device may reach a machine directly on the LAN:
// the address is an IP literal (IPv6 without brackets or zone) and the port that of
// the agent's listener for enrolled devices.
type apiDirect struct {
	Address string `json:"address"`
	Port    int    `json:"port"`
}

type apiMachine struct {
	LastSeen *string `json:"lastSeen"`
	// Direct is null unless the hub marks the machine home and its agent reports
	// the listener for enrolled devices bound.
	Direct        *apiDirect `json:"direct"`
	Name          string     `json:"name"`
	ViewerURL     string     `json:"viewerUrl"`
	AgentIdentity string     `json:"agentIdentity"`
	Online        bool       `json:"online"`
}

type apiMachines struct {
	Machines []apiMachine `json:"machines"`
}

type apiTunnel struct {
	Path           *string `json:"path"`
	ConnectedSince *string `json:"connectedSince"`
}

// apiFleetMachine is the /machines entry plus the /status state of the machine.
type apiFleetMachine struct { //nolint:govet // keep the existing fields first in JSON
	apiMachine

	DesiredVersion string `json:"desiredVersion,omitempty"`

	AgentVersion *string                  `json:"agentVersion"`
	CertNotAfter *string                  `json:"certNotAfter"`
	Tunnel       apiTunnel                `json:"tunnel"`
	Alerts       []string                 `json:"alerts"`
	Services     map[string]serviceHealth `json:"services"`
}

// apiTrust is the body of /api/v1/trust: the clients CA bundle with its revision
// and the blocked leaf fingerprints, which include every blocked agent leaf.
type apiTrust struct {
	CABundle      string   `json:"caBundle"`
	CARevision    string   `json:"caRevision"`
	RevokedAgents []string `json:"revokedAgents"`
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

	leaf := policy.Session{Identity: caller, Fingerprint: fp, NotAfter: notAfter}

	err := server.admitAPI(r, snap, &leaf)
	if err != nil {
		server.rejectAPI(r, caller, err.Error())
		refuse(w, err)

		return
	}

	switch r.URL.Path {
	case renewPath:
		server.serveRenew(w, r, snap, &leaf)
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
	case "/api/v1/trust":
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)

			return
		}

		server.serveTrust(w, r, snap)
	default:
		http.NotFound(w, r)
	}
}

func (server *Server) admitAPI(
	r *http.Request,
	snap *hubconfig.Snapshot,
	leaf *policy.Session,
) error {
	err := policy.CheckLeaf(snap.Revocations, *leaf, server.now())
	if err != nil {
		return fmt.Errorf("API caller: %w", err)
	}

	if !snap.APICaller(leaf.Identity) {
		return errNotAPICaller
	}

	if r.URL.Path == renewPath && r.Method == http.MethodPost &&
		snap.Device(
			leaf.Identity,
		) && server.cachedRenewal(leaf.Identity, leaf.Fingerprint).leaf != nil {
		return nil
	}

	return server.admitDevice(r.Context(), snap, leaf.Identity, leaf.Fingerprint)
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

	for name, machine := range snap.Machines {
		if machine.Services[apiSvc].Kind == proto.KindHTTP &&
			policy.Allowed(snap.Rules, caller, apiSvc, name) {
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
		Name:          name,
		Online:        st.Connected,
		ViewerURL:     "https://" + policy.Target(apiSvc, name) + "." + snap.ViewerDomain,
		AgentIdentity: st.Identity,
	}

	if st.LastSeen != nil {
		entry.LastSeen = formatTime(st.LastSeen)
	}

	if st.Connected && st.Path == pathLAN {
		entry.Direct = directRoute(snap, st.DeviceListener, st.source)
	}

	return entry
}

// directRoute chooses the address an enrolled device should dial for a machine that
// is home and reports its device listener bound, or nil when there is none. Only
// addresses the home gate considers home qualify (inside homeCIDRs, so a wrong or
// hostile report cannot point a phone outside the LAN), IPv4 is preferred to IPv6
// (the viewer path stays reachable on either, but a literal IPv4 needs no scope
// and is what the LAN VIP and Technitium records lead with), and within a family the
// address the tunnel arrived from wins, then the lowest.
func directRoute(
	snap *hubconfig.Snapshot,
	listener *proto.DeviceListener,
	source netip.Addr,
) *apiDirect {
	if listener == nil {
		return nil
	}

	var v4, v6 []netip.Addr

	for _, text := range listener.Addrs {
		addr, err := netip.ParseAddr(text)
		if err != nil {
			continue
		}

		addr = addr.Unmap().WithZone("")
		if !snap.IsHome(addr) || addr.IsUnspecified() || addr.IsMulticast() ||
			addr.IsLinkLocalUnicast() {
			continue
		}

		if addr.Is4() {
			v4 = append(v4, addr)
		} else {
			v6 = append(v6, addr)
		}
	}

	for _, family := range [][]netip.Addr{v4, v6} {
		if len(family) == 0 {
			continue
		}

		pick := slices.MinFunc(family, netip.Addr.Compare)
		if slices.Contains(family, source.Unmap()) {
			pick = source.Unmap()
		}

		return &apiDirect{Address: pick.String(), Port: listener.Port}
	}

	return nil
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
			apiMachine:     apiMachineOf(snap, name, &st),
			DesiredVersion: st.DesiredVersion,
			CertNotAfter:   formatTime(st.CertNotAfter),
			Tunnel:         apiTunnel{ConnectedSince: formatTime(st.ConnectedSince)},
			Alerts:         firingAlerts(st.Alerts),
			Services:       st.ServiceHealth,
		}

		for svc, service := range snap.Machines[name].Services {
			if service.Kind == proto.KindTCP {
				delete(entry.Services, svc)
			}
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

// serveTrust answers with what an app needs to verify an agent directly: the
// clients CA bundle it may trust and the leaves that are revoked. The list is the
// configured blocked fingerprints as they are, since the hub cannot tell an
// agent's leaf from another by its fingerprint; the app only ever compares an
// agent's leaf against it. It holds no identity, so every API caller sees the same.
func (server *Server) serveTrust(
	w http.ResponseWriter,
	r *http.Request,
	snap *hubconfig.Snapshot,
) {
	server.writeAPI(w, r, apiTrust{
		CABundle:      snap.TrustBundle.PEM,
		CARevision:    snap.TrustBundle.Revision,
		RevokedAgents: slices.Clone(nonNil(snap.Revocations.BlockedFingerprints)),
	})
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
