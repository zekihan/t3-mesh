package hub

import (
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/zekihan/t3-mesh/internal/hub/hubconfig"
	"github.com/zekihan/t3-mesh/internal/proto"
)

// Alert thresholds.
const (
	certExpiryWarn   = 14 * 24 * time.Hour
	versionLagAfter  = time.Hour
	statusTimeFormat = time.RFC3339
)

// OpsHandler returns the handler for /status, /alerts/<name>, /healthz and
// /readyz.
func (s *Server) OpsHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		if !s.Ready() {
			http.Error(w, "not ready", http.StatusServiceUnavailable)

			return
		}

		_, _ = w.Write([]byte("ready\n"))
	})
	mux.HandleFunc("GET /status", s.serveStatus)
	mux.HandleFunc("GET /alerts/{name}", s.serveAlert)

	return mux
}

type servicesStatus struct {
	Configured []string `json:"configured"`
	Announced  []string `json:"announced"`
	Missing    []string `json:"missing"`
	Unexpected []string `json:"unexpected"`
}

type ackedStatus struct {
	Release     string `json:"release"`
	Rules       string `json:"rules"`
	Revocations string `json:"revocations"`
	TrustBundle string `json:"trustBundle"`
}

type machineStatus struct {
	Identity       string               `json:"identity"`
	Connected      bool                 `json:"connected"`
	Path           string               `json:"path,omitempty"`
	ConnectedSince *time.Time           `json:"connectedSince,omitempty"`
	Sessions       int                  `json:"sessions"`
	OpenStreams    int64                `json:"openStreams"`
	LinkStreams    int64                `json:"linkStreams"`
	DirectSessions int                  `json:"directSessions"`
	Version        string               `json:"version,omitempty"`
	CertNotAfter   *time.Time           `json:"certNotAfter,omitempty"`
	LastSeen       *time.Time           `json:"lastSeen,omitempty"`
	Services       servicesStatus       `json:"services"`
	Acked          ackedStatus          `json:"acked"`
	Warnings       []string             `json:"warnings"`
	AgentWarnings  []string             `json:"agentWarnings,omitempty"`
	FailedUpdates  []proto.FailedUpdate `json:"failedUpdates"`
	Alerts         map[string]bool      `json:"alerts"`
}

type statusDoc struct {
	Now            time.Time                `json:"now"`
	StartedAt      time.Time                `json:"startedAt"`
	PolicyRevision string                   `json:"policyRevision"`
	Rules          string                   `json:"rulesRevision"`
	Revocations    string                   `json:"revocationRevision"`
	TrustBundle    string                   `json:"trustBundleRevision"`
	Release        proto.Release            `json:"release"`
	Stale          bool                     `json:"stale"`
	StaleReason    string                   `json:"staleReason,omitempty"`
	ConfigError    string                   `json:"configError,omitempty"`
	Machines       map[string]machineStatus `json:"machines"`
}

func ptrTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}

	t = t.UTC()

	return &t
}

func (s *Server) serveStatus(w http.ResponseWriter, _ *http.Request) {
	snap := s.cfg.Current()
	now := s.now()
	stale, reason := s.cfg.Stale(now)

	doc := statusDoc{
		Now: now.UTC(), StartedAt: s.started.UTC(),
		PolicyRevision: snap.PolicyRevision, Rules: snap.Rules.Revision,
		Revocations: snap.Revocations.Revision, TrustBundle: snap.TrustBundle.Revision,
		Release: snap.Release, Stale: stale, StaleReason: reason,
		Machines: map[string]machineStatus{},
	}
	if err := s.cfg.LastError(); err != nil {
		doc.ConfigError = err.Error()
	}

	s.mu.Lock()
	for name, mc := range snap.Machines {
		doc.Machines[name] = s.machineStatusLocked(snap, name, mc, now)
	}
	s.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(doc)
}

func (s *Server) machineStatusLocked(snap *hubconfig.Snapshot, name string, mc hubconfig.Machine, now time.Time) machineStatus {
	ms := s.machines[name]
	if ms == nil {
		ms = &machineState{name: name}
	}

	out := machineStatus{Identity: mc.Identity, Warnings: slices.Clone(ms.warnings), FailedUpdates: []proto.FailedUpdate{}}
	if out.Warnings == nil {
		out.Warnings = []string{}
	}

	live := ms.newestLive()
	out.Connected = live != nil
	out.Sessions = len(ms.sessions)
	out.Version = ms.version
	out.CertNotAfter = ptrTime(ms.certNotAfter)

	for _, c := range ms.sessions {
		out.OpenStreams += c.streams.Load()
		out.LinkStreams += c.linkStream.Load()
	}

	if live != nil {
		out.Path = pathName(live.home)
		out.ConnectedSince = ptrTime(live.accepted)
		out.LastSeen = ptrTime(now)
	} else {
		out.LastSeen = ptrTime(ms.lastSeen)
	}

	configured := snap.Services(name)
	missing, unexpected := serviceDiff(ms.announced, configured)
	out.Services = servicesStatus{
		Configured: configured, Announced: nonNil(ms.announced),
		Missing: nonNil(missing), Unexpected: nonNil(unexpected),
	}

	if st := ms.status; st != nil {
		out.DirectSessions = st.DirectSessions
		out.Acked = ackedStatus{
			Release: st.ReleaseRevision, Rules: st.RulesRevision,
			Revocations: st.RevocationRevision, TrustBundle: st.TrustBundleRevision,
		}
		out.AgentWarnings = st.Warnings
		out.FailedUpdates = nonNilFU(st.FailedUpdates)
	}

	out.Alerts = map[string]bool{
		"disconnected": s.disconnectedLocked(mc, ms, now),
		"cert-expiry":  certExpiring(ms, now),
		"update-failed": func() bool {
			f, _ := s.updateFailedLocked(snap, ms, now)

			return f
		}(),
	}

	return out
}

func nonNil(in []string) []string {
	if in == nil {
		return []string{}
	}

	return in
}

func nonNilFU(in []proto.FailedUpdate) []proto.FailedUpdate {
	if in == nil {
		return []proto.FailedUpdate{}
	}

	return in
}

// disconnectedLocked: the machine has had no live session for longer than its
// DisconnectAlertAfter, counted from the later of hub start and its last
// disconnect.
func (s *Server) disconnectedLocked(mc hubconfig.Machine, ms *machineState, now time.Time) bool {
	if ms.newestLive() != nil {
		return false
	}

	since := s.started
	if ms.lastSeen.After(since) {
		since = ms.lastSeen
	}

	return now.Sub(since) > mc.DisconnectAlertAfter
}

// certExpiring: the best known certificate expiry (connected leaf, issued
// renewal or last known) is under 14 days away. Unknown expiry does not fire.
func certExpiring(ms *machineState, now time.Time) bool {
	return !ms.certNotAfter.IsZero() && now.Add(certExpiryWarn).After(ms.certNotAfter)
}

func normVersion(v string) string { return strings.TrimPrefix(strings.TrimSpace(v), "v") }

// updateFailedLocked fires when the last Status lists a failed update for the
// currently desired release version, or when the connected agent has run a
// version other than the desired one for over an hour (counted from the later
// of its connection and the desired version becoming desired).
func (s *Server) updateFailedLocked(snap *hubconfig.Snapshot, ms *machineState, now time.Time) (bool, string) {
	desired := snap.Release.Version

	if st := ms.status; st != nil {
		for _, fu := range st.FailedUpdates {
			if normVersion(fu.Version) == normVersion(desired) {
				return true, fmt.Sprintf("agent reports failed update to %s: %s", fu.Version, fu.Reason)
			}
		}
	}

	live := ms.newestLive()
	if live == nil || ms.version == "" || normVersion(ms.version) == normVersion(desired) {
		return false, ""
	}

	since := live.accepted
	if s.releaseSince.After(since) {
		since = s.releaseSince
	}

	if now.Sub(since) > versionLagAfter {
		return true, fmt.Sprintf("agent runs %s, desired %s for over %s", ms.version, desired, versionLagAfter)
	}

	return false, ""
}

func (s *Server) serveAlert(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	snap := s.cfg.Current()
	now := s.now()

	firing, reason, known := false, "", false

	if name == "stale-config" {
		known = true
		firing, reason = s.cfg.Stale(now)
	} else {
		s.mu.Lock()
		for mname, mc := range snap.Machines {
			ms := s.machines[mname]
			if ms == nil {
				ms = &machineState{name: mname}
			}

			switch name {
			case "agent-" + mname + "-disconnected":
				known = true
				firing = s.disconnectedLocked(mc, ms, now)
				reason = "agent not connected"
			case "agent-" + mname + "-cert-expiry":
				known = true
				firing = certExpiring(ms, now)
				reason = "certificate expires " + ms.certNotAfter.UTC().Format(statusTimeFormat)
			case "agent-" + mname + "-update-failed":
				known = true
				firing, reason = s.updateFailedLocked(snap, ms, now)
			}
		}
		s.mu.Unlock()
	}

	if !known {
		http.NotFound(w, r)

		return
	}

	if firing {
		http.Error(w, "firing: "+reason, http.StatusServiceUnavailable)

		return
	}

	_, _ = w.Write([]byte("ok\n"))
}
