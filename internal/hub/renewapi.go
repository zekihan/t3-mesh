package hub

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/zekihan/t3-mesh/internal/hub/hubconfig"
	"github.com/zekihan/t3-mesh/internal/pki"
	"github.com/zekihan/t3-mesh/internal/policy"
)

const (
	// The media type of a renewal request body: a PEM CSR.
	renewContentType = "application/x-pem-file"
	// The largest renewal request body.
	renewMaxBody = 16 << 10
	// Bound the time a device holds its renewal slot while sending the CSR.
	renewBodyTimeout = 10 * time.Second

	// Each identity may attempt renewalMax renewals per renewalWindow. Every
	// attempt by the newest leaf counts, whether or not it succeeds. A replay
	// candidate has to prove it holds the issued leaf's key before it counts.
	renewalMax          = 5
	renewalWindow       = 10 * time.Minute
	renewalReplayWindow = 10 * time.Minute
)

var errRenewalBusy = errors.New("hub: a renewal is already in progress or the limit is reached")

// renewReply is the body of a successful POST /api/v1/renew.
type renewReply struct {
	Certificate string `json:"certificate"`
	Chain       string `json:"chain"`
	CABundle    string `json:"caBundle"`
	CARevision  string `json:"caRevision"`
}

type renewalReplyCache struct {
	expires     time.Time
	leaf        *x509.Certificate
	previous    string
	certificate string
	chain       string
}

func (server *Server) cachedRenewal(identity, previous string) renewalReplyCache {
	server.nmu.Lock()
	defer server.nmu.Unlock()

	cached := server.renewalReplies[identity]
	if cached.previous != previous || !server.now().Before(cached.expires) {
		return renewalReplyCache{}
	}

	return cached
}

func (server *Server) expireRenewalReplies() {
	now := server.now()

	server.nmu.Lock()
	defer server.nmu.Unlock()

	for identity, cached := range server.renewalReplies {
		if !now.Before(cached.expires) {
			delete(server.renewalReplies, identity)
		}
	}
}

func (server *Server) recordRenewal(identity string, cached *renewalReplyCache) bool {
	server.nmu.Lock()
	defer server.nmu.Unlock()

	if current := server.newest[identity]; current != "" && current != cached.previous {
		return false
	}

	server.renewalReplies[identity] = *cached
	server.newest[identity] = pki.Fingerprint(cached.leaf)

	return true
}

// renewLimiter allows renewalMax attempts per renewalWindow per enrolled device.
type renewLimiter struct {
	now  func() time.Time
	hits map[string][]time.Time
	mu   sync.Mutex
}

func newRenewLimiter(now func() time.Time) *renewLimiter {
	return &renewLimiter{now: now, hits: map[string][]time.Time{}}
}

// allow records an attempt by identity or returns how long to wait.
func (limiter *renewLimiter) allow(identity string) (time.Duration, bool) {
	now := limiter.now()
	cutoff := now.Add(-renewalWindow)

	limiter.mu.Lock()
	defer limiter.mu.Unlock()

	live := limiter.hits[identity][:0]

	for _, hit := range limiter.hits[identity] {
		if hit.After(cutoff) {
			live = append(live, hit)
		}
	}

	limiter.hits[identity] = live

	if len(live) >= renewalMax {
		return live[0].Add(renewalWindow).Sub(now), false
	}

	limiter.hits[identity] = append(live, now)

	return 0, true
}

// serveRenew serves POST /api/v1/renew. By the time it runs, serveAPI has
// admitted the caller as the viewer admission does, listed under api.identities,
// and holding its newest leaf or a candidate for renewal replay. Only an enrolled device
// renews here: a KeyChain identity such as z-phone is a legitimate API caller
// and is refused.
func (server *Server) serveRenew(
	w http.ResponseWriter,
	r *http.Request,
	snap *hubconfig.Snapshot,
	session *policy.Session,
) {
	caller := session.Identity
	if !snap.Device(caller) {
		server.rejectAPI(r, caller, "renewal is for enrolled devices")
		http.Error(w, "forbidden", http.StatusForbidden)

		return
	}

	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)

		return
	}

	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != renewContentType {
		http.Error(w, "content type must be "+renewContentType, http.StatusUnsupportedMediaType)

		return
	}

	unlock, _ := server.issuance.begin(caller)
	if unlock == nil {
		server.rejectRenewalLimit(w, r, caller, time.Second)

		return
	}
	defer unlock()

	replayCandidate := server.cachedRenewal(caller, session.Fingerprint).leaf != nil
	if !replayCandidate && !server.chargeRenewal(w, r, caller) {
		return
	}

	body, ok := readRenewBody(w, r)
	if ok {
		server.renewDevice(w, r, session, body, replayCandidate)
	}
}

func (server *Server) chargeRenewal(w http.ResponseWriter, r *http.Request, caller string) bool {
	wait, ok := server.renewals.allow(caller)
	if !ok {
		server.rejectRenewalLimit(w, r, caller, wait)
	}

	return ok
}

func (server *Server) rejectRenewalLimit(w http.ResponseWriter, r *http.Request,
	caller string, wait time.Duration,
) {
	server.rejectAPI(r, caller, errRenewalBusy.Error())
	w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
	http.Error(w, "too many renewals", http.StatusTooManyRequests)
}

func readRenewBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	rc := http.NewResponseController(w)

	err := rc.SetReadDeadline(time.Now().Add(renewBodyTimeout))
	if err != nil {
		http.Error(w, "could not set request deadline", http.StatusInternalServerError)

		return nil, false
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, renewMaxBody))
	if err == nil {
		// The body deadline ends before issuance or a subsequent request.
		//nolint:errcheck // a closed connection has no deadline to clear
		_ = rc.SetReadDeadline(time.Time{})

		return body, true
	}

	_, tooBig := errors.AsType[*http.MaxBytesError](err)

	switch {
	case tooBig:
		http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
	case errors.Is(err, os.ErrDeadlineExceeded):
		http.Error(w, "request body timed out", http.StatusRequestTimeout)
	default:
		http.Error(w, "unreadable request", http.StatusBadRequest)
	}

	return nil, false
}

// renewDevice validates the CSR, has it issued and answers with the new leaf.
func (server *Server) renewDevice(
	w http.ResponseWriter,
	r *http.Request,
	session *policy.Session,
	body []byte,
	replayCandidate bool,
) {
	caller := session.Identity

	csr, identity, err := pki.ValidateCSR(body)
	if err != nil {
		server.rejectAPI(r, caller, "invalid CSR: "+err.Error())
		http.Error(w, "invalid CSR: "+err.Error(), http.StatusBadRequest)

		return
	}

	if identity != caller {
		server.rejectAPI(r, caller, "CSR names "+identity)
		http.Error(w, "CSR identity does not match the caller", http.StatusForbidden)

		return
	}

	csrKey, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		// ValidateCSR accepts ECDSA P-256 only, so this cannot happen.
		http.Error(w, "invalid CSR: key is not ECDSA", http.StatusBadRequest)

		return
	}

	snap := server.cfg.Current()

	cached := server.cachedRenewal(caller, session.Fingerprint)

	err = server.checkRenewal(r, snap, session, &cached, csrKey)
	if err != nil {
		server.rejectAPI(r, caller, err.Error())
		refuse(w, err)

		return
	}

	if replayCandidate && !server.chargeRenewal(w, r, caller) {
		return
	}

	if cached.leaf != nil {
		server.log.InfoContext(r.Context(), "Device renewal reply replayed",
			slog.String("identity", caller),
			slog.String("fingerprint", pki.Fingerprint(cached.leaf)),
		)
		server.writeRenewal(w, r, snap, &cached)

		return
	}

	server.issueRenewal(w, r, snap, session, csrKey, body)
}

func (server *Server) checkRenewal(r *http.Request, snap *hubconfig.Snapshot,
	session *policy.Session, cached *renewalReplyCache, key *ecdsa.PublicKey,
) error {
	if !snap.APICaller(session.Identity) || !snap.Device(session.Identity) {
		return errNotAPICaller
	}

	now := server.now()

	err := policy.CheckLeaf(snap.Revocations, *session, now)
	if err != nil {
		return fmt.Errorf("renewal caller: %w", err)
	}

	if cached.leaf == nil {
		return server.admitDevice(r.Context(), snap, session.Identity, session.Fingerprint)
	}

	if !key.Equal(cached.leaf.PublicKey) {
		return fmt.Errorf("%w: renewal replay key differs", errDeviceSuperseded)
	}

	err = policy.CheckLeaf(snap.Revocations, policy.Session{
		Identity:    session.Identity,
		Fingerprint: pki.Fingerprint(cached.leaf),
		NotAfter:    cached.leaf.NotAfter,
	}, now)
	if err != nil {
		return fmt.Errorf("cached renewal leaf: %w", err)
	}

	return nil
}

func (server *Server) issueRenewal(w http.ResponseWriter, r *http.Request,
	snap *hubconfig.Snapshot, session *policy.Session, csrKey *ecdsa.PublicKey, body []byte,
) {
	caller := session.Identity
	// The issuance outlives a client that hangs up: a certificate the hub asked
	// for is recorded as the newest whether or not the reply is read.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), renewTimeout)
	defer cancel()

	certPEM, chainPEM, err := server.issuer.Issue(ctx, caller, body)
	if err != nil {
		server.log.WarnContext(
			r.Context(),
			"Device renewal failed",
			slog.String("identity", caller),
			slog.Any("error", err),
		)
		http.Error(w, "issuance failed", http.StatusBadGateway)

		return
	}

	leaf, err := verifyIssuedLeaf(certPEM, caller, csrKey)
	if err == nil {
		err = pki.CheckDeviceLeaf(leaf)
	}

	if err != nil {
		server.log.WarnContext(
			r.Context(),
			"Device renewal produced an unusable certificate",
			slog.String("identity", caller),
			slog.Any("error", err),
		)
		http.Error(w, "issuance failed", http.StatusBadGateway)

		return
	}

	cached := renewalReplyCache{
		expires: server.now().Add(renewalReplayWindow),
		leaf:    leaf, previous: session.Fingerprint,
		certificate: string(certPEM), chain: string(chainPEM),
	}
	if !server.recordRenewal(caller, &cached) {
		server.rejectAPI(r, caller, errDeviceSuperseded.Error())
		http.Error(w, "renewal superseded", http.StatusConflict)

		return
	}
	//nolint:contextcheck // pruning runs detached from the request on purpose
	server.afterIssuance(caller)

	server.log.InfoContext(
		r.Context(),
		"Certificate issued",
		slog.Any("identity", caller),
		slog.Any("fingerprint", pki.Fingerprint(leaf)),
		slog.String("via", "device-renewal"),
		slog.String("notAfter", leaf.NotAfter.UTC().Format(time.RFC3339)),
	)
	server.log.InfoContext(
		r.Context(),
		"Renewal",
		slog.Any("newFingerprint", pki.Fingerprint(leaf)),
		slog.Any("oldFingerprint", session.Fingerprint),
		slog.Any("identity", caller),
	)

	server.writeRenewal(w, r, snap, &cached)
}

func (server *Server) writeRenewal(w http.ResponseWriter, r *http.Request,
	snap *hubconfig.Snapshot, cached *renewalReplyCache,
) {
	server.writeAPI(w, r, renewReply{
		Certificate: cached.certificate,
		Chain:       cached.chain,
		CABundle:    snap.TrustBundle.PEM,
		CARevision:  snap.TrustBundle.Revision,
	})
}
