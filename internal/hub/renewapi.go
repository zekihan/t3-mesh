package hub

import (
	"context"
	"crypto/ecdsa"
	"errors"
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
)

const (
	// The media type of a renewal request body: a PEM CSR.
	renewContentType = "application/x-pem-file"
	// The largest renewal request body.
	renewMaxBody = 16 << 10
	// Bound the time a device holds its renewal slot while sending the CSR.
	renewBodyTimeout = 10 * time.Second

	// Each identity may attempt renewalMax renewals per renewalWindow. Every
	// attempt that passes admission counts, whether or not it succeeds, so a
	// device cannot make the hub create certificate requests in a loop.
	renewalMax    = 5
	renewalWindow = 10 * time.Minute
)

var errRenewalBusy = errors.New("hub: a renewal is already in progress or the limit is reached")

// renewReply is the body of a successful POST /api/v1/renew.
type renewReply struct {
	Certificate string `json:"certificate"`
	Chain       string `json:"chain"`
	CABundle    string `json:"caBundle"`
	CARevision  string `json:"caRevision"`
}

// renewLimiter allows one renewal at a time per identity and renewalMax
// attempts per renewalWindow. Identities are enrolled devices only, so the
// table is as small as the configuration.
type renewLimiter struct {
	now  func() time.Time
	hits map[string][]time.Time
	busy map[string]bool
	mu   sync.Mutex
}

func newRenewLimiter(now func() time.Time) *renewLimiter {
	return &renewLimiter{now: now, hits: map[string][]time.Time{}, busy: map[string]bool{}}
}

// begin records an attempt by identity. When it is allowed it returns the
// function that ends the attempt; otherwise it returns how long to wait.
func (limiter *renewLimiter) begin(identity string) (func(), time.Duration, bool) {
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

	if limiter.busy[identity] {
		return nil, time.Second, false
	}

	if len(live) >= renewalMax {
		return nil, live[0].Add(renewalWindow).Sub(now), false
	}

	limiter.hits[identity] = append(live, now)
	limiter.busy[identity] = true

	return func() {
		limiter.mu.Lock()
		delete(limiter.busy, identity)
		limiter.mu.Unlock()
	}, 0, true
}

// serveRenew serves POST /api/v1/renew. By the time it runs, serveAPI has
// admitted the caller as the viewer admission does, listed under api.identities,
// and, for an enrolled device, holding its newest leaf. Only an enrolled device
// renews here: a KeyChain identity such as z-phone is a legitimate API caller
// and is refused.
func (server *Server) serveRenew(
	w http.ResponseWriter,
	r *http.Request,
	snap *hubconfig.Snapshot,
	caller string,
) {
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

	end, wait, ok := server.renewals.begin(caller)
	if !ok {
		server.rejectAPI(r, caller, errRenewalBusy.Error())
		w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
		http.Error(w, "too many renewals", http.StatusTooManyRequests)

		return
	}
	defer end()

	body, ok := readRenewBody(w, r)
	if ok {
		server.renewDevice(w, r, snap, caller, body)
	}
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
	snap *hubconfig.Snapshot,
	caller string,
	body []byte,
) {
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

	//nolint:contextcheck // pruning runs detached from the request on purpose
	server.noteIssued(caller, pki.Fingerprint(leaf))

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
		slog.Any("oldFingerprint", r.Header.Get(HeaderFingerprint)),
		slog.Any("identity", caller),
	)

	server.writeAPI(w, r, renewReply{
		Certificate: string(certPEM),
		Chain:       string(chainPEM),
		CABundle:    snap.TrustBundle.PEM,
		CARevision:  snap.TrustBundle.Revision,
	})
}
