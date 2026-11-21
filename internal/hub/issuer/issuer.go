// Package issuer obtains agent certificates by creating cert-manager
// CertificateRequests and waiting for them to be issued.
package issuer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/zekihan/t3-mesh/internal/hub/kube"
	"github.com/zekihan/t3-mesh/internal/pki"
	"github.com/zekihan/t3-mesh/internal/policy"
)

const (
	defaultPollInterval = 2 * time.Second
	defaultDuration     = 8760 * time.Hour

	// LabelIdentity and LabelManagedBy mark CertificateRequests created by the hub.
	LabelIdentity  = "t3-mesh.noqer.com/identity"
	LabelManagedBy = "app.kubernetes.io/managed-by"
	ManagedByValue = "t3-mesh-hub"

	maxResponseBytes = 4 << 20

	// Longest identity accepted, and longest API error body quoted in errors.
	maxIdentityLen   = policy.MaxIdentityLen
	maxErrorBodySize = 512
)

var (
	errNamespaceRequired = errors.New("issuer: namespace is required")
	errIssuerRefRequired = errors.New("issuer: issuer name, kind and group are required")
	errInvalidIdentity   = errors.New("issuer: invalid identity")
	errEmptyCSR          = errors.New("issuer: empty CSR")
	errUnknownKind       = errors.New("issuer: identity is neither an agent nor an enrolled device")
	errCSRIdentity       = errors.New("issuer: CSR identity differs from the requested identity")
	errNoRequestName     = errors.New("issuer: API server returned a request without a name")
	errNoCertInPEM       = errors.New("no certificate in PEM")
	errRequestFailed     = errors.New("certificate request failed")
	errUnexpectedStatus  = errors.New("unexpected status")
)

const (
	condReady  = "Ready"
	condDenied = "Denied"
	condTrue   = "True"
)

// statusError is a non-2xx API response; it unwraps to errUnexpectedStatus.
type statusError struct {
	err  error
	code int
}

func (e *statusError) Error() string { return e.err.Error() }
func (e *statusError) Unwrap() error { return e.err }

var identityRe = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)

// usagesFor returns the CertificateRequest usages for an identity kind. An agent
// is also a TLS server (its direct listener); an enrolled device never is, and
// the device approver-policy denies any request that adds server auth.
func usagesFor(kind policy.Kind) []string {
	if kind == policy.KindDevice {
		return []string{"client auth", "digital signature"}
	}

	return []string{"client auth", "server auth", "digital signature"}
}

// IssuerRef names the cert-manager issuer that signs requests.
type IssuerRef struct{ Name, Kind, Group string }

// Config configures the Kubernetes-backed issuer.
type Config struct {
	HTTPClient   *http.Client
	Logger       *slog.Logger
	Issuer       IssuerRef
	Namespace    string
	APIServer    string
	TokenPath    string
	CAPath       string
	Duration     time.Duration
	PollInterval time.Duration
}

// Issuer issues certificates and reports the newest one per identity.
type Issuer interface {
	// Issue creates a CertificateRequest for identity with the given CSR PEM,
	// waits until it is Ready or Denied/Failed, and returns the leaf PEM and
	// the chain PEM (status.ca). The usages follow the identity's kind, and the
	// CSR must carry exactly that identity's URI.
	Issue(ctx context.Context, identity string, csrPEM []byte) (certPEM, chainPEM []byte, err error)
	// Newest returns the lowercase hex SHA-256 of the DER of the newest issued
	// leaf for identity, or "" if none.
	Newest(ctx context.Context, identity string) (string, error)
	// Prune deletes this hub's older CertificateRequests for identity, keeping
	// the keep newest, the one Newest reports, and any still in flight.
	Prune(ctx context.Context, identity string, keep int) error
}

// K8s is the Issuer backed by the Kubernetes API.
type K8s struct {
	client *kube.Client
	log    *slog.Logger
	cfg    Config
}

var _ Issuer = (*K8s)(nil)

// New validates cfg and builds a K8s issuer.
//
//nolint:gocritic // exported constructor takes Config by value; changing it would break callers
func New(cfg Config) (*K8s, error) {
	if cfg.Namespace == "" {
		return nil, errNamespaceRequired
	}

	if cfg.Issuer.Name == "" || cfg.Issuer.Kind == "" || cfg.Issuer.Group == "" {
		return nil, errIssuerRefRequired
	}

	if cfg.Duration <= 0 {
		cfg.Duration = defaultDuration
	}

	if cfg.PollInterval <= 0 {
		cfg.PollInterval = defaultPollInterval
	}

	log := cfg.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}

	client, err := kube.New(cfg.APIServer, cfg.CAPath, cfg.TokenPath, cfg.HTTPClient)
	if err != nil {
		return nil, fmt.Errorf("issuer: %w", err)
	}

	return &K8s{cfg: cfg, client: client, log: log}, nil
}

type objectMeta struct {
	Name              string            `json:"name,omitempty"`
	GenerateName      string            `json:"generateName,omitempty"`
	Labels            map[string]string `json:"labels,omitempty"`
	CreationTimestamp string            `json:"creationTimestamp,omitempty"`
}

type issuerRef struct {
	Name  string `json:"name"`
	Kind  string `json:"kind"`
	Group string `json:"group"`
}

type crSpec struct {
	Request   []byte    `json:"request"`
	IssuerRef issuerRef `json:"issuerRef"`
	Duration  string    `json:"duration"`
	Usages    []string  `json:"usages"`
}

type condition struct {
	Type    string `json:"type"`
	Status  string `json:"status"`
	Reason  string `json:"reason"`
	Message string `json:"message"`
}

type crStatus struct {
	Certificate []byte      `json:"certificate,omitempty"`
	CA          []byte      `json:"ca,omitempty"`
	Conditions  []condition `json:"conditions,omitempty"`
}

type certificateRequest struct {
	APIVersion string     `json:"apiVersion"`
	Kind       string     `json:"kind"`
	Metadata   objectMeta `json:"metadata"`
	Spec       crSpec     `json:"spec"`
	Status     crStatus   `json:"status"`
}

type certificateRequestList struct {
	Items []certificateRequest `json:"items"`
}

func validIdentity(identity string) error {
	if identity == "" || len(identity) > maxIdentityLen || !identityRe.MatchString(identity) {
		return fmt.Errorf("%w: %q", errInvalidIdentity, identity)
	}

	return nil
}

// Issue implements Issuer.
func (k8s *K8s) Issue(ctx context.Context, identity string, csrPEM []byte) ([]byte, []byte, error) {
	err := validIdentity(identity)
	if err != nil {
		return nil, nil, err
	}

	if len(csrPEM) == 0 {
		return nil, nil, errEmptyCSR
	}

	kind, ok := policy.KindOf(identity)
	if !ok {
		return nil, nil, fmt.Errorf("%w: %q", errUnknownKind, identity)
	}

	// The request is built from the identity's kind and the CSR is checked against
	// it, so a CertificateRequest never mixes an agent's usages or URI with a
	// device's, whatever the caller passes.
	_, csrIdentity, err := pki.ValidateCSR(csrPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("issuer: %w", err)
	}

	if csrIdentity != identity {
		return nil, nil, fmt.Errorf("%w: %q, want %q", errCSRIdentity, csrIdentity, identity)
	}

	body := certificateRequest{
		APIVersion: "cert-manager.io/v1",
		Kind:       "CertificateRequest",
		Metadata: objectMeta{
			GenerateName: "t3-mesh-" + identity + "-",
			Labels: map[string]string{
				LabelIdentity:  identity,
				LabelManagedBy: ManagedByValue,
			},
		},
		Spec: crSpec{
			Request:   csrPEM,
			IssuerRef: issuerRef(k8s.cfg.Issuer),
			Duration:  k8s.cfg.Duration.String(),
			Usages:    usagesFor(kind),
		},
	}

	var created certificateRequest

	err = k8s.do(ctx, http.MethodPost, k8s.collectionURL(), body, &created)
	if err != nil {
		return nil, nil, fmt.Errorf("create certificate request: %w", err)
	}

	name := created.Metadata.Name
	if name == "" {
		return nil, nil, errNoRequestName
	}

	cur := created
	for {
		done, cert, chain, err := k8s.evaluate(identity, name, &cur)
		if err != nil {
			return nil, nil, err
		}

		if done {
			return cert, chain, nil
		}

		cur, err = k8s.pollRequest(ctx, name)
		if err != nil {
			return nil, nil, err
		}
	}
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}

	return b
}

// Fingerprint returns the lowercase hex SHA-256 of the DER of the first
// certificate in certPEM.
func Fingerprint(certPEM []byte) (string, error) {
	rest := certPEM

	for {
		var blk *pem.Block

		blk, rest = pem.Decode(rest)
		if blk == nil {
			return "", errNoCertInPEM
		}

		if blk.Type != "CERTIFICATE" {
			continue
		}

		cert, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return "", fmt.Errorf("parse certificate: %w", err)
		}

		sum := sha256.Sum256(cert.Raw)

		return hex.EncodeToString(sum[:]), nil
	}
}

// Newest implements Issuer. Requests are ordered by creationTimestamp (one
// second resolution); ties are broken by name so the result is deterministic.
func (k8s *K8s) Newest(ctx context.Context, identity string) (string, error) {
	err := validIdentity(identity)
	if err != nil {
		return "", err
	}

	items, err := k8s.listOwn(ctx, identity)
	if err != nil {
		return "", err
	}

	var (
		best     *certificateRequest
		bestTime time.Time
	)

	for i := range items {
		it := &items[i]
		if it.Metadata.Labels[LabelIdentity] != identity || len(it.Status.Certificate) == 0 {
			continue
		}

		ts, parseErr := time.Parse(time.RFC3339, it.Metadata.CreationTimestamp)
		if parseErr != nil {
			continue
		}

		if best == nil || ts.After(bestTime) ||
			(ts.Equal(bestTime) && it.Metadata.Name > best.Metadata.Name) {
			best, bestTime = it, ts
		}
	}

	if best == nil {
		return "", nil
	}

	fp, err := Fingerprint(best.Status.Certificate)
	if err != nil {
		return "", fmt.Errorf("certificate request %s: %w", best.Metadata.Name, err)
	}

	return fp, nil
}

// settled reports whether cr reached Ready, Denied or Failed.
func settled(cr *certificateRequest) bool {
	for _, cond := range cr.Status.Conditions {
		switch {
		case cond.Type == condReady && cond.Status == condTrue,
			cond.Type == condDenied && cond.Status == condTrue,
			cond.Type == condReady && cond.Status == "False" &&
				(cond.Reason == "Failed" || cond.Reason == "Denied"):
			return true
		}
	}

	return false
}

// Prune implements Issuer. Requests are ranked newest first by
// creationTimestamp, ties by name descending, as Newest does.
func (k8s *K8s) Prune(ctx context.Context, identity string, keep int) error {
	err := validIdentity(identity)
	if err != nil {
		return err
	}

	items, err := k8s.listOwn(ctx, identity)
	if err != nil {
		return err
	}

	var errs []error

	for _, name := range pruneCandidates(items, identity, keep) {
		delErr := k8s.do(
			ctx, http.MethodDelete, k8s.collectionURL()+"/"+url.PathEscape(name), nil, nil,
		)
		if delErr != nil && !isNotFound(delErr) {
			errs = append(errs, fmt.Errorf("delete certificate request %s: %w", name, delErr))

			continue
		}

		k8s.log.InfoContext(
			ctx,
			"Pruned certificate request",
			slog.Any("request", name),
			slog.Any("identity", identity),
		)
	}

	return errors.Join(errs...)
}

// pruneCandidates returns the names to delete: everything past the keep newest,
// except the newest issued request and any not yet settled.
func pruneCandidates(items []certificateRequest, identity string, keep int) []string {
	type ranked struct {
		ts time.Time
		cr *certificateRequest
	}

	all := make([]ranked, 0, len(items))

	for i := range items {
		item := &items[i]
		if item.Metadata.Labels[LabelIdentity] != identity || item.Metadata.Name == "" {
			continue
		}

		ts, err := time.Parse(time.RFC3339, item.Metadata.CreationTimestamp)
		if err != nil {
			// Unknown age: never delete.
			continue
		}

		all = append(all, ranked{ts: ts, cr: item})
	}

	slices.SortFunc(all, func(a, b ranked) int {
		if c := b.ts.Compare(a.ts); c != 0 {
			return c
		}

		return strings.Compare(b.cr.Metadata.Name, a.cr.Metadata.Name)
	})

	// The first request with a certificate is the one Newest returns.
	newest := slices.IndexFunc(all, func(r ranked) bool { return len(r.cr.Status.Certificate) > 0 })

	var names []string

	for i, r := range all {
		if i >= keep && i != newest && settled(r.cr) {
			names = append(names, r.cr.Metadata.Name)
		}
	}

	return names
}

func isNotFound(err error) bool {
	var se *statusError

	return errors.As(err, &se) && se.code == http.StatusNotFound
}

// listOwn returns this hub's CertificateRequests for identity.
func (k8s *K8s) listOwn(ctx context.Context, identity string) ([]certificateRequest, error) {
	q := url.Values{}
	q.Set("labelSelector", LabelManagedBy+"="+ManagedByValue+","+LabelIdentity+"="+identity)

	var list certificateRequestList

	err := k8s.do(ctx, http.MethodGet, k8s.collectionURL()+"?"+q.Encode(), nil, &list)
	if err != nil {
		return nil, fmt.Errorf("list certificate requests: %w", err)
	}

	return list.Items, nil
}

// pollRequest reads an existing request. A temporary API failure must not
// abandon a request that cert-manager can still issue.
func (k8s *K8s) pollRequest(ctx context.Context, name string) (certificateRequest, error) {
	requestURL := k8s.collectionURL() + "/" + url.PathEscape(name)

	for {
		timer := time.NewTimer(k8s.cfg.PollInterval)
		select {
		case <-ctx.Done():
			timer.Stop()

			return certificateRequest{}, fmt.Errorf(
				"waiting for certificate request %s: %w",
				name,
				ctx.Err(),
			)
		case <-timer.C:
		}

		var cur certificateRequest

		err := k8s.do(ctx, http.MethodGet, requestURL, nil, &cur)
		if err == nil {
			return cur, nil
		}

		if !retryablePollError(err) {
			return certificateRequest{}, fmt.Errorf("get certificate request %s: %w", name, err)
		}
	}
}

func retryablePollError(err error) bool {
	status, ok := errors.AsType[*statusError](err)
	if !ok {
		return false
	}

	switch status.code {
	case http.StatusTooManyRequests, http.StatusInternalServerError, http.StatusBadGateway,
		http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	default:
		return false
	}
}

func (k8s *K8s) evaluate(
	identity, name string,
	cr *certificateRequest,
) (bool, []byte, []byte, error) {
	for _, cond := range cr.Status.Conditions {
		denied := cond.Type == "Denied" && cond.Status == "True"

		failed := cond.Type == "Ready" && cond.Status == "False" &&
			(cond.Reason == "Failed" || cond.Reason == "Denied")
		if denied || failed {
			return false, nil, nil, fmt.Errorf(
				"%w: %s %s: %s",
				errRequestFailed,
				name,
				strings.ToLower(firstNonEmpty(cond.Reason, cond.Type)),
				cond.Message,
			)
		}
	}

	for _, cond := range cr.Status.Conditions {
		if cond.Type != "Ready" || cond.Status != "True" {
			continue
		}

		if len(cr.Status.Certificate) == 0 {
			return false, nil, nil, nil
		}

		fp, err := Fingerprint(cr.Status.Certificate)
		if err != nil {
			return false, nil, nil, fmt.Errorf("certificate request %s: %w", name, err)
		}

		k8s.log.Info(
			"Certificate issued",
			slog.Any("identity", identity),
			slog.Any("fingerprint", fp),
			slog.Any("request", name),
		)

		return true, cr.Status.Certificate, cr.Status.CA, nil
	}

	return false, nil, nil, nil
}

func (k8s *K8s) do(ctx context.Context, method, rawURL string, body, out any) error {
	var rd io.Reader

	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("encode request: %w", err)
		}

		rd = bytes.NewReader(b)
	}

	resp, err := k8s.client.Do(ctx, method, rawURL, rd)
	if err != nil {
		return fmt.Errorf("issuer API request: %w", err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		msg := strings.TrimSpace(string(data))
		if len(msg) > maxErrorBodySize {
			msg = msg[:maxErrorBodySize]
		}

		return &statusError{
			err: fmt.Errorf(
				"%s %s: %w %d: %s", method, rawURL, errUnexpectedStatus, resp.StatusCode, msg,
			),
			code: resp.StatusCode,
		}
	}

	if out != nil {
		err := json.Unmarshal(data, out)
		if err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
	}

	return nil
}

func (k8s *K8s) collectionURL() string {
	return "/apis/cert-manager.io/v1/namespaces/" + url.PathEscape(
		k8s.cfg.Namespace,
	) + "/certificaterequests"
}
