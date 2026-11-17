// Package issuer obtains agent certificates by creating cert-manager
// CertificateRequests and waiting for them to be issued.
package issuer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

const (
	defaultTokenPath    = /* #nosec G101 */ "/var/run/secrets/kubernetes.io/serviceaccount/token"
	defaultCAPath       = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	defaultPollInterval = 2 * time.Second
	defaultDuration     = 8760 * time.Hour

	// LabelIdentity and LabelManagedBy mark CertificateRequests created by the hub.
	LabelIdentity  = "t3-mesh.noqer.com/identity"
	LabelManagedBy = "app.kubernetes.io/managed-by"
	ManagedByValue = "t3-mesh-hub"

	maxResponseBytes = 4 << 20
)

var identityRe = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)

// IssuerRef names the cert-manager issuer that signs requests.
type IssuerRef struct{ Name, Kind, Group string }

// Config configures the Kubernetes-backed issuer.
type Config struct {
	Namespace string
	Issuer    IssuerRef
	Duration  time.Duration

	// APIServer is the base URL of the API server. Empty means in-cluster
	// (KUBERNETES_SERVICE_HOST/PORT).
	APIServer string
	// TokenPath is re-read on every request. Empty means the in-cluster default.
	TokenPath string
	// CAPath is the API server CA. Used only when HTTPClient is nil.
	CAPath string
	// HTTPClient overrides the client entirely (tests).
	HTTPClient *http.Client
	// PollInterval is how often a pending request is re-read.
	PollInterval time.Duration
	Logger       *slog.Logger
}

// Issuer issues certificates and reports the newest one per identity.
type Issuer interface {
	// Issue creates a CertificateRequest for identity with the given CSR PEM,
	// waits until it is Ready or Denied/Failed, and returns the leaf PEM and
	// the chain PEM (status.ca).
	Issue(ctx context.Context, identity string, csrPEM []byte) (certPEM, chainPEM []byte, err error)
	// Newest returns the lowercase hex SHA-256 of the DER of the newest issued
	// leaf for identity, or "" if none.
	Newest(ctx context.Context, identity string) (string, error)
}

// K8s is the Issuer backed by the Kubernetes API.
type K8s struct {
	cfg    Config
	client *http.Client
	base   string
	log    *slog.Logger
}

var _ Issuer = (*K8s)(nil)

// New validates cfg and builds a K8s issuer.
func New(cfg Config) (*K8s, error) {
	if cfg.Namespace == "" {
		return nil, errors.New("issuer: namespace is required")
	}
	if cfg.Issuer.Name == "" || cfg.Issuer.Kind == "" || cfg.Issuer.Group == "" {
		return nil, errors.New("issuer: issuer name, kind and group are required")
	}
	if cfg.Duration <= 0 {
		cfg.Duration = defaultDuration
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = defaultPollInterval
	}
	if cfg.TokenPath == "" {
		cfg.TokenPath = defaultTokenPath
	}
	if cfg.CAPath == "" {
		cfg.CAPath = defaultCAPath
	}
	log := cfg.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}

	base := cfg.APIServer
	if base == "" {
		host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
		if host == "" || port == "" {
			return nil, errors.New(
				"issuer: no APIServer configured and KUBERNETES_SERVICE_HOST/PORT unset",
			)
		}
		base = "https://" + net.JoinHostPort(host, port)
	}
	base = strings.TrimRight(base, "/")

	client := cfg.HTTPClient
	if client == nil {
		ca, err := os.ReadFile(cfg.CAPath)
		if err != nil {
			return nil, fmt.Errorf("issuer: read CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(ca) {
			return nil, errors.New("issuer: CA file holds no certificates")
		}
		client = &http.Client{Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
			TLSHandshakeTimeout: 10 * time.Second,
		}}
	}
	return &K8s{cfg: cfg, client: client, base: base, log: log}, nil
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

func (k *K8s) collectionURL() string {
	return k.base + "/apis/cert-manager.io/v1/namespaces/" + url.PathEscape(
		k.cfg.Namespace,
	) + "/certificaterequests"
}

func (k *K8s) do(ctx context.Context, method, u string, body, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("encode request: %w", err)
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	tok, err := os.ReadFile(k.cfg.TokenPath)
	if err != nil {
		return fmt.Errorf("read service account token: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(tok)))
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := k.client.Do(req)
	if err != nil {
		return fmt.Errorf("%s %s: %w", method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		msg := strings.TrimSpace(string(data))
		if len(msg) > 512 {
			msg = msg[:512]
		}
		return fmt.Errorf(
			"%s %s: unexpected status %d: %s",
			method,
			req.URL.Path,
			resp.StatusCode,
			msg,
		)
	}
	if out != nil {
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
	}
	return nil
}

func validIdentity(identity string) error {
	if len(identity) == 0 || len(identity) > 40 || !identityRe.MatchString(identity) {
		return fmt.Errorf("issuer: invalid identity %q", identity)
	}
	return nil
}

// Issue implements Issuer.
func (k *K8s) Issue(ctx context.Context, identity string, csrPEM []byte) ([]byte, []byte, error) {
	if err := validIdentity(identity); err != nil {
		return nil, nil, err
	}
	if len(csrPEM) == 0 {
		return nil, nil, errors.New("issuer: empty CSR")
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
			IssuerRef: issuerRef(k.cfg.Issuer),
			Duration:  k.cfg.Duration.String(),
			Usages:    []string{"client auth", "server auth", "digital signature"},
		},
	}
	var created certificateRequest
	if err := k.do(ctx, http.MethodPost, k.collectionURL(), body, &created); err != nil {
		return nil, nil, fmt.Errorf("create certificate request: %w", err)
	}
	name := created.Metadata.Name
	if name == "" {
		return nil, nil, errors.New("issuer: API server returned a request without a name")
	}

	cur := created
	for {
		done, cert, chain, err := k.evaluate(identity, name, &cur)
		if err != nil {
			return nil, nil, err
		}
		if done {
			return cert, chain, nil
		}
		t := time.NewTimer(k.cfg.PollInterval)
		select {
		case <-ctx.Done():
			t.Stop()
			return nil, nil, fmt.Errorf("waiting for certificate request %s: %w", name, ctx.Err())
		case <-t.C:
		}
		cur = certificateRequest{}
		if err := k.do(
			ctx,
			http.MethodGet,
			k.collectionURL()+"/"+url.PathEscape(name),
			nil,
			&cur,
		); err != nil {
			return nil, nil, fmt.Errorf("get certificate request %s: %w", name, err)
		}
	}
}

func (k *K8s) evaluate(
	identity, name string,
	cr *certificateRequest,
) (bool, []byte, []byte, error) {
	for _, c := range cr.Status.Conditions {
		denied := c.Type == "Denied" && c.Status == "True"
		failed := c.Type == "Ready" && c.Status == "False" &&
			(c.Reason == "Failed" || c.Reason == "Denied")
		if denied || failed {
			return false, nil, nil, fmt.Errorf(
				"certificate request %s %s: %s",
				name,
				strings.ToLower(firstNonEmpty(c.Reason, c.Type)),
				c.Message,
			)
		}
	}
	for _, c := range cr.Status.Conditions {
		if c.Type == "Ready" && c.Status == "True" {
			if len(cr.Status.Certificate) == 0 {
				return false, nil, nil, nil
			}
			fp, err := Fingerprint(cr.Status.Certificate)
			if err != nil {
				return false, nil, nil, fmt.Errorf("certificate request %s: %w", name, err)
			}
			k.log.Info(
				"certificate issued",
				"identity",
				identity,
				"fingerprint",
				fp,
				"request",
				name,
			)
			return true, cr.Status.Certificate, cr.Status.CA, nil
		}
	}
	return false, nil, nil, nil
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
			return "", errors.New("no certificate in PEM")
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
func (k *K8s) Newest(ctx context.Context, identity string) (string, error) {
	if err := validIdentity(identity); err != nil {
		return "", err
	}
	q := url.Values{}
	q.Set("labelSelector", LabelManagedBy+"="+ManagedByValue+","+LabelIdentity+"="+identity)
	var list certificateRequestList
	if err := k.do(ctx, http.MethodGet, k.collectionURL()+"?"+q.Encode(), nil, &list); err != nil {
		return "", fmt.Errorf("list certificate requests: %w", err)
	}
	var (
		best     *certificateRequest
		bestTime time.Time
	)
	for i := range list.Items {
		it := &list.Items[i]
		if it.Metadata.Labels[LabelIdentity] != identity || len(it.Status.Certificate) == 0 {
			continue
		}
		ts, err := time.Parse(time.RFC3339, it.Metadata.CreationTimestamp)
		if err != nil {
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
