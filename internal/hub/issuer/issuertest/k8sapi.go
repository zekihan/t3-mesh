package issuertest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zekihan/t3-mesh/internal/hub/issuer"
	"github.com/zekihan/t3-mesh/internal/pki/pkitest"
	"github.com/zekihan/t3-mesh/internal/policy"
)

const (
	crPrefix      = "/apis/cert-manager.io/v1/namespaces/mtls-pki/certificaterequests"
	tokenFileMode = 0o600
	certDuration  = 8760 * time.Hour
	pollInterval  = 5 * time.Millisecond
)

var (
	errBadRequestBody = errors.New("issuertest: bad CertificateRequest")
	errNoPolicy       = errors.New("no CertificateRequestPolicy allows the request")
	errDenied         = errors.New("denied")
)

// Request is a CertificateRequest the hub created, as a policy sees it.
type Request struct {
	CSR  *x509.CertificateRequest
	Name string
	// Identity is the value of the hub's identity label.
	Identity string
	Duration string
	// IssuerRef is the issuer's name, kind and group.
	IssuerRef [3]string
	Usages    []string
	IsCA      bool
	// Approved is whether the policies approved the request.
	Approved bool
}

// Policy decides whether a Request may be approved; nil approves it.
type Policy func(req *Request) error

// API is a stand-in for the certificaterequests endpoint of the Kubernetes API
// with cert-manager behind it: it records every request, runs it through the
// approver policies and signs the approved ones with the test CA, giving each
// the usages the request asked for.
type API struct {
	tb      testing.TB
	srv     *httptest.Server
	ca      *pkitest.CA
	policy  Policy
	items   map[string]*item
	order   []string
	reqs    []Request
	counter int
	mu      sync.Mutex
}

type item struct {
	created time.Time
	denied  string
	certPEM []byte
	req     Request
}

type crMeta struct {
	Labels            map[string]string `json:"labels,omitempty"`
	Name              string            `json:"name"`
	CreationTimestamp string            `json:"creationTimestamp,omitempty"`
	GenerateName      string            `json:"generateName,omitempty"`
}

type crCondition struct {
	Type    string `json:"type"`
	Status  string `json:"status"`
	Reason  string `json:"reason,omitempty"`
	Message string `json:"message,omitempty"`
}

type crStatus struct {
	Certificate []byte        `json:"certificate,omitempty"`
	CA          []byte        `json:"ca,omitempty"`
	Conditions  []crCondition `json:"conditions,omitempty"`
}

type crSpec struct {
	IssuerRef struct {
		Name  string `json:"name"`
		Kind  string `json:"kind"`
		Group string `json:"group"`
	} `json:"issuerRef"`
	Duration string   `json:"duration"`
	Request  []byte   `json:"request"`
	Usages   []string `json:"usages"`
	IsCA     bool     `json:"isCA"` //nolint:tagliatelle // cert-manager's field name
}

type crObject struct {
	Metadata crMeta   `json:"metadata"`
	Status   crStatus `json:"status"`
	Spec     crSpec   `json:"spec"`
}

type crList struct {
	Items []crObject `json:"items"`
}

// NewAPI starts the stand-in. Every request is evaluated by approve.
func NewAPI(tb testing.TB, ca *pkitest.CA, approve Policy) *API {
	tb.Helper()

	api := &API{tb: tb, ca: ca, policy: approve, items: map[string]*item{}}
	api.srv = httptest.NewServer(http.HandlerFunc(api.handle))

	tb.Cleanup(api.srv.Close)

	return api
}

// NewIssuer returns the real Kubernetes-backed issuer pointed at the stand-in.
func (api *API) NewIssuer(tb testing.TB) *issuer.K8s {
	tb.Helper()

	token := filepath.Join(tb.TempDir(), "token")

	err := os.WriteFile(token, []byte("test-token"), tokenFileMode)
	if err != nil {
		tb.Fatal(err)
	}

	iss, err := issuer.New(issuer.Config{
		Namespace:    "mtls-pki",
		Issuer:       issuer.IssuerRef{Name: "clients", Kind: "Issuer", Group: "cert-manager.io"},
		APIServer:    api.srv.URL,
		TokenPath:    token,
		HTTPClient:   api.srv.Client(),
		PollInterval: pollInterval,
	})
	if err != nil {
		tb.Fatal(err)
	}

	return iss
}

// Requests returns every request the hub created, in order, denied ones included.
func (api *API) Requests() []Request {
	api.mu.Lock()
	defer api.mu.Unlock()

	return slices.Clone(api.reqs)
}

func (api *API) handle(w http.ResponseWriter, r *http.Request) {
	api.mu.Lock()
	defer api.mu.Unlock()

	rest, ok := strings.CutPrefix(r.URL.Path, crPrefix)
	name := strings.TrimPrefix(rest, "/")

	switch {
	case !ok:
		http.Error(w, "unsupported", http.StatusNotFound)
	case r.Method == http.MethodPost && name == "":
		api.create(w, r)
	case r.Method == http.MethodGet && name == "":
		api.list(w, r)
	case r.Method == http.MethodGet:
		api.get(w, name)
	case r.Method == http.MethodDelete:
		delete(api.items, name)
		api.write(w, struct{}{})
	default:
		http.Error(w, "unsupported", http.StatusNotFound)
	}
}

func (api *API) write(w http.ResponseWriter, doc any) {
	err := json.NewEncoder(w).Encode(doc)
	if err != nil {
		api.tb.Logf("issuertest: write response: %v", err)
	}
}

func parseRequest(body *crObject) (Request, error) {
	block, _ := pem.Decode(body.Spec.Request)
	if block == nil {
		return Request{}, fmt.Errorf("%w: no CSR", errBadRequestBody)
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return Request{}, fmt.Errorf("%w: %w", errBadRequestBody, err)
	}

	ref := body.Spec.IssuerRef

	return Request{
		CSR: csr, Identity: body.Metadata.Labels[issuer.LabelIdentity],
		Duration: body.Spec.Duration, Usages: body.Spec.Usages, IsCA: body.Spec.IsCA,
		IssuerRef: [3]string{ref.Name, ref.Kind, ref.Group},
	}, nil
}

func (api *API) create(w http.ResponseWriter, r *http.Request) {
	var body crObject

	err := json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)

		return
	}

	req, err := parseRequest(&body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)

		return
	}

	api.counter++
	req.Name = fmt.Sprintf("%s%05d", body.Metadata.GenerateName, api.counter)

	entry := &item{req: req, created: time.Now()}
	api.items[req.Name] = entry
	api.order = append(api.order, req.Name)

	err = api.policy(&req)
	if err == nil {
		req.Approved = true
		entry.req.Approved = true

		entry.certPEM, err = api.sign(&req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)

			return
		}
	} else {
		entry.denied = err.Error()
	}

	api.reqs = append(api.reqs, req)

	w.WriteHeader(http.StatusCreated)
	api.write(w, crObject{Metadata: crMeta{Name: req.Name}})
}

// sign issues the certificate cert-manager would: the usages of the request.
func (api *API) sign(req *Request) ([]byte, error) {
	var usages []x509.ExtKeyUsage

	for _, usage := range req.Usages {
		switch usage {
		case "client auth":
			usages = append(usages, x509.ExtKeyUsageClientAuth)
		case "server auth":
			usages = append(usages, x509.ExtKeyUsageServerAuth)
		}
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: req.CSR.Raw})

	cert, _, err := api.ca.SignCSRUsages(csrPEM, certDuration, usages)
	if err != nil {
		return nil, fmt.Errorf("issuertest: sign: %w", err)
	}

	return cert, nil
}

func (api *API) object(entry *item) crObject {
	obj := crObject{Metadata: crMeta{
		Name:              entry.req.Name,
		CreationTimestamp: entry.created.UTC().Format(time.RFC3339),
		Labels: map[string]string{
			issuer.LabelIdentity:  entry.req.Identity,
			issuer.LabelManagedBy: issuer.ManagedByValue,
		},
	}}

	if entry.denied != "" {
		obj.Status.Conditions = []crCondition{
			{Type: "Denied", Status: "True", Reason: "policy", Message: entry.denied},
		}

		return obj
	}

	obj.Status = crStatus{
		Certificate: entry.certPEM,
		CA:          api.ca.CertPEM,
		Conditions:  []crCondition{{Type: "Ready", Status: "True"}},
	}

	return obj
}

func (api *API) get(w http.ResponseWriter, name string) {
	entry, ok := api.items[name]
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)

		return
	}

	api.write(w, api.object(entry))
}

func (api *API) list(w http.ResponseWriter, r *http.Request) {
	selector := r.URL.Query().Get("labelSelector")
	list := crList{Items: []crObject{}}

	for _, name := range api.order {
		entry, ok := api.items[name]
		if ok && strings.Contains(selector, issuer.LabelIdentity+"="+entry.req.Identity) {
			list.Items = append(list.Items, api.object(entry))
		}
	}

	api.write(w, list)
}

// HomelabPolicies is the pair of CertificateRequestPolicies the homelab chart
// renders for the hub's ServiceAccount, and the rule that a request is approved
// only when one policy allows all of it. A mixed request, with the usages of one
// and the URI of the other, is allowed by neither.
func HomelabPolicies(agents, devices []string) Policy {
	return func(req *Request) error {
		agent := allowed(req, agents, []string{"client auth", "server auth", "digital signature"})
		device := allowed(req, devices, []string{"client auth", "digital signature"})

		if agent == nil || device == nil {
			return nil
		}

		return fmt.Errorf("%w: %s", errNoPolicy, req.Identity)
	}
}

// allowed is one policy: exactly the enumerated URIs, only the listed usages,
// ECDSA P-256, 8760h, no CN and no DNS, IP or email SANs, not a CA, and the
// clients Issuer.
func allowed(req *Request, identities, usages []string) error {
	err := allowedShape(req)
	if err != nil {
		return err
	}

	if len(req.Usages) == 0 {
		return fmt.Errorf("%w: no usages", errDenied)
	}

	for _, usage := range req.Usages {
		if !slices.Contains(usages, usage) {
			return fmt.Errorf("%w: usage %q", errDenied, usage)
		}
	}

	if len(req.CSR.URIs) == 0 {
		return fmt.Errorf("%w: no URI", errDenied)
	}

	for _, uri := range req.CSR.URIs {
		name, idErr := policy.IdentityFromURI(uri.String())
		if idErr != nil || !slices.Contains(identities, name) {
			return fmt.Errorf("%w: URI %s", errDenied, uri)
		}
	}

	return nil
}

func allowedShape(req *Request) error {
	csr := req.CSR

	pub, ok := csr.PublicKey.(*ecdsa.PublicKey)

	switch {
	case !ok || pub.Curve != elliptic.P256():
		return fmt.Errorf("%w: key", errDenied)
	case req.IsCA, req.Duration != certDuration.String():
		return fmt.Errorf("%w: isCA or duration", errDenied)
	case req.IssuerRef != [3]string{"clients", "Issuer", "cert-manager.io"}:
		return fmt.Errorf("%w: issuer", errDenied)
	case csr.Subject.CommonName != "" || len(csr.DNSNames) > 0 || len(csr.IPAddresses) > 0 ||
		len(csr.EmailAddresses) > 0:
		return fmt.Errorf("%w: subject or SANs", errDenied)
	}

	return nil
}
