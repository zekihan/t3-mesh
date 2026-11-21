// Package kube shares the hub's in-cluster Kubernetes HTTP transport.
package kube

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	serviceAccountDir = "/var/run/secrets/kubernetes.io/serviceaccount"
	handshakeTimeout  = 10 * time.Second
	headerTimeout     = 10 * time.Second
)

var (
	errNoAPIServer = errors.New(
		"kube: no API server configured and KUBERNETES_SERVICE_HOST/PORT unset",
	)
	errNoCACerts = errors.New("kube: CA file holds no certificates")
)

// Client authenticates each request with the current projected token.
type Client struct {
	http      *http.Client
	base      string
	tokenPath string
}

// Namespace returns the pod namespace from the projected service account.
func Namespace() (string, error) {
	raw, err := os.ReadFile(serviceAccountDir + "/namespace")
	if err != nil {
		return "", fmt.Errorf("read pod namespace: %w", err)
	}

	return strings.TrimSpace(string(raw)), nil
}

func New(server, caPath, tokenPath string, client *http.Client) (*Client, error) {
	base, err := apiBase(server)
	if err != nil {
		return nil, err
	}

	if client == nil {
		if caPath == "" {
			caPath = serviceAccountDir + "/ca.crt"
		}

		client, err = inClusterClient(caPath)
		if err != nil {
			return nil, err
		}
	}

	if tokenPath == "" {
		tokenPath = serviceAccountDir + "/token"
	}

	return &Client{http: client, base: base, tokenPath: tokenPath}, nil
}

func (client *Client) Do(
	ctx context.Context,
	method, path string,
	body io.Reader,
) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, client.base+path, body)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}

	tok, err := os.ReadFile(client.tokenPath)
	if err != nil {
		return nil, fmt.Errorf("read service account token: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(tok)))
	req.Header.Set("Accept", "application/json")

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := client.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", method, req.URL.Path, err)
	}

	return resp, nil
}

// apiBase returns the API server base URL, falling back to the in-cluster
// service environment when none is configured.
func apiBase(apiServer string) (string, error) {
	base := apiServer
	if base == "" {
		host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
		if host == "" || port == "" {
			return "", errNoAPIServer
		}

		base = "https://" + net.JoinHostPort(host, port)
	}

	return strings.TrimRight(base, "/"), nil
}

// inClusterClient builds an HTTP client that trusts the cluster CA at caPath.
func inClusterClient(caPath string) (*http.Client, error) {
	ca, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("kube: read CA: %w", err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, errNoCACerts
	}

	return &http.Client{Transport: &http.Transport{
		TLSClientConfig:       &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:   handshakeTimeout,
		ResponseHeaderTimeout: headerTimeout,
	}}, nil
}
