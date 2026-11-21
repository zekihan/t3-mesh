package kube

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

const (
	watchTimeout      = 310 * time.Second
	apiTimeout        = 5 * time.Second
	maxConfigMapReply = 4 << 20
)

var (
	errConfigMapStatus  = errors.New("unexpected ConfigMap API status")
	errConfigMapMissing = errors.New("named ConfigMap missing from list")
	errConfigMapWatch   = errors.New("ConfigMap watch interrupted")
)

type Metadata struct {
	Name            string `json:"name"`
	ResourceVersion string `json:"resourceVersion"`
}

type ConfigMap struct {
	Data     map[string]string `json:"data"`
	Metadata Metadata          `json:"metadata"`
}

type configMapList struct {
	Metadata Metadata    `json:"metadata"`
	Items    []ConfigMap `json:"items"`
}

type configMapEvent struct {
	Object ConfigMap `json:"object"`
	Type   string    `json:"type"`
}

func ConfigMapsPath(namespace string) string {
	return "/api/v1/namespaces/" + url.PathEscape(namespace) + "/configmaps"
}

func (client *Client) WatchConfigMap(
	ctx context.Context, namespace, name string, update func(map[string]string),
) error {
	path := ConfigMapsPath(namespace)
	query := url.Values{"fieldSelector": {"metadata.name=" + name}}

	var list configMapList

	_, err := client.ConfigMapRequest(ctx, http.MethodGet, path+"?"+query.Encode(), nil, &list)
	if err != nil {
		return err
	}

	if len(list.Items) != 1 || list.Items[0].Metadata.Name != name ||
		list.Metadata.ResourceVersion == "" {
		return fmt.Errorf("%w: %s", errConfigMapMissing, name)
	}

	query.Set("watch", "true")
	query.Set("resourceVersion", list.Metadata.ResourceVersion)
	query.Set("timeoutSeconds", "300")

	ctx, cancel := context.WithTimeout(ctx, watchTimeout)
	defer cancel()

	resp, err := client.Do(ctx, http.MethodGet, path+"?"+query.Encode(), nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w %d: watch %s", errConfigMapStatus, resp.StatusCode, name)
	}

	update(list.Items[0].Data)

	return readConfigMapEvents(resp.Body, name, update)
}

func readConfigMapEvents(body io.Reader, name string, update func(map[string]string)) error {
	dec := json.NewDecoder(body)

	for {
		var event configMapEvent

		err := dec.Decode(&event)
		switch {
		case errors.Is(err, io.EOF):
			return nil
		case err != nil:
			return fmt.Errorf("decode ConfigMap watch: %w", err)
		case event.Type == "ERROR" || event.Type == "DELETED":
			return fmt.Errorf("%w: %s (%s)", errConfigMapWatch, name, event.Type)
		case (event.Type == "ADDED" || event.Type == "MODIFIED") &&
			event.Object.Metadata.Name == name:
			update(event.Object.Data)
		}
	}
}

// ConfigMapRequest performs a bounded, non-streaming ConfigMap API request.
func (client *Client) ConfigMapRequest(
	ctx context.Context, method, path string, body io.Reader, out any,
) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, apiTimeout)
	defer cancel()

	resp, err := client.Do(ctx, method, path, body)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, fmt.Errorf("%w %d: %s %s",
			errConfigMapStatus, resp.StatusCode, method, path)
	}

	err = json.NewDecoder(io.LimitReader(resp.Body, maxConfigMapReply)).Decode(out)
	if err != nil {
		return resp.StatusCode, fmt.Errorf("decode ConfigMap response: %w", err)
	}

	return resp.StatusCode, nil
}
