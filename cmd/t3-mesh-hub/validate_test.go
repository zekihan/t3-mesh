package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidate(t *testing.T) {
	const valid = `machines:
  devbox: {identity: agent-devbox, services: {t3: {kind: http}}}
viewerDomain: mesh.example.com
release: {version: v1.2.3}
`
	for _, tc := range []struct {
		name, config string
		valid        bool
	}{
		{"valid", valid, true},
		{"unknown", valid + "unknown: true\n", false},
		{"bad pin", strings.Replace(valid, "identity: agent-devbox,",
			"identity: agent-devbox, release: {version: bad},", 1), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")

			err := os.WriteFile(path, []byte(tc.config), 0o600)
			if err != nil {
				t.Fatal(err)
			}

			err = validate([]string{"--config", path})
			if (err == nil) != tc.valid {
				t.Fatalf("validate: %v", err)
			}
		})
	}
}
