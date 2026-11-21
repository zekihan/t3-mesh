package kube

import "testing"

func TestInClusterIPv6(t *testing.T) {
	t.Setenv("KUBERNETES_SERVICE_HOST", "::1")
	t.Setenv("KUBERNETES_SERVICE_PORT", "443")

	base, err := apiBase("")
	if err != nil || base != "https://[::1]:443" {
		t.Fatalf("base = %q, err = %v", base, err)
	}
}
