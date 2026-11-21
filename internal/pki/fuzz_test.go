package pki_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"runtime"
	"testing"

	"github.com/zekihan/t3-mesh/internal/pki"
	"github.com/zekihan/t3-mesh/internal/policy"
)

//nolint:gocyclo // Seed setup and independent validation invariants.
func FuzzValidateCSR(f *testing.F) {
	key, err := pki.GenerateKey()
	if err != nil {
		f.Fatal(err)
	}

	for _, id := range []string{"agent-devbox", "device-z-phone-mesh"} {
		csr, err := pki.CreateCSR(key, id)
		if err != nil {
			f.Fatal(err)
		}

		f.Add(csr)
	}

	f.Add([]byte("garbage"))
	f.Fuzz(func(t *testing.T, data []byte) {
		var before runtime.MemStats
		runtime.ReadMemStats(&before)

		defer func() {
			var after runtime.MemStats
			runtime.ReadMemStats(&after)

			if after.TotalAlloc-before.TotalAlloc > 64<<20 {
				t.Fatalf("parser allocated more than 64 MiB")
			}
		}()

		if len(data) > 4096 {
			t.Skip()
		}

		csr, id, err := pki.ValidateCSR(data)
		if err != nil {
			return
		}

		if csr.CheckSignature() != nil {
			t.Fatal("accepted invalid signature")
		}

		key, ok := csr.PublicKey.(*ecdsa.PublicKey)
		if !ok || key.Curve != elliptic.P256() || len(csr.URIs) != 1 {
			t.Fatal("accepted invalid key or URI")
		}

		got, err := policy.IdentityFromURI(csr.URIs[0].String())
		if err != nil || got != id {
			t.Fatal("inconsistent identity")
		}

		block := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr.Raw})

		again, name, err := pki.ValidateCSR(block)
		if err != nil || name != id || !x509Equal(csr, again) {
			t.Fatal("CSR round trip failed")
		}
	})
}
func x509Equal(a, b *x509.CertificateRequest) bool { return bytes.Equal(a.Raw, b.Raw) }
