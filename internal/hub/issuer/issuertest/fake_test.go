package issuertest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/zekihan/t3-mesh/internal/hub/issuer"
)

var _ issuer.Issuer = (*Fake)(nil)

var errBoom = errors.New("boom")

func TestFake(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}

	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	sum := sha256.Sum256(der)
	fake := &Fake{Sign: func([]byte) ([]byte, []byte, error) {
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), []byte("chain"), nil
	}}

	ctx := t.Context()
	if fp, _ := fake.Newest(ctx, "a"); fp != "" {
		t.Errorf("fp %q", fp)
	}

	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			_, _, issueErr := fake.Issue(ctx, "a", nil)
			if issueErr != nil {
				t.Error(issueErr)
			}
		})
	}

	wg.Wait()

	if fp, _ := fake.Newest(ctx, "a"); fp != hex.EncodeToString(sum[:]) {
		t.Errorf("fp %q", fp)
	}

	fake.SetNewest("a", "zz")

	if fp, _ := fake.Newest(ctx, "a"); fp != "zz" {
		t.Errorf("fp %q", fp)
	}

	fake.Sign = func([]byte) ([]byte, []byte, error) { return nil, nil, errBoom }

	_, _, err = fake.Issue(ctx, "a", nil)
	if err == nil {
		t.Error("want error")
	}
}
