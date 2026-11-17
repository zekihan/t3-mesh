package issuertest

import (
	"context"
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
	f := &Fake{Sign: func([]byte) ([]byte, []byte, error) {
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), []byte("chain"), nil
	}}
	ctx := context.Background()
	if fp, _ := f.Newest(ctx, "a"); fp != "" {
		t.Errorf("fp %q", fp)
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, _, err := f.Issue(ctx, "a", nil); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if fp, _ := f.Newest(ctx, "a"); fp != hex.EncodeToString(sum[:]) {
		t.Errorf("fp %q", fp)
	}
	f.SetNewest("a", "zz")
	if fp, _ := f.Newest(ctx, "a"); fp != "zz" {
		t.Errorf("fp %q", fp)
	}
	f.Sign = func([]byte) ([]byte, []byte, error) { return nil, nil, errors.New("boom") }
	if _, _, err := f.Issue(ctx, "a", nil); err == nil {
		t.Error("want error")
	}
}
