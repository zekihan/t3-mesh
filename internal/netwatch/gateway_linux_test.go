package netwatch

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultGatewayMACFiles(t *testing.T) {
	dir := t.TempDir()

	rp, ap := filepath.Join(dir, "route"), filepath.Join(dir, "arp")

	err := os.WriteFile(rp, []byte(routeSample), 0o600)
	if err != nil {
		t.Fatal(err)
	}

	err = os.WriteFile(ap, []byte(arpSample), 0o600)
	if err != nil {
		t.Fatal(err)
	}

	oldR, oldA := procRoutePath, procARPPath

	procRoutePath, procARPPath = rp, ap
	defer func() { procRoutePath, procARPPath = oldR, oldA }()

	gw, mac, err := DefaultGatewayMAC()
	if err != nil || gw.String() != "192.168.0.2" || mac.String() != "aa:bb:cc:dd:ee:02" {
		t.Fatalf("gw=%v mac=%v err=%v", gw, mac, err)
	}
}
