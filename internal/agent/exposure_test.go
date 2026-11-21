package agent

import (
	"net"
	"net/netip"
	"strings"
	"testing"

	"github.com/zekihan/t3-mesh/internal/agent/agentconfig"
	"github.com/zekihan/t3-mesh/internal/netwatch"
)

func TestExposureWarningClears(t *testing.T) {
	addrs, err := netwatch.LocalAddrs()
	if err != nil {
		t.Fatal(err)
	}

	for _, addr := range addrs {
		if !addr.IsGlobalUnicast() {
			continue
		}

		var listen net.ListenConfig

		ln, err := listen.Listen(t.Context(), "tcp", net.JoinHostPort(addr.String(), "0"))
		if err != nil {
			continue
		}

		testExposureListener(t, ln, addr)

		return
	}

	t.Skip("no bindable non-loopback, non-link-local address")
}

func testExposureListener(t *testing.T, ln net.Listener, addr netip.Addr) {
	t.Helper()

	defer ln.Close()

	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	agt, err := New(Options{
		Config: &agentconfig.Config{Serve: map[string]string{
			"t3":  net.JoinHostPort("localhost", port),
			"lan": ln.Addr().String(),
		}},
		LocalAddrs: func() ([]netip.Addr, error) { return []netip.Addr{addr}, nil },
	})
	if err != nil {
		t.Fatal(err)
	}

	endpoint, err := netip.ParseAddrPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	owned := []netip.AddrPort{endpoint}
	if warnings := exposureWarnings(
		t.Context(),
		agt.cfg.Serve,
		[]netip.Addr{addr},
		owned,
	); len(
		warnings,
	) != 0 {
		t.Fatalf("own listener reported as exposed: %v", warnings)
	}

	agt.checkExposure(t.Context())

	warnings := agt.exposureWarnings
	if len(warnings) != 1 || !strings.Contains(warnings[0], "t3 port "+port) ||
		!strings.Contains(warnings[0], addr.String()) {
		t.Fatalf("exposure warnings: %v", warnings)
	}

	_ = ln.Close()

	agt.checkExposure(t.Context())

	if len(agt.exposureWarnings) != 0 {
		t.Fatalf("warnings after close: %v", agt.exposureWarnings)
	}
}
