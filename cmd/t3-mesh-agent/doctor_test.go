package main

import (
	"net"
	"net/netip"
	"testing"

	"github.com/zekihan/t3-mesh/internal/agent"
	"github.com/zekihan/t3-mesh/internal/agent/agentconfig"
)

func TestDoctorLinkPortOwnership(t *testing.T) {
	var listen net.ListenConfig

	ln, err := listen.Listen(t.Context(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	defer ln.Close()

	const name = "t3.peer"

	address, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatal("expected a TCP listener")
	}

	target := address.String()

	if got := checkLinkPort(name, target, nil); got.State != checkFail {
		t.Fatalf("foreign listener: %+v", got)
	}

	status := &agent.LocalStatus{
		Links: []agent.LinkStatus{{Name: name, Address: target, Port: address.Port, Bound: true}},
	}
	if got := checkLinkPort(name, target, status); got.State != checkPass {
		t.Fatalf("agent's listener: %+v", got)
	}

	_ = ln.Close()

	if got := checkLinkPort(name, target, nil); got.State != checkPass {
		t.Fatalf("unused port: %+v", got)
	}
}

func TestListenerPortOwnershipIsPerAddress(t *testing.T) {
	var listen net.ListenConfig

	ln, err := listen.Listen(t.Context(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	endpoint, err := netip.ParseAddrPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	port := int(endpoint.Port())
	ips := []net.IP{net.ParseIP("127.0.0.1")}

	other := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.2"), endpoint.Port())
	if got := listenerPortResult(
		"direct",
		port,
		[]netip.AddrPort{other},
		ips,
	); got.State != checkFail {
		t.Fatalf("ownership on another address: %+v", got)
	}

	if got := listenerPortResult(
		"direct",
		port,
		[]netip.AddrPort{endpoint},
		ips,
	); got.State != checkPass {
		t.Fatalf("ownership on exact address: %+v", got)
	}
}

func TestDoctorDirectIgnoresLoopbackListener(t *testing.T) {
	var listen net.ListenConfig

	ln, err := listen.Listen(t.Context(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	cfg := &agentconfig.Config{}
	cfg.Direct.Enabled = true

	endpoint, err := netip.ParseAddrPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	cfg.Direct.Port = int(endpoint.Port())
	for _, got := range checkPorts(cfg, nil) {
		if got.State != checkPass {
			t.Fatalf("loopback listener caused failure: %+v", got)
		}
	}
}
