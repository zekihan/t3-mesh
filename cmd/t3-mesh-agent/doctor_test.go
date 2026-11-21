package main

import (
	"net"
	"testing"

	"github.com/zekihan/t3-mesh/internal/agent"
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
