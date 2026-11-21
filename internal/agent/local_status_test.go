package agent

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/zekihan/t3-mesh/internal/proto"
)

func TestLocalStatusWithoutHub(t *testing.T) {
	rig := newHarness(t, func(opts *hopts) {
		opts.noHub = true
		opts.noStart = true
	})

	// Use a short path even when macOS puts the test temp directory under /var/folders.
	dir, err := os.MkdirTemp("/tmp", "t3mesh-") //nolint:usetesting // short Unix socket path
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	path := filepath.Join(dir, "agent.sock")

	rig.agent.statusSocket = path
	rig.start()

	var status *LocalStatus

	waitFor(t, "local status and service probe", func() bool {
		snapshot, err := ReadLocalStatus(t.Context(), path)
		if err != nil || len(snapshot.Report.Services) == 0 {
			return false
		}

		status = snapshot

		return true
	})

	if status.TunnelConnected || status.ConnectedSince != nil || status.DirectActive ||
		status.DirectReason == "" || status.Report.Version != "dev" ||
		status.Report.CertNotAfter == "" || status.Report.Services[0].State != proto.ServiceReachable {
		t.Fatalf("offline status: %+v", status)
	}

	if len(status.Links) != 1 || !status.Links[0].Bound || status.Links[0].Port != rig.linkPort {
		t.Fatalf("links: %+v", status.Links)
	}

	checkSocketAccess(t, path)
	checkReadOnlyProtocol(t, path)
}

func checkSocketAccess(t *testing.T, path string) {
	t.Helper()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	if info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0o660 {
		t.Errorf("socket mode = %v", info.Mode())
	}

	var stat unix.Stat_t

	err = unix.Lstat(path, &stat)
	if err != nil {
		t.Fatal(err)
	}

	if int(stat.Gid) != os.Getegid() {
		t.Errorf("socket gid = %d, want %d", stat.Gid, os.Getegid())
	}
}

func checkReadOnlyProtocol(t *testing.T, path string) {
	t.Helper()

	dialer := net.Dialer{}

	conn, err := dialer.DialContext(t.Context(), "unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	err = proto.WriteLine(conn, localRequest{Op: "restart"})
	if err != nil {
		t.Fatal(err)
	}

	var reply localReply

	decoder := json.NewDecoder(conn)

	err = decoder.Decode(&reply)
	if err != nil || reply.Error == "" || reply.Status != nil {
		t.Fatalf("invalid operation reply %+v, err %v", reply, err)
	}

	err = decoder.Decode(&reply)
	if err == nil {
		t.Fatal("received a second reply on one connection")
	}
}
