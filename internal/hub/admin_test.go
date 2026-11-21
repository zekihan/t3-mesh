package hub

import (
	"errors"
	"testing"
)

func TestAdminStatusAndDisconnect(t *testing.T) {
	harness := newEnv(t)
	devbox := harness.connect("agent-devbox", "devbox-body")

	rows := harness.srv.AdminStatus()
	if len(rows) != 2 || rows[0].Name != "devbox" || !rows[0].Online || rows[0].Path == "" ||
		rows[0].CertNotAfter == nil || rows[0].LastSeen == nil || rows[0].Services["t3"] == "" ||
		rows[1].Online {
		t.Fatalf("admin status = %+v", rows)
	}

	err := harness.srv.Disconnect("devbox")
	if err != nil {
		t.Fatal(err)
	}

	devbox.waitClosed()

	err = harness.srv.Disconnect("devbox")
	if !errors.Is(err, errNoSession) {
		t.Fatalf("offline disconnect: %v", err)
	}

	err = harness.srv.Disconnect("unconfigured")
	if !errors.Is(err, errUnknownMachine) {
		t.Fatalf("unknown machine disconnect: %v", err)
	}
}
