package integration

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/zekihan/t3-mesh/internal/netwatch"
)

var errLookupFailed = errors.New("lookup failed")

// netNode starts mesh node b with a faked network watcher, dialing the hub as
// "localhost" so the agent runs its DNS re-resolve check against the current
// peer 127.0.0.1.
func netNode(t *testing.T, dnsRecheck time.Duration) (*mesh, *node, phone) {
	t.Helper()

	msh := newMesh(t, &meshOpts{})
	nd := msh.newNode("b", &nodeOpts{hubName: "localhost", fakeNet: true, dnsRecheck: dnsRecheck})

	ph := msh.newPhone()

	return msh, nd, ph
}

func (msh *mesh) sessions(machine string) int { return msh.status().Machines[machine].Sessions }

// assertViewerOK checks a fresh request reaches the machine.
func assertViewerOK(t *testing.T, msh *mesh, ph *phone) {
	t.Helper()

	code, body := msh.viewerGet(ph, "b", "/")
	if code != http.StatusOK || body != "t3@b mtls=0" {
		t.Fatalf("viewer request: %d %q", code, body)
	}
}

// assertKept checks the tunnel was not replaced: no new connection, one hub
// session, the open stream alive, and new requests served.
func assertKept(t *testing.T, msh *mesh, ph *phone, live *held, conns int) {
	t.Helper()

	if got := msh.tl.count(); got != conns {
		t.Fatalf("hub accepted %d connections, want %d (session replaced)", got, conns)
	}

	if got := msh.sessions("b"); got != 1 {
		t.Fatalf("hub sessions for b = %d, want 1", got)
	}

	assertOpen(t, live, "viewer stream")
	assertViewerOK(t, msh, ph)
}

func TestNetEventKeepsHealthySession(t *testing.T) {
	t.Parallel()

	for _, kind := range []netwatch.EventKind{netwatch.EventNetwork, netwatch.EventWake} {
		t.Run(kind.String(), func(t *testing.T) {
			t.Parallel()

			msh, nd, ph := netNode(t, 0)
			live := msh.openViewerHold(&ph, "b")
			conns := msh.tl.count()

			nd.netEvent(kind)

			// The lookup runs on every check and still names the peer.
			if nd.lookupCalls.Load() == 0 {
				t.Fatal("event did not run the path check")
			}

			assertKept(t, msh, &ph, live, conns)
		})
	}
}

func TestFailedOrEmptyLookupKeepsSession(t *testing.T) {
	t.Parallel()

	answers := map[string]lookupFn{
		"error": func(context.Context, string) ([]string, error) { return nil, errLookupFailed },
		"empty": func(context.Context, string) ([]string, error) { return nil, nil },
		"unparsable": func(context.Context, string) ([]string, error) {
			return []string{"not-an-address"}, nil
		},
	}

	for name, fn := range answers {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			msh, nd, ph := netNode(t, 0)
			live := msh.openViewerHold(&ph, "b")
			conns := msh.tl.count()

			nd.setLookup(fn)
			nd.netEvent(netwatch.EventNetwork)

			if nd.lookupCalls.Load() == 0 {
				t.Fatal("lookup was not consulted")
			}

			assertKept(t, msh, &ph, live, conns)
		})
	}
}

// moved makes the lookup answer with an address that is not the hub's peer.
func moved(context.Context, string) ([]string, error) { return []string{"127.0.0.2"}, nil }

// peerLookup answers with the hub's real address, which is the current peer.
func peerLookup(context.Context, string) ([]string, error) { return []string{"127.0.0.1"}, nil }

func TestLookupWithoutPeerReplacesSession(t *testing.T) {
	t.Parallel()

	for _, kind := range []netwatch.EventKind{netwatch.EventNetwork, netwatch.EventWake} {
		t.Run(kind.String(), func(t *testing.T) {
			t.Parallel()

			msh, nd, ph := netNode(t, 0)
			old := msh.openViewerHold(&ph, "b")
			conns := msh.tl.count()

			nd.setLookup(moved)
			nd.sendNetEvents(kind, 1)

			eventually(t, 10*time.Second, "agent opens a new session", func() bool {
				return msh.tl.count() == conns+1 && msh.sessions("b") == 2
			})

			// Hold an answer that matches the new peer so no further replacement runs.
			nd.setLookup(peerLookup)

			// The old stream survives while the old session lingers.
			assertOpen(t, old, "stream on the replaced session")

			// New streams use the new session: they outlive the old session's retirement.
			fresh := msh.openViewerHold(&ph, "b")

			old.close()
			eventually(t, 10*time.Second, "old session retired", func() bool {
				return msh.sessions("b") == 1
			})

			assertOpen(t, fresh, "stream on the new session")
			assertViewerOK(t, msh, &ph)

			if got := msh.tl.count(); got != conns+1 {
				t.Fatalf("hub accepted %d connections, want %d", got, conns+1)
			}
		})
	}
}

func TestLocalAddressGoneReplacesSession(t *testing.T) {
	t.Parallel()

	msh, nd, ph := netNode(t, 0)
	old := msh.openViewerHold(&ph, "b")
	conns := msh.tl.count()

	nd.localGone.Store(true)
	nd.sendNetEvents(netwatch.EventNetwork, 1)

	eventually(t, 10*time.Second, "agent opens a new session", func() bool {
		return msh.tl.count() == conns+1 && msh.sessions("b") == 2
	})

	nd.localGone.Store(false)

	assertOpen(t, old, "stream on the replaced session")

	fresh := msh.openViewerHold(&ph, "b")

	old.close()
	eventually(t, 10*time.Second, "old session retired", func() bool {
		return msh.sessions("b") == 1
	})

	assertOpen(t, fresh, "stream on the new session")
	assertViewerOK(t, msh, &ph)
}

func TestDNSRecheckReplacesSessionWithoutEvent(t *testing.T) {
	t.Parallel()

	msh, nd, ph := netNode(t, 100*time.Millisecond)
	conns := msh.tl.count()

	// Healthy recheck ticks keep the session.
	eventually(t, 5*time.Second, "recheck consults the lookup", func() bool {
		return nd.lookupCalls.Load() >= 2
	})

	if got := msh.tl.count(); got != conns {
		t.Fatalf("recheck replaced a healthy session: %d connections, want %d", got, conns)
	}

	nd.setLookup(moved)

	eventually(t, 10*time.Second, "recheck opens a new session", func() bool {
		return msh.tl.count() > conns
	})

	nd.setLookup(peerLookup)

	eventually(t, 10*time.Second, "one session left", func() bool { return msh.sessions("b") == 1 })
	assertViewerOK(t, msh, &ph)
}
