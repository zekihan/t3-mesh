package agent

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/zekihan/t3-mesh/internal/agent/agentconfig"
)

func TestProbeService(t *testing.T) {
	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", "http://[invalid")
		w.WriteHeader(http.StatusFound)
	}))
	defer web.Close()

	err := ProbeService(t.Context(), "t3", strings.TrimPrefix(web.URL, "http://"))
	if err != nil {
		t.Fatalf("redirect response: %v", err)
	}

	var listen net.ListenConfig

	raw, err := listen.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()

	target := raw.Addr().String()

	err = ProbeService(t.Context(), "other", target)
	if err != nil {
		t.Fatalf("TCP-only target: %v", err)
	}

	err = ProbeService(t.Context(), "t3", target)
	if err == nil ||
		!strings.Contains(err.Error(), "TCP accepts but HTTP failed") {
		t.Fatalf("hung HTTP: %v", err)
	}

	_ = raw.Close()

	err = ProbeService(t.Context(), "t3", target)
	if err == nil ||
		!strings.Contains(err.Error(), "service TCP probe") {
		t.Fatalf("closed listener: %v", err)
	}
}

func TestServiceHealthNudgesOnlyOnStateChange(t *testing.T) {
	web := httptest.NewServer(http.NotFoundHandler())
	defer web.Close()

	now := time.Now()

	agt, err := New(Options{
		Config: &agentconfig.Config{Serve: map[string]string{
			"t3": strings.TrimPrefix(web.URL, "http://"),
		}},
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}

	agt.checkServices(t.Context(), []string{"t3"})

	select {
	case <-agt.statusNudge:
	default:
		t.Fatal("initial result did not nudge status")
	}

	first := now
	now = now.Add(time.Minute)

	agt.checkServices(t.Context(), []string{"t3"})

	select {
	case <-agt.statusNudge:
		t.Fatal("unchanged state nudged status")
	default:
	}

	if got := agt.services[0].Since; got != first.UTC().Format(time.RFC3339) {
		t.Errorf("unchanged state since = %s, want the first check", got)
	}

	web.Close()
	agt.checkServices(t.Context(), []string{"t3"})

	select {
	case <-agt.statusNudge:
	default:
		t.Fatal("unreachable service did not nudge status")
	}

	if got := agt.services[0].Since; got != now.UTC().Format(time.RFC3339) {
		t.Errorf("changed state since = %s, want the latest check", got)
	}
}
