package hub

import (
	"time"

	"github.com/zekihan/t3-mesh/internal/proto"
)

type serviceHealth struct {
	Since *string `json:"since"`
	State string  `json:"state"`
}

func serviceHealthOf(configured []string, live *session) map[string]serviceHealth {
	out := make(map[string]serviceHealth, len(configured))
	for _, name := range configured {
		out[name] = serviceHealth{State: "unknown"}
	}

	if live == nil {
		return out
	}

	for _, health := range live.services {
		if _, configured := out[health.Name]; !configured {
			continue
		}

		if health.State != proto.ServiceReachable && health.State != proto.ServiceUnreachable {
			continue
		}

		since, err := time.Parse(time.RFC3339, health.Since)
		if err == nil {
			out[health.Name] = serviceHealth{State: health.State, Since: formatTime(&since)}
		}
	}

	return out
}
