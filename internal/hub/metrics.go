package hub

import (
	"github.com/zekihan/go-commons/metrics"
)

// Aggregate gauges served on /metrics. Labels stay empty: per-machine values
// would turn machine identities into label cardinality, so only totals are
// exported.
const (
	metricConnectedMachines = "t3mesh_connected_machines"
	metricOpenStreams       = "t3mesh_open_streams"
)

// MetricsRegistry is the hub's Prometheus registry: request counts and
// durations, the aggregate mesh gauges, and Go runtime and process metrics.
func (server *Server) MetricsRegistry() *metrics.Registry {
	return server.metrics
}

// observeMesh publishes aggregate mesh totals. Only totals are exported:
// per-machine values would turn machine identities into label cardinality.
func (server *Server) observeMesh(connected int, openStreams int64) {
	server.metrics.Gauge(metricConnectedMachines, nil).Set(float64(connected))
	server.metrics.Gauge(metricOpenStreams, nil).Set(float64(openStreams))
}
