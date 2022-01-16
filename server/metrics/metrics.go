package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"net/http"
)

type MetricsServer struct {
	*http.Server
}

// NewMetricsServer returns a new prometheus server which collects api server metrics
func NewMetricsServer(address string) *MetricsServer {
	mux := http.NewServeMux()
	registry := prometheus.NewRegistry()
	mux.Handle("/metrics", promhttp.HandlerFor(prometheus.Gatherers{
		registry,
		prometheus.DefaultGatherer,
	}, promhttp.HandlerOpts{}))

	return &MetricsServer{
		Server: &http.Server{
			Addr:    address,
			Handler: mux,
		},
	}
}
