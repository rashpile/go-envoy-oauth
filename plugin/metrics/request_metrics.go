// Package metrics provides Prometheus metrics for the gateway-auth filter.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

// Request metrics for tracking HTTP requests through the OAuth filter.
// Labels:
//   - status: "success", "unauthorized", "forbidden", or "error"
var (
	// RequestsTotal counts total requests processed by the OAuth filter.
	// Incremented once per request in EncodeHeaders.
	RequestsTotal *prometheus.CounterVec

	// RequestDuration tracks request processing duration in seconds.
	// Observed once per request in EncodeHeaders.
	RequestDuration *prometheus.HistogramVec
)

// RegisterRequestMetrics registers the request metrics with the provided registry.
// Must be called during server initialization.
func RegisterRequestMetrics(registry *prometheus.Registry) {
	RequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "envoy_oauth_requests_total",
			Help: "Total number of requests processed by the OAuth filter",
		},
		[]string{"status"},
	)

	RequestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "envoy_oauth_request_duration_seconds",
			Help:    "Request processing duration in seconds",
			Buckets: prometheus.DefBuckets, // 0.005 to 10 seconds
		},
		[]string{"status"},
	)

	registry.MustRegister(RequestsTotal)
	registry.MustRegister(RequestDuration)
}

// RecordRequest records a request completion with the given status code and duration.
// Safe to call even if metrics server is disabled (metrics will be nil).
func RecordRequest(statusCode int, durationSeconds float64) {
	// Handle case where metrics server is disabled
	if RequestsTotal == nil || RequestDuration == nil {
		return
	}

	status := GetStatusLabel(statusCode)
	RequestsTotal.WithLabelValues(status).Inc()
	RequestDuration.WithLabelValues(status).Observe(durationSeconds)
}

// GetStatusLabel maps HTTP status codes to metric label values.
// Returns one of: "success", "unauthorized", "forbidden", "error"
func GetStatusLabel(statusCode int) string {
	switch {
	case statusCode == 401:
		return "unauthorized"
	case statusCode == 403:
		return "forbidden"
	case statusCode >= 500 && statusCode <= 599:
		return "error"
	default:
		// 2xx, 3xx, and 4xx (except 401/403) are all "success"
		// This includes redirects (302) which are part of normal OAuth flow
		return "success"
	}
}
