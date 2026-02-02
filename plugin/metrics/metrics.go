// Package metrics provides Prometheus metrics server for the gateway-auth filter.
package metrics

import (
	"fmt"
	"net/http"
	"os"
	"strconv"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	initOnce sync.Once
	initErr  error
)

// Init initializes the metrics server if METRICS_PORT is set.
// Safe to call multiple times - only initializes once.
// If METRICS_PORT is empty or unset, metrics server is disabled (not an error).
func Init() error {
	initOnce.Do(func() {
		port := os.Getenv("METRICS_PORT")
		if port == "" {
			return // Disabled - not an error
		}

		// Validate port is numeric
		if _, err := strconv.Atoi(port); err != nil {
			initErr = fmt.Errorf("invalid METRICS_PORT '%s': must be a number", port)
			return
		}

		initErr = startServer(port)
	})
	return initErr
}

func startServer(port string) error {
	// Use custom registry to avoid conflicts with other .so plugins
	registry := prometheus.NewRegistry()

	// Register Go runtime metrics (go_goroutines, go_memstats_*, etc.)
	registry.MustRegister(collectors.NewGoCollector())

	// Register process metrics (process_cpu_seconds_total, process_resident_memory_bytes, etc.)
	registry.MustRegister(collectors.NewProcessCollector(
		collectors.ProcessCollectorOpts{},
	))

	// Register request metrics (envoy_oauth_requests_total, envoy_oauth_request_duration_seconds)
	RegisterRequestMetrics(registry)

	// Create HTTP handler for custom registry
	handler := promhttp.HandlerFor(registry, promhttp.HandlerOpts{
		EnableOpenMetrics: true,
	})

	mux := http.NewServeMux()
	mux.Handle("/metrics", handler)

	server := &http.Server{
		Addr:    ":" + port,
		Handler: mux,
	}

	// Start server in background goroutine (init() must not block)
	go func() {
		fmt.Fprintf(os.Stderr, "[metrics] starting server on :%s\n", port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Fprintf(os.Stderr, "[metrics] server error: %v\n", err)
		}
	}()

	return nil
}
