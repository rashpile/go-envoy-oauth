// Package metrics provides Prometheus metrics for the gateway-auth filter.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

// OAuth flow metrics for tracking OAuth-specific operations.
// Labels:
//   - idp: Identity provider hostname (e.g., "keycloak.example.com")
//   - result: Operation result ("success", "failure", "valid", "invalid", "error")
var (
	// CallbackDuration tracks OAuth callback processing time in seconds.
	// Observed in HandleCallback for each OAuth callback request.
	CallbackDuration *prometheus.HistogramVec

	// TokenRefreshTotal counts token refresh attempts.
	// Incremented when refreshing expired access tokens.
	TokenRefreshTotal *prometheus.CounterVec

	// TokenValidationTotal counts bearer token validation attempts.
	// Incremented when validating tokens for API requests.
	TokenValidationTotal *prometheus.CounterVec

	// IDPUp tracks identity provider availability.
	// Set to 1 when IDP is reachable, 0 when unavailable.
	IDPUp *prometheus.GaugeVec

	// IDPState tracks per-provider health state (HLTH-02, D-08).
	// Label set: {idp, state} where state ∈ {"ready", "degraded", "down"}.
	// Exactly one series per provider is 1.0 at any time; the other two are 0.0.
	IDPState *prometheus.GaugeVec
)

// RegisterOAuthFlowMetrics registers the OAuth flow metrics with the provided registry.
// Must be called during server initialization.
func RegisterOAuthFlowMetrics(registry *prometheus.Registry) {
	// Custom buckets for OAuth callbacks: 50ms to 10s
	// OAuth callbacks typically take 100ms-5s due to IDP round-trips
	oauthBuckets := []float64{0.05, 0.1, 0.2, 0.3, 0.5, 0.75, 1, 1.5, 2, 3, 5, 10}

	CallbackDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "envoy_oauth_callback_duration_seconds",
			Help:    "OAuth callback processing duration in seconds",
			Buckets: oauthBuckets,
		},
		[]string{"idp"},
	)

	TokenRefreshTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "envoy_oauth_token_refresh_total",
			Help: "Total token refresh attempts",
		},
		[]string{"idp", "result"},
	)

	TokenValidationTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "envoy_oauth_token_validation_total",
			Help: "Total bearer token validation attempts",
		},
		[]string{"idp", "result"},
	)

	IDPUp = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "envoy_oauth_idp_up",
			Help: "Identity provider availability (1=up, 0=down)",
		},
		[]string{"idp"},
	)

	// envoy_oauth_idp_state: one series per (provider, state) tuple.
	IDPState = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "envoy_oauth_idp_state",
			Help: "Identity provider health state (1=active, 0=inactive). One of {ready, degraded, down} is active at any time.",
		},
		[]string{"idp", "state"},
	)

	registry.MustRegister(CallbackDuration)
	registry.MustRegister(TokenRefreshTotal)
	registry.MustRegister(TokenValidationTotal)
	registry.MustRegister(IDPUp)
	registry.MustRegister(IDPState)
}

// RecordCallbackDuration records the OAuth callback processing time for the given IDP.
// Safe to call even if metrics server is disabled (metrics will be nil).
func RecordCallbackDuration(idp string, durationSeconds float64) {
	if CallbackDuration == nil {
		return
	}
	CallbackDuration.WithLabelValues(idp).Observe(durationSeconds)
}

// RecordTokenRefresh records a token refresh attempt with the given IDP and result.
// Result should be "success" or "failure".
// Safe to call even if metrics server is disabled (metrics will be nil).
func RecordTokenRefresh(idp, result string) {
	if TokenRefreshTotal == nil {
		return
	}
	TokenRefreshTotal.WithLabelValues(idp, result).Inc()
}

// RecordTokenValidation records a token validation attempt with the given IDP and result.
// Result should be "valid", "invalid", or "error".
// Safe to call even if metrics server is disabled (metrics will be nil).
func RecordTokenValidation(idp, result string) {
	if TokenValidationTotal == nil {
		return
	}
	TokenValidationTotal.WithLabelValues(idp, result).Inc()
}

// UpdateIDPAvailability sets the IDP availability gauge for the given IDP.
// Sets to 1 if available, 0 if unavailable.
// Safe to call even if metrics server is disabled (metrics will be nil).
func UpdateIDPAvailability(idp string, available bool) {
	if IDPUp == nil {
		return
	}
	value := 0.0
	if available {
		value = 1.0
	}
	IDPUp.WithLabelValues(idp).Set(value)
}

// UpdateIDPState sets the active state series to 1.0 and the other two to 0.0
// for the given idp label. Also synchronizes envoy_oauth_idp_up for backward
// compatibility: ready OR degraded => up=1, down => up=0 (D-08).
//
// Safe to call even if metrics server is disabled (metrics will be nil).
//
// Accepts the stateLabel string directly (not a ProviderState) to keep the
// metrics package free of the oauth import — the caller in plugin/oauth passes
// state.String().
func UpdateIDPState(idp string, stateLabel string) {
	if IDPState == nil {
		return
	}
	states := []string{"ready", "degraded", "down"}
	for _, s := range states {
		v := 0.0
		if s == stateLabel {
			v = 1.0
		}
		IDPState.WithLabelValues(idp, s).Set(v)
	}
	// Backward-compat: envoy_oauth_idp_up is 1 when ready OR degraded, 0 when down (D-08).
	available := stateLabel != "down"
	UpdateIDPAvailability(idp, available)
}
