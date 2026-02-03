// Package metrics provides Prometheus metrics for the gateway-auth filter.
package metrics

import (
	"net/url"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
)

// Error classification constants for login failures
const (
	ReasonInvalidToken = "invalid_token"
	ReasonExpired      = "expired"
	ReasonRevoked      = "revoked"
	ReasonInvalidState = "invalid_state"
	ReasonMissingCode  = "missing_code"
	ReasonTimeout      = "timeout"
	ReasonIDPError     = "idp_error"
	ReasonUnknown      = "unknown"
)

// Authentication metrics for tracking OAuth login/logout events.
// Labels:
//   - idp: Identity provider hostname (e.g., "keycloak.example.com")
//   - status: "success" or "failure"
//   - reason: Failure reason (login/logout) or session end reason (session_ended)
var (
	// LoginTotal counts total login attempts through the OAuth filter.
	// Incremented in HandleCallback for each login attempt.
	LoginTotal *prometheus.CounterVec

	// LogoutTotal counts total logout attempts through the OAuth filter.
	// Incremented in HandleLogout for each logout attempt.
	LogoutTotal *prometheus.CounterVec

	// SessionCreatedTotal counts total sessions created.
	// Incremented on successful login in HandleCallback.
	SessionCreatedTotal *prometheus.CounterVec

	// SessionEndedTotal counts total sessions ended.
	// Incremented on logout or session expiry.
	SessionEndedTotal *prometheus.CounterVec

	// ClusterAuthTotal counts total authentication attempts per cluster.
	// Labels:
	//   - cluster: Configured cluster name (or "unknown" for unbounded cardinality safety)
	//   - realm: Keycloak realm extracted from issuer URL (or "unknown")
	//   - result: "success" or "failure"
	ClusterAuthTotal *prometheus.CounterVec
)

// RegisterAuthMetrics registers the authentication metrics with the provided registry.
// Must be called during server initialization.
func RegisterAuthMetrics(registry *prometheus.Registry) {
	LoginTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "envoy_oauth_login_total",
			Help: "Total number of login attempts through the OAuth filter",
		},
		[]string{"idp", "status", "reason"},
	)

	LogoutTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "envoy_oauth_logout_total",
			Help: "Total number of logout attempts through the OAuth filter",
		},
		[]string{"idp", "status", "reason"},
	)

	SessionCreatedTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "envoy_oauth_session_created_total",
			Help: "Total number of sessions created",
		},
		[]string{"idp"},
	)

	SessionEndedTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "envoy_oauth_session_ended_total",
			Help: "Total number of sessions ended",
		},
		[]string{"idp", "reason"},
	)

	ClusterAuthTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "envoy_oauth_cluster_auth_total",
			Help: "Total authentication attempts per cluster (all auth methods)",
		},
		[]string{"cluster", "realm", "result"},
	)

	registry.MustRegister(LoginTotal)
	registry.MustRegister(LogoutTotal)
	registry.MustRegister(SessionCreatedTotal)
	registry.MustRegister(SessionEndedTotal)
	registry.MustRegister(ClusterAuthTotal)
}

// RecordLogin records a login attempt with the given IDP, status, and reason.
// Safe to call even if metrics server is disabled (metrics will be nil).
func RecordLogin(idp, status, reason string) {
	if LoginTotal == nil {
		return
	}
	LoginTotal.WithLabelValues(idp, status, reason).Inc()
}

// RecordLogout records a logout attempt with the given IDP, status, and reason.
// Safe to call even if metrics server is disabled (metrics will be nil).
func RecordLogout(idp, status, reason string) {
	if LogoutTotal == nil {
		return
	}
	LogoutTotal.WithLabelValues(idp, status, reason).Inc()
}

// RecordSessionCreated records a session creation with the given IDP.
// Safe to call even if metrics server is disabled (metrics will be nil).
func RecordSessionCreated(idp string) {
	if SessionCreatedTotal == nil {
		return
	}
	SessionCreatedTotal.WithLabelValues(idp).Inc()
}

// RecordSessionEnded records a session ending with the given IDP and reason.
// Safe to call even if metrics server is disabled (metrics will be nil).
func RecordSessionEnded(idp, reason string) {
	if SessionEndedTotal == nil {
		return
	}
	SessionEndedTotal.WithLabelValues(idp, reason).Inc()
}

// GetIDPName extracts the hostname from an issuer URL.
// Returns "unknown" if the URL cannot be parsed.
// Example: "https://keycloak.example.com/realms/foo" -> "keycloak.example.com"
func GetIDPName(issuerURL string) string {
	u, err := url.Parse(issuerURL)
	if err != nil || u.Host == "" {
		return "unknown"
	}
	return u.Host
}

// ClassifyLoginError maps error messages to reason labels for login failures.
// Uses pattern matching on error strings to categorize failures.
func ClassifyLoginError(err error) string {
	if err == nil {
		return ReasonUnknown
	}

	errMsg := strings.ToLower(err.Error())

	// Check for specific error patterns
	switch {
	case strings.Contains(errMsg, "state"):
		return ReasonInvalidState
	case strings.Contains(errMsg, "code not found"):
		return ReasonMissingCode
	case strings.Contains(errMsg, "expired"):
		return ReasonExpired
	case strings.Contains(errMsg, "revoked"):
		return ReasonRevoked
	case strings.Contains(errMsg, "timeout") || strings.Contains(errMsg, "context deadline"):
		return ReasonTimeout
	case strings.Contains(errMsg, "failed to") || strings.Contains(errMsg, "oidc") || strings.Contains(errMsg, "provider"):
		return ReasonIDPError
	default:
		return ReasonUnknown
	}
}

// GetClusterLabel returns a bounded cluster label for metrics.
// Returns cluster name if it's in the knownClusters set, otherwise "unknown".
// This prevents cardinality explosion from unconfigured cluster names.
func GetClusterLabel(cluster string, knownClusters map[string]bool) string {
	if cluster == "" {
		return "unknown"
	}
	if knownClusters[cluster] {
		return cluster
	}
	return "unknown"
}

// GetRealm extracts the Keycloak realm from the issuer URL path.
// Example: "https://keycloak.example.com/auth/realms/test" -> "test"
// Returns "unknown" if the realm cannot be extracted.
func GetRealm(issuerURL string) string {
	u, err := url.Parse(issuerURL)
	if err != nil || u.Path == "" {
		return "unknown"
	}
	segments := strings.Split(strings.Trim(u.Path, "/"), "/")
	for i, seg := range segments {
		if seg == "realms" && i+1 < len(segments) && segments[i+1] != "" {
			return segments[i+1]
		}
	}
	return "unknown"
}

// RecordClusterAuth records a cluster authentication attempt with the given labels.
// Safe to call even if metrics server is disabled (metrics will be nil).
func RecordClusterAuth(cluster, realm, result string) {
	if ClusterAuthTotal == nil {
		return
	}
	ClusterAuthTotal.WithLabelValues(cluster, realm, result).Inc()
}
