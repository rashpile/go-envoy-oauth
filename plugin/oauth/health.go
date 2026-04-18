// Package oauth — Phase 5 health types and constants.
//
// State transitions are driven by the background refresher only (D-06).
// Request-path code MUST read HealthState() to gate 503s (D-03) but MUST NOT
// call setHealthState.
package oauth

import (
	"time"

	"github.com/rashpile/go-envoy-oauth/plugin/metrics"
	"golang.org/x/oauth2"
)

// ProviderState represents the operational health state of a provider (D-05).
type ProviderState int32

const (
	// StateReady — initial discovery succeeded and latest JWKS refresh succeeded.
	StateReady ProviderState = 0
	// StateDegraded — a subsequent refresh is failing, last-known-good JWKS still usable.
	StateDegraded ProviderState = 1
	// StateDown — initial discovery never succeeded OR stale-key thresholds exceeded;
	// requests routed to this provider MUST receive 503 (D-03).
	StateDown ProviderState = 2
)

// String returns the lowercase label used in Prometheus series for this state.
// Must match the values enumerated in metrics.UpdateIDPState.
func (s ProviderState) String() string {
	switch s {
	case StateReady:
		return "ready"
	case StateDegraded:
		return "degraded"
	case StateDown:
		return "down"
	default:
		return "unknown"
	}
}

// Thresholds for state transitions (D-15). Exposed as constants so operators
// can locate and tune them without hunting through logic.
const (
	// MaxConsecFailures — refresh failures before degraded → down.
	MaxConsecFailures = 5
	// MaxStaleAge — maximum time since last successful refresh before degraded → down.
	MaxStaleAge = 6 * time.Hour
	// SteadyStateInterval — cadence between successful refreshes in ready state (D-14).
	SteadyStateInterval = 1 * time.Hour
	// InitialBackoff — first retry interval after a refresh failure (D-14).
	InitialBackoff = 5 * time.Second
	// MaxBackoff — upper bound on exponential backoff (D-14).
	MaxBackoff = 5 * time.Minute
	// JitterFactorLow / JitterFactorRange — ±20% jitter factor ∈ [0.8, 1.2] (D-14).
	JitterFactorLow   = 0.8
	JitterFactorRange = 0.4
)

// HealthState returns the current health state of this handler.
// Safe to call from any goroutine (atomic read).
func (h *OAuthHandlerImpl) HealthState() ProviderState {
	return ProviderState(h.healthState.Load())
}

// setHealthState atomically updates the health state cell and syncs Prometheus
// metrics. Intended for use by the background refresher goroutine only (D-06).
// Call sites that mutate state from the request path are a bug.
func (h *OAuthHandlerImpl) setHealthState(s ProviderState) {
	h.healthState.Store(int32(s))
	metrics.UpdateIDPState(h.providerName, s.String())
}

// getProvider returns a consistent snapshot of the current OIDC provider under
// a read lock. Use this on the request path to avoid races with refreshOnce.
func (h *OAuthHandlerImpl) getProvider() *OIDCProvider {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.provider
}

// getOAuth2Config returns a value snapshot of the current oauth2.Config under
// a read lock. Callers receive their own copy; mutations by refreshOnce cannot
// affect the returned value after the lock is released. Returns nil if
// oauth2Config was never set (bare struct construction in tests).
func (h *OAuthHandlerImpl) getOAuth2Config() *oauth2.Config {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if h.oauth2Config == nil {
		return nil
	}
	cfg := *h.oauth2Config
	return &cfg
}

// getTokenValidator returns the current TokenValidator under a read lock.
// May return nil if the validator has not yet been initialised or failed on
// every refresh attempt.
func (h *OAuthHandlerImpl) getTokenValidator() *TokenValidator {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.tokenValidator
}
