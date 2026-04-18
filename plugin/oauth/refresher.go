// Package oauth — Phase 5 background JWKS refresher (HLTH-04).
//
// StartRefresher spawns a goroutine that keeps the handler's OIDC provider
// and JWKS current. It drives health-state transitions (D-03 state machine):
//
//	ready     → one refresh failure        → degraded
//	degraded  → MaxConsecFailures reached  → down
//	degraded  → successful refresh         → ready
//
// NOTE: StateDown is terminal for this refresher. A handler whose initial OIDC
// discovery failed is registered as a DownHandler; StartRefresher is never
// called for it. Instead, ProviderRegistry.startDownHandlerRecovery retries
// discovery in the background and swaps in a live handler on success.
//
// State writes use setHealthState(); request-path code MUST only read
// HealthState() (D-06).
package oauth

import (
	"context"
	"math/rand"
	"time"

	"go.uber.org/zap"
)

// StartRefresher launches the background JWKS refresh goroutine for this
// handler. It runs until shutdownCtx is cancelled (supplied by
// ProviderRegistry.ShutdownContext()).
//
// Called by ProviderRegistry.InitAll after a handler is successfully created.
// MUST NOT be called for *DownHandler instances (they have no OIDC state to
// refresh; re-discovery for down providers is handled separately by the
// registry).
func (h *OAuthHandlerImpl) StartRefresher(shutdownCtx context.Context) {
	go h.runRefreshLoop(shutdownCtx)
}

// runRefreshLoop is the main refresh loop. It alternates between steady-state
// sleeps (SteadyStateInterval) and failure-backoff sleeps (InitialBackoff with
// exponential growth up to MaxBackoff), updating healthState on each outcome.
func (h *OAuthHandlerImpl) runRefreshLoop(ctx context.Context) {
	backoff := InitialBackoff

	for {
		// Wait before the next refresh attempt.
		// On ready/degraded: sleep SteadyStateInterval before next attempt.
		// On failure: sleep the current backoff.
		sleep := SteadyStateInterval
		if h.HealthState() != StateReady {
			sleep = backoff
		}

		select {
		case <-ctx.Done():
			h.logger.Info("JWKS refresher shutting down",
				zap.String("provider", h.providerName))
			return
		case <-time.After(sleep):
		}

		if err := h.refreshOnce(); err != nil {
			h.jwksFailures++
			if h.jwksStaleAt.IsZero() {
				h.jwksStaleAt = time.Now()
			}

			// Determine new state.
			stale := time.Since(h.jwksStaleAt)
			if h.jwksFailures >= MaxConsecFailures || stale >= MaxStaleAge {
				h.setHealthState(StateDown)
			} else {
				h.setHealthState(StateDegraded)
			}

			h.logger.Warn("JWKS refresh failed",
				zap.String("provider", h.providerName),
				zap.Int("consecutive_failures", h.jwksFailures),
				zap.Duration("stale_age", stale),
				zap.String("health", h.HealthState().String()),
				zap.Error(err))

			// Advance backoff with ±20% jitter.
			backoff = JitteredBackoff(backoff)
		} else {
			// Success: reset failure counters and transition to ready.
			h.jwksFailures = 0
			h.jwksStaleAt = time.Time{}
			backoff = InitialBackoff

			h.setHealthState(StateReady)

			h.logger.Debug("JWKS refresh succeeded",
				zap.String("provider", h.providerName))
		}
	}
}

// refreshOnce performs a single OIDC re-discovery and updates the handler's
// provider, oauth2Config, and tokenValidator fields under h.mu.
func (h *OAuthHandlerImpl) refreshOnce() error {
	newProvider, err := fetchOIDCConfig(h.config.IssuerURL)
	if err != nil {
		return err
	}

	newValidator, err := NewTokenValidator(h.config.IssuerURL, h.config.ClientID, h.logger)
	if err != nil {
		// Non-fatal: validator failure means bearer-token auth is degraded but
		// redirect and session flows still work with the refreshed provider.
		h.logger.Warn("JWKS refresh: token validator update failed (bearer auth degraded)",
			zap.String("provider", h.providerName),
			zap.Error(err))
		newValidator = nil
	}

	h.mu.Lock()
	h.provider = newProvider
	if h.oauth2Config != nil {
		h.oauth2Config.Endpoint.AuthURL = newProvider.AuthEndpoint
		h.oauth2Config.Endpoint.TokenURL = newProvider.TokenEndpoint
	}
	if newValidator != nil {
		h.tokenValidator = newValidator
	}
	h.mu.Unlock()

	return nil
}

// JitteredBackoff returns the next backoff value: doubles the current value,
// clamps to MaxBackoff, then applies ±20% jitter (D-14).
// Exported so ProviderRegistry's down-handler recovery loop can reuse the same
// backoff schedule as the JWKS refresher.
func JitteredBackoff(current time.Duration) time.Duration {
	next := current * 2
	if next > MaxBackoff {
		next = MaxBackoff
	}
	// jitter ∈ [0.8, 1.2]
	jitter := JitterFactorLow + rand.Float64()*JitterFactorRange //nolint:gosec // non-crypto backoff jitter
	return time.Duration(float64(next) * jitter)
}
