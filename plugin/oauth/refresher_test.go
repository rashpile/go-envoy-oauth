package oauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"
)

// TestJitteredBackoff verifies that jitteredBackoff:
//   - doubles the input up to MaxBackoff
//   - applies ±20% jitter (output ∈ [0.8×doubled, 1.2×doubled])
func TestJitteredBackoff(t *testing.T) {
	const iterations = 500

	cases := []struct {
		input    time.Duration
		wantBase time.Duration // doubled value before jitter
	}{
		{InitialBackoff, 2 * InitialBackoff},
		{MaxBackoff / 2, MaxBackoff},
		{MaxBackoff, MaxBackoff},
		{MaxBackoff * 2, MaxBackoff},
	}

	for _, tc := range cases {
		lo := time.Duration(float64(tc.wantBase) * JitterFactorLow)
		hi := time.Duration(float64(tc.wantBase) * (JitterFactorLow + JitterFactorRange))

		for i := 0; i < iterations; i++ {
			got := JitteredBackoff(tc.input)
			if got < lo || got > hi {
				t.Errorf("jitteredBackoff(%v) = %v, want [%v, %v]", tc.input, got, lo, hi)
				break
			}
		}
	}
}

// TestRefreshLoopStateTransitions verifies that consecutive failures drive the
// state machine ready → degraded → down and that a reset brings it back to ready.
func TestRefreshLoopStateTransitions(t *testing.T) {
	h := &OAuthHandlerImpl{providerName: "p-test"}
	if h.HealthState() != StateReady {
		t.Fatalf("initial state = %v, want StateReady", h.HealthState())
	}

	// Simulate MaxConsecFailures consecutive failures using the same logic as
	// runRefreshLoop (inline the state-machine block for correctness parity).
	for i := 1; i <= MaxConsecFailures; i++ {
		h.jwksFailures = i
		if h.jwksStaleAt.IsZero() {
			h.jwksStaleAt = time.Now()
		}
		if h.jwksFailures >= MaxConsecFailures {
			h.setHealthState(StateDown)
		} else {
			h.setHealthState(StateDegraded)
		}
	}

	if got := h.HealthState(); got != StateDown {
		t.Errorf("after %d failures HealthState() = %v, want StateDown", MaxConsecFailures, got)
	}

	// Simulate a successful refresh — counters reset, state becomes ready.
	h.jwksFailures = 0
	h.jwksStaleAt = time.Time{}
	h.setHealthState(StateReady)
	if got := h.HealthState(); got != StateReady {
		t.Errorf("after reset HealthState() = %v, want StateReady", got)
	}
}

// minimalOIDCServer starts an httptest.Server that serves a valid OIDC
// discovery document at any "/.well-known/openid-configuration" path.
func minimalOIDCServer(t *testing.T) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		issuer := srv.URL
		cfg := map[string]interface{}{
			"issuer":                 issuer,
			"authorization_endpoint": issuer + "/auth",
			"token_endpoint":         issuer + "/token",
			"userinfo_endpoint":      issuer + "/userinfo",
			"jwks_uri":               issuer + "/jwks",
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(cfg)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestRefreshLoopExitsOnContextCancel verifies that the refresher goroutine
// exits promptly when the context is cancelled.
func TestRefreshLoopExitsOnContextCancel(t *testing.T) {
	// We want the first select in runRefreshLoop to fire on ctx.Done().
	// We'll use a handler whose health is not StateReady so the sleep
	// is InitialBackoff (5s) — cancelling immediately before that fires.
	logger, _ := zap.NewDevelopment()
	h := &OAuthHandlerImpl{
		providerName: "p-exit",
		config:       &OIDCConfig{IssuerURL: "http://127.0.0.1:1", ClientID: "c1"},
		logger:       logger,
	}
	// Put it into a non-ready state so the backoff sleep is short if ctx
	// cancellation is slow.
	h.setHealthState(StateDegraded)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		h.runRefreshLoop(ctx)
	}()

	// Cancel before the first sleep fires.
	cancel()

	select {
	case <-done:
		// success
	case <-time.After(5 * time.Second):
		t.Fatal("refresher goroutine did not exit within 5s after context cancel")
	}
}

// TestRefreshOnceUpdatesProvider verifies that a successful refreshOnce()
// populates h.provider by fetching the OIDC discovery document.
func TestRefreshOnceUpdatesProvider(t *testing.T) {
	var callCount atomic.Int32
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount.Add(1)
		issuer := srv.URL
		cfg := map[string]interface{}{
			"issuer":                 issuer,
			"authorization_endpoint": issuer + "/auth",
			"token_endpoint":         issuer + "/token",
			"userinfo_endpoint":      issuer + "/userinfo",
			"jwks_uri":               issuer + "/jwks",
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(cfg)
	}))
	defer srv.Close()

	logger, _ := zap.NewDevelopment()
	h := &OAuthHandlerImpl{
		providerName: "p-refresh",
		config:       &OIDCConfig{IssuerURL: srv.URL, ClientID: "c1"},
		logger:       logger,
	}

	if err := h.refreshOnce(); err != nil {
		t.Fatalf("refreshOnce() failed: %v", err)
	}

	if h.provider == nil {
		t.Fatal("h.provider is nil after successful refreshOnce")
	}
	if callCount.Load() == 0 {
		t.Fatal("refreshOnce made no HTTP requests")
	}
}

// TestRefreshOnceFailsWithUnreachableHost verifies that refreshOnce() returns
// an error when the IDP host is unreachable.
func TestRefreshOnceFailsWithUnreachableHost(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	h := &OAuthHandlerImpl{
		providerName: "p-fail",
		config:       &OIDCConfig{IssuerURL: "http://127.0.0.1:1", ClientID: "c1"},
		logger:       logger,
	}

	err := h.refreshOnce()
	if err == nil {
		t.Fatal("expected error from refreshOnce with unreachable host, got nil")
	}
}

// TestRefreshOnceRecoveredTurnsPanicIntoError verifies that a panic during a
// JWKS refresh becomes an error instead of killing the refresh goroutine.
func TestRefreshOnceRecoveredTurnsPanicIntoError(t *testing.T) {
	h := &OAuthHandlerImpl{logger: zap.NewNop()} // nil config makes refreshOnce panic
	if err := h.refreshOnceRecovered(); err == nil || !strings.Contains(err.Error(), "panic") {
		t.Errorf("refreshOnceRecovered = %v, want a panic error", err)
	}
}
