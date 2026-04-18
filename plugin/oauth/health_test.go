package oauth

import (
	"context"
	"strings"
	"testing"
)

// TestHealthStateInitialValue — HLTH-02: default OAuthHandlerImpl reports ready.
func TestHealthStateInitialValue(t *testing.T) {
	h := &OAuthHandlerImpl{providerName: "p1"}
	if got := h.HealthState(); got != StateReady {
		t.Errorf("HealthState() on zero handler = %v, want StateReady", got)
	}
}

// TestProviderStateString — String() produces the stable Prometheus labels.
func TestProviderStateString(t *testing.T) {
	cases := []struct {
		s    ProviderState
		want string
	}{
		{StateReady, "ready"},
		{StateDegraded, "degraded"},
		{StateDown, "down"},
		{ProviderState(99), "unknown"},
	}
	for _, tc := range cases {
		if got := tc.s.String(); got != tc.want {
			t.Errorf("ProviderState(%d).String() = %q, want %q", tc.s, got, tc.want)
		}
	}
}

// TestSetHealthStateUpdatesAtomic — round-trip the atomic cell.
func TestSetHealthStateUpdatesAtomic(t *testing.T) {
	h := &OAuthHandlerImpl{providerName: "p1"}
	h.setHealthState(StateDegraded)
	if got := h.HealthState(); got != StateDegraded {
		t.Errorf("after setHealthState(Degraded), HealthState() = %v, want StateDegraded", got)
	}
	h.setHealthState(StateDown)
	if got := h.HealthState(); got != StateDown {
		t.Errorf("after setHealthState(Down), HealthState() = %v, want StateDown", got)
	}
	h.setHealthState(StateReady)
	if got := h.HealthState(); got != StateReady {
		t.Errorf("after setHealthState(Ready), HealthState() = %v, want StateReady", got)
	}
}

// TestDownHandlerHealthStateIsDown — DownHandler unconditionally reports down.
func TestDownHandlerHealthStateIsDown(t *testing.T) {
	d := &DownHandler{ProviderName: "kc"}
	if got := d.HealthState(); got != StateDown {
		t.Errorf("DownHandler.HealthState() = %v, want StateDown", got)
	}
}

// TestDownHandlerValidateBearerTokenReturnsError — every operation returns "unavailable".
func TestDownHandlerValidateBearerTokenReturnsError(t *testing.T) {
	d := &DownHandler{ProviderName: "kc"}
	_, err := d.ValidateBearerToken(context.Background(), "tok")
	if err == nil {
		t.Fatal("expected non-nil error from DownHandler.ValidateBearerToken")
	}
	if !strings.Contains(err.Error(), "unavailable") {
		t.Errorf("error message = %q, want containing 'unavailable'", err.Error())
	}
}

// TestDownHandlerInterface — compile-time check moved inside a test to ensure
// it's exercised by `go test` and caught by CI even if unused elsewhere.
func TestDownHandlerInterface(t *testing.T) {
	var _ OAuthHandler = (*DownHandler)(nil)
}
