package oauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

// newHandlerWithTokenEndpoint returns a handler whose token endpoint answers
// every refresh_token grant with an access token derived from the submitted
// refresh token, and counts the calls.
func newHandlerWithTokenEndpoint(t *testing.T) (*OAuthHandlerImpl, *int32) {
	t.Helper()
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "AT-for-" + r.PostForm.Get("refresh_token"),
			"token_type":   "Bearer",
			"expires_in":   300,
		})
	}))
	t.Cleanup(srv.Close)

	return &OAuthHandlerImpl{
		config:       &OIDCConfig{ClientID: "test-client", ProviderName: "keycloak"},
		providerName: "keycloak",
		oauth2Config: &oauth2.Config{
			ClientID:     "test-client",
			ClientSecret: "test-secret",
			Endpoint:     oauth2.Endpoint{TokenURL: srv.URL, AuthStyle: oauth2.AuthStyleInParams},
		},
		refreshTokenCache: make(map[string]*tokenCacheEntry),
		logger:            zap.NewNop(),
	}, &calls
}

// TestExchangeRefreshTokenCacheIsPerToken verifies that two refresh tokens
// sharing a long common prefix (as JWTs from one realm do) get separate cache
// entries, so one caller can never receive another caller's access token (issue #8).
func TestExchangeRefreshTokenCacheIsPerToken(t *testing.T) {
	h, calls := newHandlerWithTokenEndpoint(t)
	const prefix = "eyJhbGciOiJIUzUxMiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICI."
	victim := prefix + "victim-payload.sig"
	other := prefix + "other-payload.sig"

	got, err := h.ExchangeRefreshToken(context.Background(), victim)
	if err != nil {
		t.Fatalf("victim exchange: %v", err)
	}
	if got != "AT-for-"+victim {
		t.Fatalf("victim access token = %q", got)
	}

	got, err = h.ExchangeRefreshToken(context.Background(), other)
	if err != nil {
		t.Fatalf("other exchange: %v", err)
	}
	if got != "AT-for-"+other {
		t.Errorf("token sharing a prefix got %q, want its own access token", got)
	}
	if n := atomic.LoadInt32(calls); n != 2 {
		t.Errorf("token endpoint calls = %d, want 2 (no cache hit across tokens)", n)
	}

	// The same token is still served from cache.
	if _, err := h.ExchangeRefreshToken(context.Background(), victim); err != nil {
		t.Fatalf("repeat exchange: %v", err)
	}
	if n := atomic.LoadInt32(calls); n != 2 {
		t.Errorf("token endpoint calls after repeat = %d, want 2 (cache hit)", n)
	}
}

// TestExchangeRefreshTokenShortTokenDoesNotPanic verifies that tokens shorter
// than any fixed prefix length are handled without a slice-bounds panic.
func TestExchangeRefreshTokenShortTokenDoesNotPanic(t *testing.T) {
	h, _ := newHandlerWithTokenEndpoint(t)
	for _, tok := range []string{"", "x", "short-token"} {
		if _, err := h.ExchangeRefreshToken(context.Background(), tok); err != nil && tok != "" {
			t.Errorf("ExchangeRefreshToken(%q): unexpected error %v", tok, err)
		}
	}
}

func TestRefreshTokenCacheKeyIsFullHash(t *testing.T) {
	a := refreshTokenCacheKey("same-prefix-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA-1")
	b := refreshTokenCacheKey("same-prefix-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA-2")
	if a == b {
		t.Errorf("cache keys collide for tokens differing only in the last byte")
	}
	if len(a) != 64 {
		t.Errorf("cache key length = %d, want 64 hex chars", len(a))
	}
}
