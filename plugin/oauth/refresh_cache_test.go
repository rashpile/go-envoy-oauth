package oauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rashpile/go-envoy-oauth/plugin/session"
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

// TestConcurrentSessionRefreshSharesOneTokenRequest verifies that parallel
// requests on a session whose access token is about to expire send its
// refresh token once, and all of them see the new access token. Sending a
// rotating refresh token twice would log the user out.
func TestConcurrentSessionRefreshSharesOneTokenRequest(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		time.Sleep(100 * time.Millisecond) // keep the request open so callers overlap
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token":  "new-at",
			"refresh_token": "rotated-rt",
			"token_type":    "Bearer",
			"expires_in":    300,
		})
	}))
	defer srv.Close()

	store := session.NewInMemorySessionStore()
	h := &OAuthHandlerImpl{
		config:       &OIDCConfig{ClientID: "gateway", ProviderName: "kc"},
		providerName: "kc",
		oauth2Config: &oauth2.Config{
			ClientID: "gateway",
			Endpoint: oauth2.Endpoint{TokenURL: srv.URL, AuthStyle: oauth2.AuthStyleInParams},
		},
		sessionStore:      store,
		refreshTokenCache: make(map[string]*tokenCacheEntry),
		logger:            zap.NewNop(),
	}
	if err := store.Store(&session.Session{
		ID:             "s1",
		Token:          "old-at",
		RefreshToken:   "rt",
		TokenExpiresAt: time.Now(),
		ExpiresAt:      time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("Store: %v", err)
	}

	const n = 10
	var wg sync.WaitGroup
	errs := make(chan error, n)
	tokens := make(chan string, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s, err := store.Get("s1")
			if err != nil {
				errs <- err
				return
			}
			if err := h.ValidateSession(s); err != nil {
				errs <- err
				return
			}
			tokens <- s.Token
		}()
	}
	wg.Wait()
	close(errs)
	close(tokens)
	for err := range errs {
		t.Errorf("ValidateSession: %v", err)
	}
	for tok := range tokens {
		if tok != "new-at" {
			t.Errorf("caller saw access token %q, want new-at", tok)
		}
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Errorf("token endpoint calls = %d, want 1", got)
	}
	stored, _ := store.Get("s1")
	if stored.Token != "new-at" || stored.RefreshToken != "rotated-rt" {
		t.Errorf("stored session token=%q refresh=%q, want the refreshed values", stored.Token, stored.RefreshToken)
	}
}

// TestSessionRefreshTimesOut verifies that an IdP that never answers fails the
// refresh within the deadline instead of blocking every request of the
// session behind the shared call.
func TestSessionRefreshTimesOut(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		<-release
	}))
	defer srv.Close()
	defer close(release)

	orig := tokenRefreshTimeout
	tokenRefreshTimeout = 100 * time.Millisecond
	defer func() { tokenRefreshTimeout = orig }()

	store := session.NewInMemorySessionStore()
	h := &OAuthHandlerImpl{
		config:       &OIDCConfig{ClientID: "gateway", ProviderName: "kc"},
		providerName: "kc",
		oauth2Config: &oauth2.Config{
			ClientID: "gateway",
			Endpoint: oauth2.Endpoint{TokenURL: srv.URL, AuthStyle: oauth2.AuthStyleInParams},
		},
		sessionStore:      store,
		refreshTokenCache: make(map[string]*tokenCacheEntry),
		logger:            zap.NewNop(),
	}
	if err := store.Store(&session.Session{ID: "s1", RefreshToken: "rt", TokenExpiresAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatalf("Store: %v", err)
	}
	s, _ := store.Get("s1")

	start := time.Now()
	err := h.ValidateSession(s)
	if err == nil {
		t.Fatal("ValidateSession succeeded against a hanging token endpoint")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("refresh took %v, want it bounded by the timeout", elapsed)
	}
}
