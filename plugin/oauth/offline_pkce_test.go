package oauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rashpile/go-envoy-oauth/plugin/session"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

// TestOfflineFlowUsesPKCE verifies that the API-key (offline) flow sends an
// S256 code challenge and redeems the code with the matching verifier (issue #11).
func TestOfflineFlowUsesPKCE(t *testing.T) {
	var gotVerifier string
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotVerifier = r.PostForm.Get("code_verifier")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token":  "at",
			"refresh_token": "rt",
			"token_type":    "Bearer",
			"expires_in":    300,
		})
	}))
	defer tokenSrv.Close()

	h := &OAuthHandlerImpl{
		config:       &OIDCConfig{ClientID: "gateway", ProviderName: "keycloak"},
		providerName: "keycloak",
		oauth2Config: &oauth2.Config{
			ClientID:    "gateway",
			RedirectURL: "/oauth/callback",
			Endpoint: oauth2.Endpoint{
				AuthURL:   "https://idp.example.com/auth",
				TokenURL:  tokenSrv.URL,
				AuthStyle: oauth2.AuthStyleInParams,
			},
		},
		sessionStore:      session.NewInMemorySessionStore(),
		refreshTokenCache: make(map[string]*tokenCacheEntry),
		logger:            zap.NewNop(),
	}
	oh, err := NewOfflineTokenHandler(h, zap.NewNop())
	if err != nil {
		t.Fatalf("NewOfflineTokenHandler: %v", err)
	}

	hdr := newMockHeaderMap()
	hdr.headers[":authority"] = "app.example.com"

	status, _, headers := oh.HandleOfflineAuthRedirect(hdr)
	if status != http.StatusFound || len(headers["Location"]) != 1 {
		t.Fatalf("redirect: status=%d headers=%v", status, headers)
	}
	authURL, err := url.Parse(headers["Location"][0])
	if err != nil {
		t.Fatalf("parse auth URL: %v", err)
	}
	q := authURL.Query()
	if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" {
		t.Fatalf("auth URL lacks an S256 code challenge: %s", authURL)
	}
	secrets := headers[StateBindingHeader]
	stateSession, err := h.sessionStore.Get(q.Get("state"))
	if err != nil {
		t.Fatalf("state session not stored: %v", err)
	}
	hash, _ := stateSession.Claims["binding_hash"].(string)
	if len(secrets) != 1 || !session.StateBindingMatches(secrets[0], hash) {
		t.Errorf("offline redirect binding secret %v does not match the stored hash", secrets)
	}

	status, _, _ = oh.HandleOfflineCallback(hdr, url.Values{"state": {q.Get("state")}, "code": {"c"}}.Encode())
	if status != http.StatusOK {
		t.Fatalf("callback status = %d, want 200", status)
	}
	sum := sha256.Sum256([]byte(gotVerifier))
	if gotVerifier == "" || base64.RawURLEncoding.EncodeToString(sum[:]) != q.Get("code_challenge") {
		t.Errorf("token request code_verifier %q does not match the code challenge", gotVerifier)
	}
}

// TestOfflineCallbackRequiresStoredVerifier verifies that a state session
// without a PKCE verifier (for example one created before the upgrade) is
// refused without calling the token endpoint.
func TestOfflineCallbackRequiresStoredVerifier(t *testing.T) {
	var called atomic.Bool
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called.Store(true)
		http.Error(w, "unexpected", http.StatusInternalServerError)
	}))
	defer tokenSrv.Close()

	store := session.NewInMemorySessionStore()
	h := &OAuthHandlerImpl{
		config:       &OIDCConfig{ClientID: "gateway", ProviderName: "keycloak"},
		providerName: "keycloak",
		oauth2Config: &oauth2.Config{
			ClientID:    "gateway",
			RedirectURL: "/oauth/callback",
			Endpoint:    oauth2.Endpoint{TokenURL: tokenSrv.URL, AuthStyle: oauth2.AuthStyleInParams},
		},
		sessionStore:      store,
		refreshTokenCache: make(map[string]*tokenCacheEntry),
		logger:            zap.NewNop(),
	}
	oh, err := NewOfflineTokenHandler(h, zap.NewNop())
	if err != nil {
		t.Fatalf("NewOfflineTokenHandler: %v", err)
	}
	if err := store.Store(&session.Session{
		ID:        "old|offline",
		Claims:    map[string]interface{}{"type": "offline_token"},
		ExpiresAt: time.Now().Add(time.Minute),
	}); err != nil {
		t.Fatalf("store state session: %v", err)
	}
	hdr := newMockHeaderMap()
	hdr.headers[":authority"] = "app.example.com"

	status, _, _ := oh.HandleOfflineCallback(hdr, url.Values{"state": {"old|offline"}, "code": {"c"}}.Encode())
	if status != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", status)
	}
	if called.Load() {
		t.Error("token endpoint was called without a stored verifier")
	}
}

// TestTokenEndpointCallsAreBounded verifies that a token endpoint that never
// answers fails the code exchange and the refresh-token exchange after the
// issuer HTTP timeout instead of blocking forever.
func TestTokenEndpointCallsAreBounded(t *testing.T) {
	old := oidcHTTPTimeout
	oidcHTTPTimeout = 200 * time.Millisecond
	t.Cleanup(func() { oidcHTTPTimeout = old })

	stop := make(chan struct{})
	stalled := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-stop:
		case <-r.Context().Done():
		}
	}))
	defer stalled.Close()
	defer close(stop) // runs first: release handlers so Close does not wait

	h := &OAuthHandlerImpl{
		config:       &OIDCConfig{ClientID: "gateway", ProviderName: "keycloak"},
		providerName: "keycloak",
		oauth2Config: &oauth2.Config{
			ClientID:    "gateway",
			RedirectURL: "/oauth/callback",
			Endpoint: oauth2.Endpoint{
				AuthURL:   "https://idp.example.com/auth",
				TokenURL:  stalled.URL,
				AuthStyle: oauth2.AuthStyleInParams,
			},
		},
		sessionStore:      session.NewInMemorySessionStore(),
		refreshTokenCache: make(map[string]*tokenCacheEntry),
		logger:            zap.NewNop(),
	}
	oh, err := NewOfflineTokenHandler(h, zap.NewNop())
	if err != nil {
		t.Fatalf("NewOfflineTokenHandler: %v", err)
	}

	within := func(name string, call func() bool) {
		t.Helper()
		done := make(chan bool, 1)
		go func() { done <- call() }()
		select {
		case failed := <-done:
			if !failed {
				t.Errorf("%s: succeeded against a stalled token endpoint", name)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: still blocked after 5s, the token endpoint call has no timeout", name)
		}
	}

	within("refresh-token exchange", func() bool {
		_, err := h.ExchangeRefreshToken(context.Background(), "rt")
		return err != nil
	})

	hdr := newMockHeaderMap()
	hdr.headers[":authority"] = "app.example.com"
	_, _, headers := oh.HandleOfflineAuthRedirect(hdr)
	authURL, _ := url.Parse(headers["Location"][0])
	within("offline code exchange", func() bool {
		status, _, _ := oh.HandleOfflineCallback(hdr, url.Values{"state": {authURL.Query().Get("state")}, "code": {"c"}}.Encode())
		return status != http.StatusOK
	})
}
