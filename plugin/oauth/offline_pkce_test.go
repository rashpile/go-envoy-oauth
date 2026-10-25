package oauth

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

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

	status, _, _ = oh.HandleOfflineCallback(hdr, url.Values{"state": {q.Get("state")}, "code": {"c"}}.Encode())
	if status != http.StatusOK {
		t.Fatalf("callback status = %d, want 200", status)
	}
	sum := sha256.Sum256([]byte(gotVerifier))
	if gotVerifier == "" || base64.RawURLEncoding.EncodeToString(sum[:]) != q.Get("code_challenge") {
		t.Errorf("token request code_verifier %q does not match the code challenge", gotVerifier)
	}
}
