package oauth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/envoyproxy/envoy/contrib/golang/common/go/api"
	"github.com/rashpile/go-envoy-oauth/session"
	"golang.org/x/oauth2"
)

// OIDCConfig represents the OpenID Connect configuration
type OIDCConfig struct {
	IssuerURL    string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
}

// OIDCProvider represents the OpenID Connect provider configuration
type OIDCProvider struct {
	Issuer           string   `json:"issuer"`
	AuthEndpoint     string   `json:"authorization_endpoint"`
	TokenEndpoint    string   `json:"token_endpoint"`
	UserInfoEndpoint string   `json:"userinfo_endpoint"`
	JWKSURI          string   `json:"jwks_uri"`
	ScopesSupported  []string `json:"scopes_supported"`
}

type OAuthHandler interface {
	HandleAuthRedirect(header api.RequestHeaderMap, redirectURI string) error
	HandleCallback(header api.RequestHeaderMap, query string) error
	HandleLogout(header api.RequestHeaderMap) error
	ValidateSession(session *session.Session) error
}

type oauthHandler struct {
	config        *OIDCConfig
	provider      *OIDCProvider
	oauth2Config  *oauth2.Config
	sessionStore  session.SessionStore
	cookieManager *session.CookieManager
	stateStore    map[string]time.Time
	mu            sync.Mutex
}

// NewOAuthHandler creates a new OAuth handler
func NewOAuthHandler(config *OIDCConfig, sessionStore session.SessionStore, cookieManager *session.CookieManager) (*oauthHandler, error) {
	// Fetch OpenID Connect configuration
	provider, err := fetchOIDCConfig(config.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch OIDC config: %v", err)
	}

	// Create OAuth2 config
	oauth2Config := &oauth2.Config{
		ClientID:     config.ClientID,
		ClientSecret: config.ClientSecret,
		RedirectURL:  config.RedirectURL,
		Scopes:       config.Scopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:  provider.AuthEndpoint,
			TokenURL: provider.TokenEndpoint,
		},
	}

	return &oauthHandler{
		config:        config,
		provider:      provider,
		oauth2Config:  oauth2Config,
		sessionStore:  sessionStore,
		cookieManager: cookieManager,
		stateStore:    make(map[string]time.Time),
	}, nil
}

func (h *oauthHandler) HandleAuthRedirect(header api.RequestHeaderMap, redirectURI string) error {
	state := generateRandomState()
	h.mu.Lock()
	h.stateStore[state] = time.Now().Add(5 * time.Minute)
	h.mu.Unlock()

	authURL := h.oauth2Config.AuthCodeURL(state, oauth2.SetAuthURLParam("redirect_uri", redirectURI))
	header.Set(":status", "302")
	header.Set("location", authURL)
	return nil
}

func (h *oauthHandler) HandleCallback(header api.RequestHeaderMap, query string) error {
	values, err := url.ParseQuery(query)
	if err != nil {
		return err
	}

	state := values.Get("state")
	h.mu.Lock()
	expiry, exists := h.stateStore[state]
	delete(h.stateStore, state)
	h.mu.Unlock()

	if !exists || time.Now().After(expiry) {
		return fmt.Errorf("invalid or expired state parameter")
	}

	code := values.Get("code")
	if code == "" {
		return fmt.Errorf("authorization code not found")
	}

	token, err := h.oauth2Config.Exchange(context.Background(), code)
	if err != nil {
		return err
	}

	userInfo, err := h.getUserInfo(token.AccessToken)
	if err != nil {
		return err
	}

	sub, ok := userInfo["sub"].(string)
	if !ok {
		return fmt.Errorf("invalid user info: sub claim not found")
	}

	session := session.NewSession(sub, token.AccessToken, userInfo, time.Now().Add(24*time.Hour))
	if err := h.sessionStore.Store(session); err != nil {
		return err
	}

	if err := h.cookieManager.SetCookie(header, session.ID); err != nil {
		return err
	}

	return nil
}

func (h *oauthHandler) HandleLogout(header api.RequestHeaderMap) error {
	sessionID, err := h.cookieManager.GetCookie(header)
	if err != nil {
		return err
	}

	if err := h.sessionStore.Delete(sessionID); err != nil {
		return err
	}

	h.cookieManager.DeleteCookie(header)
	return nil
}

func (h *oauthHandler) ValidateSession(session *session.Session) error {
	if time.Now().After(session.ExpiresAt) {
		return h.RefreshToken(session)
	}
	return nil
}

// getUserInfo retrieves user information from the OpenID Connect provider
func (h *oauthHandler) getUserInfo(accessToken string) (map[string]interface{}, error) {
	client := &http.Client{}
	req, err := http.NewRequest("GET", h.provider.UserInfoEndpoint, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get user info: %s", resp.Status)
	}

	var userInfo map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, err
	}

	return userInfo, nil
}

// fetchOIDCConfig retrieves the OpenID Connect configuration from the issuer
func fetchOIDCConfig(issuerURL string) (*OIDCProvider, error) {
	// Ensure the issuer URL has a protocol scheme
	if !strings.HasPrefix(issuerURL, "http://") && !strings.HasPrefix(issuerURL, "https://") {
		issuerURL = "https://" + issuerURL
	}

	// Construct well-known configuration URL
	configURL := issuerURL + "/.well-known/openid-configuration"

	// Fetch configuration
	resp, err := http.Get(configURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Parse response
	var provider OIDCProvider
	if err := json.Unmarshal(body, &provider); err != nil {
		return nil, err
	}

	return &provider, nil
}

// generateRandomState generates a random state parameter
func generateRandomState() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.URLEncoding.EncodeToString(b)
}

// RefreshToken attempts to refresh an expired access token
func (h *oauthHandler) RefreshToken(session *session.Session) error {
	if session.Token == "" {
		return fmt.Errorf("no token available")
	}

	// Get new token using refresh token
	token, err := h.oauth2Config.TokenSource(context.Background(), &oauth2.Token{
		AccessToken: session.Token,
	}).Token()
	if err != nil {
		return err
	}

	// Update session with new token
	session.Token = token.AccessToken
	session.ExpiresAt = time.Now().Add(24 * time.Hour)

	// Store updated session
	return h.sessionStore.Store(session)
}
