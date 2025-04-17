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
	RefreshToken(session *session.Session, additionalScopes ...string) error
	HandleApiKeyAuth(header api.RequestHeaderMap) error
	HandleApiKeyCallback(header api.RequestHeaderMap, query string) (*oauth2.Token, error)
	GetProvider() *OIDCProvider
}

type oauthHandler struct {
	config        *OIDCConfig
	provider      *OIDCProvider
	oauth2Config  *oauth2.Config
	sessionStore  session.SessionStore
	cookieManager *session.CookieManager
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
	}, nil
}

// getAbsoluteRedirectURL returns an absolute redirect URL based on the request headers
func (h *oauthHandler) getAbsoluteRedirectURL(header api.RequestHeaderMap) string {
	// Get the host from the request
	host, _ := header.Get(":authority")
	if host == "" {
		host, _ = header.Get("host")
	}

	// Ensure the redirect URL is absolute and properly formatted
	redirectURL := h.oauth2Config.RedirectURL
	if !strings.HasPrefix(redirectURL, "http://") && !strings.HasPrefix(redirectURL, "https://") {
		// If no scheme is specified, use the same scheme as the request
		scheme := "http"
		if forwardedProto, _ := header.Get("x-forwarded-proto"); forwardedProto == "https" {
			scheme = "https"
		}
		// Ensure the redirect URL starts with a slash
		if !strings.HasPrefix(redirectURL, "/") {
			redirectURL = "/" + redirectURL
		}
		redirectURL = fmt.Sprintf("%s://%s%s", scheme, host, redirectURL)
	}

	return redirectURL
}

// getOAuthConfig returns a new OAuth2 config with the absolute redirect URL
func (h *oauthHandler) getOAuthConfig(header api.RequestHeaderMap) *oauth2.Config {
	// Get the absolute redirect URL
	redirectURL := h.getAbsoluteRedirectURL(header)

	// Create a new OAuth2 config with the absolute redirect URL
	config := &oauth2.Config{
		ClientID:     h.oauth2Config.ClientID,
		ClientSecret: h.oauth2Config.ClientSecret,
		RedirectURL:  redirectURL,
		Scopes:       h.oauth2Config.Scopes, // Use original scopes without offline_access
		Endpoint:     h.oauth2Config.Endpoint,
	}

	return config
}

func (h *oauthHandler) HandleAuthRedirect(header api.RequestHeaderMap, redirectURI string) error {
	// Generate a random state and combine it with the original request path
	state := generateRandomState() + "|" + redirectURI

	// Store the state in a temporary session
	session := &session.Session{
		ID:        state,
		UserID:    "",
		Token:     "",
		Claims:    nil,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}
	if err := h.sessionStore.Store(session); err != nil {
		return fmt.Errorf("failed to store state: %v", err)
	}

	// Set the state in a cookie
	if err := h.cookieManager.SetCookie(header, state); err != nil {
		return fmt.Errorf("failed to set state cookie: %v", err)
	}

	// Use the configured RedirectURL from oauth2Config
	oauth2Config := h.getOAuthConfig(header)
	authURL := oauth2Config.AuthCodeURL(state)
	header.Set("location", authURL)
	return nil
}

func (h *oauthHandler) HandleCallback(header api.RequestHeaderMap, query string) error {
	values, err := url.ParseQuery(query)
	if err != nil {
		return err
	}

	// Get the raw state parameter
	state := values.Get("state")
	if state == "" {
		return fmt.Errorf("state parameter not found")
	}

	// Get the state from the session store
	stateSession, err := h.sessionStore.Get(state)
	if err != nil {
		return fmt.Errorf("invalid or expired state parameter")
	}

	// Validate the state session
	if time.Now().After(stateSession.ExpiresAt) {
		return fmt.Errorf("state parameter expired")
	}

	// Delete the state session
	if err := h.sessionStore.Delete(state); err != nil {
		return fmt.Errorf("failed to delete state: %v", err)
	}

	// Extract the original request path from the state parameter
	parts := strings.Split(state, "|")
	if len(parts) != 2 {
		return fmt.Errorf("invalid state parameter format")
	}
	originalPath := parts[1]

	code := values.Get("code")
	if code == "" {
		return fmt.Errorf("authorization code not found")
	}

	// Use the configured RedirectURL from oauth2Config
	oauth2Config := h.getOAuthConfig(header)
	token, err := oauth2Config.Exchange(context.Background(), code)
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

	// Create a new session for the authenticated user
	session := &session.Session{
		ID:           generateRandomState(), // Use a new random ID for the user session
		UserID:       sub,
		Token:        token.AccessToken,
		RefreshToken: token.RefreshToken,
		Claims:       userInfo,
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(24 * time.Hour),
	}
	if err := h.sessionStore.Store(session); err != nil {
		return err
	}

	if err := h.cookieManager.SetCookie(header, session.ID); err != nil {
		return err
	}

	// Set the original request path in the location header
	header.Set("location", originalPath)
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
	// Use base64.RawURLEncoding to avoid padding and make it URL-safe
	return base64.RawURLEncoding.EncodeToString(b)
}

// RefreshToken attempts to refresh an expired access token with optional additional scopes
func (h *oauthHandler) RefreshToken(session *session.Session, additionalScopes ...string) error {
	if session.Token == "" {
		return fmt.Errorf("no token available")
	}

	// Create a new OAuth2 config with additional scopes if provided
	config := h.oauth2Config
	if len(additionalScopes) > 0 {
		// For API key requests, we want to get a new token with offline_access
		// Don't include the original scopes to get a clean token
		config = &oauth2.Config{
			ClientID:     config.ClientID,
			ClientSecret: config.ClientSecret,
			RedirectURL:  config.RedirectURL,
			Scopes:       []string{"offline_access"}, // Only request offline_access scope
			Endpoint:     config.Endpoint,
		}
	}

	// Get new token using refresh token
	token, err := config.TokenSource(context.Background(), &oauth2.Token{
		AccessToken:  session.Token,
		RefreshToken: session.RefreshToken,
	}).Token()
	if err != nil {
		return err
	}

	// Update session with new token
	session.Token = token.AccessToken
	session.RefreshToken = token.RefreshToken
	session.ExpiresAt = time.Now().Add(24 * time.Hour)

	// Store updated session
	return h.sessionStore.Store(session)
}

func (h *oauthHandler) HandleApiKeyAuth(header api.RequestHeaderMap) error {
	// Generate a random state
	state := generateRandomState()

	// Store the state in a temporary session
	stateSession := &session.Session{
		ID:        state,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}
	if err := h.sessionStore.Store(stateSession); err != nil {
		return fmt.Errorf("failed to store state: %v", err)
	}

	// Get the absolute redirect URL
	redirectURL := h.getAbsoluteRedirectURL(header)
	if !strings.HasPrefix(redirectURL, "http") {
		// If the redirect URL is relative, make it absolute
		host, _ := header.Get(":authority")
		if host == "" {
			host, _ = header.Get("host")
		}
		scheme := "http"
		if forwardedProto, _ := header.Get("x-forwarded-proto"); forwardedProto == "https" {
			scheme = "https"
		}
		redirectURL = fmt.Sprintf("%s://%s%s", scheme, host, redirectURL)
	}

	// Create OAuth2 config with only offline_access scope
	config := &oauth2.Config{
		ClientID:     h.oauth2Config.ClientID,
		ClientSecret: h.oauth2Config.ClientSecret,
		RedirectURL:  redirectURL + "/apikey/callback",
		Scopes:       []string{"offline_access"},
		Endpoint:     h.oauth2Config.Endpoint,
	}

	// Generate the authorization URL
	authURL := config.AuthCodeURL(state)
	header.Set("location", authURL)
	return nil
}

func (h *oauthHandler) HandleApiKeyCallback(header api.RequestHeaderMap, query string) (*oauth2.Token, error) {
	values, err := url.ParseQuery(query)
	if err != nil {
		return nil, err
	}

	// Get the state parameter
	state := values.Get("state")
	if state == "" {
		return nil, fmt.Errorf("state parameter not found")
	}

	// Get the state from the session store
	stateSession, err := h.sessionStore.Get(state)
	if err != nil {
		return nil, fmt.Errorf("invalid or expired state parameter")
	}

	// Validate the state session
	if time.Now().After(stateSession.ExpiresAt) {
		return nil, fmt.Errorf("state parameter expired")
	}

	// Delete the state session
	if err := h.sessionStore.Delete(state); err != nil {
		return nil, fmt.Errorf("failed to delete state: %v", err)
	}

	code := values.Get("code")
	if code == "" {
		return nil, fmt.Errorf("authorization code not found")
	}

	// Get the absolute redirect URL
	redirectURL := h.getAbsoluteRedirectURL(header)
	if !strings.HasPrefix(redirectURL, "http") {
		// If the redirect URL is relative, make it absolute
		host, _ := header.Get(":authority")
		if host == "" {
			host, _ = header.Get("host")
		}
		scheme := "http"
		if forwardedProto, _ := header.Get("x-forwarded-proto"); forwardedProto == "https" {
			scheme = "https"
		}
		redirectURL = fmt.Sprintf("%s://%s%s", scheme, host, redirectURL)
	}

	// Create OAuth2 config with only offline_access scope
	config := &oauth2.Config{
		ClientID:     h.oauth2Config.ClientID,
		ClientSecret: h.oauth2Config.ClientSecret,
		RedirectURL:  redirectURL + "/apikey/callback",
		Scopes:       []string{"offline_access"},
		Endpoint:     h.oauth2Config.Endpoint,
	}
	fmt.Println("RedirectURL", config.RedirectURL)

	// Exchange the code for a token
	token, err := config.Exchange(context.Background(), code)
	if err != nil {
		return nil, err
	}

	return token, nil
}

func (h *oauthHandler) GetProvider() *OIDCProvider {
	return h.provider
}
