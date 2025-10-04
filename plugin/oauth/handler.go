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
	"github.com/rashpile/go-envoy-oauth/plugin/session"
	"go.uber.org/zap"
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
	Issuer             string   `json:"issuer"`
	AuthEndpoint       string   `json:"authorization_endpoint"`
	TokenEndpoint      string   `json:"token_endpoint"`
	UserInfoEndpoint   string   `json:"userinfo_endpoint"`
	EndSessionEndpoint string   `json:"end_session_endpoint"`
	JWKSURI            string   `json:"jwks_uri"`
	ScopesSupported    []string `json:"scopes_supported"`
}

type OAuthHandler interface {
	HandleAuthRedirect(header api.RequestHeaderMap, redirectURI string) error
	HandleCallback(header api.RequestHeaderMap, query string) error
	HandleLogout(header api.RequestHeaderMap) (string, error)
	ValidateSession(session *session.Session) error
	IsNeedValidateSession(session *session.Session) bool
	ValidateBearerToken(ctx context.Context, token string) (*session.Session, error)
	ExchangeRefreshToken(ctx context.Context, refreshToken string) (string, error)
}

type tokenCacheEntry struct {
	accessToken string
	expiry      time.Time
}

type OAuthHandlerImpl struct {
	config            *OIDCConfig
	provider          *OIDCProvider
	oauth2Config      *oauth2.Config
	sessionStore      session.SessionStore
	cookieManager     *session.CookieManager
	tokenValidator    *TokenValidator
	refreshTokenCache map[string]*tokenCacheEntry // maps refresh token hash -> access token
	cacheMu           sync.RWMutex
	mu                sync.Mutex
	logger            *zap.Logger
}

// NewOAuthHandler creates a new OAuth handler
func NewOAuthHandler(config *OIDCConfig, sessionStore session.SessionStore, cookieManager *session.CookieManager, logger *zap.Logger) (OAuthHandler, error) {
	// Fetch OpenID Connect configuration
	provider, err := fetchOIDCConfig(config.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch OIDC config: %v", err)
	}

	// Log the discovered endpoints
	logger.Debug("OIDC Provider discovered",
		zap.String("issuer", provider.Issuer),
		zap.String("auth_endpoint", provider.AuthEndpoint),
		zap.String("token_endpoint", provider.TokenEndpoint),
		zap.String("userinfo_endpoint", provider.UserInfoEndpoint),
		zap.String("end_session_endpoint", provider.EndSessionEndpoint))

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

	// Create token validator for bearer token authentication
	var tokenValidator *TokenValidator
	tokenValidator, err = NewTokenValidator(config.IssuerURL, config.ClientID, logger)
	if err != nil {
		// Log error but don't fail - bearer token auth will be disabled
		logger.Error("Failed to create token validator, bearer token auth will be disabled",
			zap.Error(err),
			zap.String("issuer_url", config.IssuerURL))
		tokenValidator = nil
	}

	return &OAuthHandlerImpl{
		config:            config,
		provider:          provider,
		oauth2Config:      oauth2Config,
		sessionStore:      sessionStore,
		cookieManager:     cookieManager,
		tokenValidator:    tokenValidator,
		refreshTokenCache: make(map[string]*tokenCacheEntry),
		logger:            logger,
	}, nil
}

// GetAbsoluteRedirectURL returns an absolute redirect URL based on the request headers
func (h *OAuthHandlerImpl) GetAbsoluteRedirectURL(header api.RequestHeaderMap) string {
	// Get the host from the request
	host, _ := header.Get(":authority")
	if host == "" {
		host, _ = header.Get("host")
	}

	if forwardedHost, _ := header.Get("x-forwarded-host"); forwardedHost != "" {
		host = forwardedHost
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

// GetOAuthConfig returns a new OAuth2 config with the absolute redirect URL
func (h *OAuthHandlerImpl) GetOAuthConfig(header api.RequestHeaderMap) *oauth2.Config {
	redirectURL := h.GetAbsoluteRedirectURL(header)
	return &oauth2.Config{
		ClientID:     h.oauth2Config.ClientID,
		ClientSecret: h.oauth2Config.ClientSecret,
		RedirectURL:  redirectURL,
		Scopes:       h.oauth2Config.Scopes,
		Endpoint:     h.oauth2Config.Endpoint,
	}
}

func (h *OAuthHandlerImpl) HandleAuthRedirect(header api.RequestHeaderMap, redirectURI string) error {
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
	oauth2Config := h.GetOAuthConfig(header)
	authURL := oauth2Config.AuthCodeURL(state)
	header.Set("location", authURL)
	return nil
}

func (h *OAuthHandlerImpl) HandleCallback(header api.RequestHeaderMap, query string) error {
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
	oauth2Config := h.GetOAuthConfig(header)
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

	// Extract ID token if available
	idToken := ""
	if idTokenRaw, ok := token.Extra("id_token").(string); ok {
		idToken = idTokenRaw
	}

	// Create a new session for the authenticated user
	session := &session.Session{
		ID:             generateRandomState(), // Use a new random ID for the user session
		UserID:         sub,
		Token:          token.AccessToken,
		TokenExpiresAt: token.Expiry, // Store access token expiry
		IDToken:        idToken,
		RefreshToken:   token.RefreshToken, // Store refresh token for future use
		Claims:         userInfo,
		CreatedAt:      time.Now(),
		ExpiresAt:      time.Now().Add(24 * time.Hour), // Session expires in 24 hours
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

func (h *OAuthHandlerImpl) HandleLogout(header api.RequestHeaderMap) (string, error) {
	h.logger.Debug("HandleLogout started",
		zap.String("provider_issuer", h.provider.Issuer),
		zap.String("end_session_endpoint", h.provider.EndSessionEndpoint),
		zap.Bool("has_end_session", h.provider.EndSessionEndpoint != ""))

	sessionID, err := h.cookieManager.GetCookie(header)
	if err != nil {
		h.logger.Debug("No session cookie found", zap.Error(err))
		return "", err
	}

	// Get the session to retrieve ID token for logout
	sess, err := h.sessionStore.Get(sessionID)
	if err != nil {
		// Session not found, just clear the cookie
		h.logger.Debug("Session not found, clearing cookie", zap.Error(err))
		h.cookieManager.DeleteCookie(header)
		return "/", nil
	}

	h.logger.Debug("Session found for logout",
		zap.String("user_id", sess.UserID),
		zap.Bool("has_id_token", sess.IDToken != ""))

	// Delete the session from store
	if err := h.sessionStore.Delete(sessionID); err != nil {
		return "", err
	}

	// Clear the cookie
	h.cookieManager.DeleteCookie(header)

	// If IDP supports end_session_endpoint, redirect to it
	if h.provider.EndSessionEndpoint != "" {
		// Build the logout URL with required parameters
		logoutURL, err := url.Parse(h.provider.EndSessionEndpoint)
		if err != nil {
			return "", fmt.Errorf("failed to parse end_session_endpoint: %v", err)
		}

		params := logoutURL.Query()

		// Add ID token hint if available
		if sess.IDToken != "" {
			params.Set("id_token_hint", sess.IDToken)
		}

		// Get the post-logout redirect URI
		postLogoutRedirectURI := h.GetPostLogoutRedirectURI(header)
		if postLogoutRedirectURI != "" {
			params.Set("post_logout_redirect_uri", postLogoutRedirectURI)
			// Add state parameter for security
			state := generateRandomState()
			params.Set("state", state)
		}

		logoutURL.RawQuery = params.Encode()

		h.logger.Debug("Redirecting to IDP logout endpoint",
			zap.String("logout_url", logoutURL.String()),
			zap.String("endpoint", h.provider.EndSessionEndpoint),
			zap.Bool("has_id_token", sess.IDToken != ""),
			zap.String("post_logout_redirect", postLogoutRedirectURI))

		return logoutURL.String(), nil
	}

	// No IDP logout endpoint, just redirect to home
	h.logger.Debug("IDP does not support end_session_endpoint, performing local logout only")
	return "/", nil
}

func (h *OAuthHandlerImpl) IsNeedValidateSession(session *session.Session) bool {
	// Check if access token has expired or will expire soon (within 10 seconds)
	if !session.TokenExpiresAt.IsZero() {
		return time.Until(session.TokenExpiresAt) < 10*time.Second
	}
	// Fallback to session expiry if token expiry is not set
	return time.Now().After(session.ExpiresAt)
}

func (h *OAuthHandlerImpl) ValidateSession(session *session.Session) error {
	// Check if access token needs refresh
	if !session.TokenExpiresAt.IsZero() && time.Until(session.TokenExpiresAt) < 10*time.Second {
		return h.RefreshToken(session)
	}
	// Fallback: check session expiry
	if time.Now().After(session.ExpiresAt) {
		return h.RefreshToken(session)
	}
	return nil
}

// getUserInfo retrieves user information from the OpenID Connect provider
func (h *OAuthHandlerImpl) getUserInfo(accessToken string) (map[string]interface{}, error) {
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

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	// Fetch configuration
	resp, err := client.Get(configURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch OIDC configuration from %s: %v", configURL, err)
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("OIDC configuration request failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read OIDC configuration response: %v", err)
	}

	// Parse response
	var provider OIDCProvider
	if err := json.Unmarshal(body, &provider); err != nil {
		// Log the first 100 chars of the response for debugging
		preview := string(body)
		if len(preview) > 100 {
			preview = preview[:100] + "..."
		}
		return nil, fmt.Errorf("failed to parse OIDC configuration (response: %s): %v", preview, err)
	}

	// Validate required fields
	if provider.AuthEndpoint == "" || provider.TokenEndpoint == "" {
		return nil, fmt.Errorf("invalid OIDC configuration: missing required endpoints")
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

// GetPostLogoutRedirectURI returns the post-logout redirect URI
func (h *OAuthHandlerImpl) GetPostLogoutRedirectURI(header api.RequestHeaderMap) string {
	// First check if redirect_uri is provided in query params
	path, _ := header.Get(":path")
	if path != "" {
		// Parse query parameters from the path
		if idx := strings.Index(path, "?"); idx > 0 {
			queryString := path[idx+1:]
			if params, err := url.ParseQuery(queryString); err == nil {
				if redirectURI := params.Get("redirect_uri"); redirectURI != "" {
					// Validate that it's a relative path or same-origin URL for security
					if strings.HasPrefix(redirectURI, "/") {
						// Relative path - make it absolute
						host, _ := header.Get(":authority")
						if host == "" {
							host, _ = header.Get("host")
						}
						if forwardedHost, _ := header.Get("x-forwarded-host"); forwardedHost != "" {
							host = forwardedHost
						}

						scheme := "http"
						if forwardedProto, _ := header.Get("x-forwarded-proto"); forwardedProto == "https" {
							scheme = "https"
						}

						return fmt.Sprintf("%s://%s%s", scheme, host, redirectURI)
					}
					// For absolute URLs, return as-is (you may want to validate the domain)
					return redirectURI
				}
			}
		}
	}

	// Fall back to /oauth/welcome page
	// Get the host from the request
	host, _ := header.Get(":authority")
	if host == "" {
		host, _ = header.Get("host")
	}

	if forwardedHost, _ := header.Get("x-forwarded-host"); forwardedHost != "" {
		host = forwardedHost
	}

	// Determine the scheme
	scheme := "http"
	if forwardedProto, _ := header.Get("x-forwarded-proto"); forwardedProto == "https" {
		scheme = "https"
	}

	// Return the welcome page URL
	return fmt.Sprintf("%s://%s/oauth/welcome", scheme, host)
}

// RefreshToken attempts to refresh an expired access token
func (h *OAuthHandlerImpl) RefreshToken(session *session.Session) error {
	if session.RefreshToken == "" {
		return fmt.Errorf("no refresh token available")
	}

	h.logger.Debug("Refreshing access token",
		zap.String("session_id", session.ID),
		zap.Time("token_expires_at", session.TokenExpiresAt))

	// Get new token using refresh token
	token, err := h.oauth2Config.TokenSource(context.Background(), &oauth2.Token{
		RefreshToken: session.RefreshToken,
	}).Token()
	if err != nil {
		h.logger.Error("Failed to refresh access token", zap.Error(err))
		return fmt.Errorf("failed to refresh token: %v", err)
	}

	// Update session with new token and expiry
	session.Token = token.AccessToken
	session.TokenExpiresAt = token.Expiry
	// Update refresh token if a new one was issued
	if token.RefreshToken != "" {
		session.RefreshToken = token.RefreshToken
	}

	h.logger.Debug("Access token refreshed successfully",
		zap.String("session_id", session.ID),
		zap.Time("new_expiry", token.Expiry))

	// Store updated session
	return h.sessionStore.Store(session)
}

// GetSessionStore returns the session store
func (h *OAuthHandlerImpl) GetSessionStore() session.SessionStore {
	return h.sessionStore
}

// ValidateBearerToken validates a bearer token and returns a session
func (h *OAuthHandlerImpl) ValidateBearerToken(ctx context.Context, token string) (*session.Session, error) {
	if h.tokenValidator == nil {
		return nil, fmt.Errorf("bearer token validation not available")
	}

	// Try to validate as access token (more lenient)
	claims, err := h.tokenValidator.ValidateAccessToken(ctx, token)
	if err != nil {
		// If access token validation fails, try as ID token
		claims, err = h.tokenValidator.ValidateToken(ctx, token)
		if err != nil {
			return nil, fmt.Errorf("token validation failed: %v", err)
		}
	}

	// Create a session from the token claims
	sess := &session.Session{
		ID:             generateRandomState(), // Generate a unique session ID
		UserID:         claims.Subject,
		Token:          token,
		TokenExpiresAt: time.Unix(claims.ExpiresAt, 0), // Set token expiry from claims
		Claims: map[string]interface{}{
			"email":              claims.Email,
			"email_verified":     claims.EmailVerified,
			"name":               claims.Name,
			"preferred_username": claims.PreferredUsername,
			"given_name":         claims.GivenName,
			"family_name":        claims.FamilyName,
			"iss":                claims.Issuer,
			"aud":                claims.Audience,
			"azp":                claims.AuthorizedParty,
			"scope":              claims.Scopes,
		},
		CreatedAt: time.Now(),
		ExpiresAt: time.Unix(claims.ExpiresAt, 0),
	}

	// Remove nil values from claims
	for k, v := range sess.Claims {
		if v == nil || v == "" {
			delete(sess.Claims, k)
		}
	}

	return sess, nil
}

// ExchangeRefreshToken exchanges a refresh token for an access token with caching
func (h *OAuthHandlerImpl) ExchangeRefreshToken(ctx context.Context, refreshToken string) (string, error) {
	// Create a hash of the refresh token for cache key (don't store the actual token)
	cacheKey := base64.RawURLEncoding.EncodeToString([]byte(refreshToken))[:32] // Use first 32 chars as key

	// Check cache first
	h.cacheMu.RLock()
	if cached, ok := h.refreshTokenCache[cacheKey]; ok {
		// Check if token is still valid (with 1 minute buffer)
		if time.Now().Add(1 * time.Minute).Before(cached.expiry) {
			h.cacheMu.RUnlock()
			h.logger.Debug("Using cached access token for refresh token")
			return cached.accessToken, nil
		}
	}
	h.cacheMu.RUnlock()

	// Use OAuth2 token endpoint to exchange refresh token
	tokenSource := h.oauth2Config.TokenSource(ctx, &oauth2.Token{
		RefreshToken: refreshToken,
	})

	// Get new token (this will use the refresh token to get a new access token)
	token, err := tokenSource.Token()
	if err != nil {
		h.logger.Error("Failed to exchange refresh token for access token",
			zap.Error(err))
		return "", fmt.Errorf("failed to exchange refresh token: %v", err)
	}

	// Cache the token
	h.cacheMu.Lock()
	h.refreshTokenCache[cacheKey] = &tokenCacheEntry{
		accessToken: token.AccessToken,
		expiry:      token.Expiry,
	}
	// Clean up old entries while we have the lock
	for key, entry := range h.refreshTokenCache {
		if time.Now().After(entry.expiry) {
			delete(h.refreshTokenCache, key)
		}
	}
	h.cacheMu.Unlock()

	// Log successful exchange
	h.logger.Debug("Successfully exchanged refresh token for access token",
		zap.String("token_type", token.TokenType),
		zap.Time("expiry", token.Expiry))

	return token.AccessToken, nil
}
