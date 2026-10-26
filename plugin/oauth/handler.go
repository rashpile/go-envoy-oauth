package oauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/envoyproxy/envoy/contrib/golang/common/go/api"
	"github.com/rashpile/go-envoy-oauth/plugin/metrics"
	"github.com/rashpile/go-envoy-oauth/plugin/session"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
	"golang.org/x/sync/singleflight"
)

// normalizeIssuer strips trailing slashes and lowercases an issuer URL for
// case-insensitive, slash-tolerant comparison (D-03).
func normalizeIssuer(s string) string {
	return strings.ToLower(strings.TrimRight(s, "/"))
}

// extractIssuerFromJWT extracts the iss claim from a JWT's payload segment
// without performing signature validation. Returns empty string on any error.
// Full signature validation is done separately via TokenValidator.
func extractIssuerFromJWT(tokenStr string) string {
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return ""
	}
	// Add padding if needed
	payload := parts[1]
	switch len(payload) % 4 {
	case 2:
		payload += "=="
	case 3:
		payload += "="
	}
	decoded, err := base64.URLEncoding.DecodeString(payload)
	if err != nil {
		// Try raw URL encoding (no padding)
		decoded, err = base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			return ""
		}
	}
	var claims struct {
		Iss string `json:"iss"`
	}
	if err := json.Unmarshal(decoded, &claims); err != nil {
		return ""
	}
	return claims.Iss
}

// OIDCConfig represents the OpenID Connect configuration
type OIDCConfig struct {
	ProviderName string // Named provider identifier (used by ProviderRegistry)
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
	// ValidateBearerTokenForResource validates a token whose aud must contain resource.
	ValidateBearerTokenForResource(ctx context.Context, token, resource string) (*session.Session, error)
	ExchangeRefreshToken(ctx context.Context, refreshToken string) (string, error)
	GetSessionCookie(header api.RequestHeaderMap) (string, error)
	DeleteSessionCookie(header api.RequestHeaderMap)
	SetSessionCookie(header api.RequestHeaderMap, value string) error
	FormatSessionCookie(value string) string
	// HealthState returns the current health state of the provider (D-07).
	// Ready/Degraded continue serving; Down requests MUST receive 503 (D-03).
	HealthState() ProviderState
}

type tokenCacheEntry struct {
	accessToken string
	expiry      time.Time
}

type OAuthHandlerImpl struct {
	config            *OIDCConfig
	providerName      string // named provider identifier from OIDCConfig.ProviderName
	provider          *OIDCProvider
	oauth2Config      *oauth2.Config
	sessionStore      session.SessionStore
	cookieManager     *session.CookieManager
	tokenValidator    *TokenValidator
	refreshTokenCache map[string]*tokenCacheEntry // maps refresh token hash -> access token
	cacheMu           sync.RWMutex
	// sessionRefresh makes concurrent refreshes of one session share a single
	// token request, so a rotating refresh token is not sent twice.
	sessionRefresh singleflight.Group
	mu             sync.RWMutex
	logger         *zap.Logger
	// Phase 5 (HLTH-02): health state machine. Writes are refresher-only (D-06).
	healthState  atomic.Int32 // holds ProviderState; default 0 == StateReady
	jwksFailures int          // consecutive refresh failure count; written by refresher goroutine only
	jwksStaleAt  time.Time    // time of first failure that moved state out of ready; refresher-only
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

	// Fallback when ProviderName is not supplied (defensive — parser.go sets
	// "default" for the legacy single-provider path). Without this the idp
	// metric label would collapse to "" and silently break dashboards. Using
	// "default" instead of the issuer hostname keeps the label format stable
	// after the Phase 04 switch to registry-key labels (OBS-01).
	providerName := config.ProviderName
	if providerName == "" {
		providerName = "default"
	}

	metrics.UpdateIDPState(providerName, StateReady.String())
	return &OAuthHandlerImpl{
		config:            config,
		providerName:      providerName,
		provider:          provider,
		oauth2Config:      oauth2Config,
		sessionStore:      sessionStore,
		cookieManager:     cookieManager,
		tokenValidator:    tokenValidator,
		refreshTokenCache: make(map[string]*tokenCacheEntry),
		logger:            logger,
	}, nil
}

// requestHost returns the host the request was routed by. X-Forwarded-Host is
// ignored: Envoy is the gateway, so that header can only come from the client,
// and it must not decide where an authorization code is sent (issue #12).
func requestHost(header api.RequestHeaderMap) string {
	if host, _ := header.Get(":authority"); host != "" {
		return host
	}
	host, _ := header.Get("host")
	return host
}

// GetAbsoluteRedirectURL returns an absolute redirect URL based on the request headers
func (h *OAuthHandlerImpl) GetAbsoluteRedirectURL(header api.RequestHeaderMap) string {
	host := requestHost(header)

	// Ensure the redirect URL is absolute and properly formatted
	redirectURL := h.getOAuth2Config().RedirectURL
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
	base := h.getOAuth2Config()
	return &oauth2.Config{
		ClientID:     base.ClientID,
		ClientSecret: base.ClientSecret,
		RedirectURL:  redirectURL,
		Scopes:       base.Scopes,
		Endpoint:     base.Endpoint,
	}
}

// StateBindingHeader carries the browser-binding secret from the OAuth handler
// to the filter, which turns it into the state cookie. Like "location" and
// "set-cookie", it is written to the request header map and never forwarded:
// the login and offline redirects end in a local reply.
const StateBindingHeader = "x-oauth-state-binding"

func (h *OAuthHandlerImpl) HandleAuthRedirect(header api.RequestHeaderMap, redirectURI string) error {
	// Generate a pure random nonce as the OAuth state parameter (D-01).
	// All context (provider, path, PKCE verifier) is stored server-side.
	nonce := generateRandomState()

	// Generate PKCE code verifier and compute S256 challenge (D-04, D-05).
	verifier := oauth2.GenerateVerifier()

	// Browser-binding secret for the state cookie; only its hash is stored (issue #11).
	bindingSecret, bindingHash, err := session.NewStateBinding()
	if err != nil {
		return err
	}

	// Store server-side pending-auth entry mapping nonce -> {provider, path, verifier} (D-01, D-02, D-05).
	pa := &session.PendingAuth{
		ProviderName: h.providerName,
		OriginalPath: redirectURI,
		CodeVerifier: verifier,
		BindingHash:  bindingHash,
		Expiry:       time.Now().Add(5 * time.Minute),
	}
	if err := session.StorePendingAuth(h.sessionStore, nonce, pa); err != nil {
		return fmt.Errorf("failed to store pending auth state: %v", err)
	}

	// Build authorization URL with PKCE S256 challenge (D-04).
	oauth2Config := h.GetOAuthConfig(header)
	authURL := oauth2Config.AuthCodeURL(nonce, oauth2.S256ChallengeOption(verifier))
	header.Set("location", authURL)
	header.Set(StateBindingHeader, bindingSecret)
	return nil
}

func (h *OAuthHandlerImpl) HandleCallback(header api.RequestHeaderMap, query string) error {
	// Extract IDP name for metrics
	idp := h.providerName

	// Start timing for callback duration metric
	startTime := time.Now()

	values, err := url.ParseQuery(query)
	if err != nil {
		metrics.RecordLogin(idp, "failure", "invalid_query")
		metrics.RecordCallbackDuration(idp, time.Since(startTime).Seconds())
		return err
	}

	// Get the raw state parameter (nonce only — per D-01, no "|" splitting).
	nonce := values.Get("state")
	if nonce == "" {
		metrics.RecordLogin(idp, "failure", "invalid_state")
		metrics.RecordCallbackDuration(idp, time.Since(startTime).Seconds())
		return fmt.Errorf("state parameter not found")
	}

	// Retrieve and delete pending-auth entry (single-use per D-01).
	// GetPendingAuth handles expiry validation, sentinel check, and deletion.
	pa, err := session.GetPendingAuth(h.sessionStore, nonce)
	if err != nil {
		metrics.RecordLogin(idp, "failure", "invalid_state")
		metrics.RecordCallbackDuration(idp, time.Since(startTime).Seconds())
		return fmt.Errorf("invalid or expired state parameter: %w", err)
	}
	originalPath := pa.OriginalPath

	code := values.Get("code")
	if code == "" {
		metrics.RecordLogin(idp, "failure", "missing_code")
		metrics.RecordCallbackDuration(idp, time.Since(startTime).Seconds())
		return fmt.Errorf("authorization code not found")
	}

	// Exchange code with PKCE verifier (D-04, D-05).
	oauth2Config := h.GetOAuthConfig(header)
	token, err := oauth2Config.Exchange(context.Background(), code, oauth2.VerifierOption(pa.CodeVerifier))
	if err != nil {
		metrics.RecordLogin(idp, "failure", metrics.ClassifyLoginError(err))
		metrics.RecordCallbackDuration(idp, time.Since(startTime).Seconds())
		return err
	}

	// Validate issuer from ID token (D-03, AUTH-03).
	// The issuer check is mandatory for OIDC flows — reject if id_token is absent.
	idTokenRaw, hasIDToken := token.Extra("id_token").(string)
	if !hasIDToken || idTokenRaw == "" {
		metrics.RecordLogin(idp, "failure", "invalid_token")
		metrics.RecordCallbackDuration(idp, time.Since(startTime).Seconds())
		return fmt.Errorf("token response missing id_token for provider %q — issuer cannot be verified", h.config.ProviderName)
	}
	iss := extractIssuerFromJWT(idTokenRaw)
	if iss == "" {
		metrics.RecordLogin(idp, "failure", "invalid_token")
		metrics.RecordCallbackDuration(idp, time.Since(startTime).Seconds())
		return fmt.Errorf("failed to extract issuer from id_token for provider %q", h.config.ProviderName)
	}
	p := h.getProvider()
	if normalizeIssuer(iss) != normalizeIssuer(p.Issuer) {
		metrics.RecordLogin(idp, "failure", "invalid_token")
		metrics.RecordCallbackDuration(idp, time.Since(startTime).Seconds())
		return fmt.Errorf("issuer mismatch: token issuer %q does not match provider issuer %q", iss, p.Issuer)
	}

	userInfo, err := h.getUserInfo(token.AccessToken)
	if err != nil {
		metrics.RecordLogin(idp, "failure", "idp_error")
		metrics.RecordCallbackDuration(idp, time.Since(startTime).Seconds())
		return err
	}

	sub, ok := userInfo["sub"].(string)
	if !ok {
		metrics.RecordLogin(idp, "failure", "invalid_token")
		metrics.RecordCallbackDuration(idp, time.Since(startTime).Seconds())
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
		IDP:            idp,                // Identity provider for metrics
		ProviderName:   h.providerName,     // Named provider registry key (SESS-02 verification)
		Claims:         userInfo,
		CreatedAt:      time.Now(),
		ExpiresAt:      time.Now().Add(24 * time.Hour), // Session expires in 24 hours
	}
	if err := h.sessionStore.Store(session); err != nil {
		metrics.RecordLogin(idp, "failure", "unknown")
		metrics.RecordCallbackDuration(idp, time.Since(startTime).Seconds())
		return err
	}

	// Record successful login and session creation
	metrics.RecordLogin(idp, "success", "")
	metrics.RecordSessionCreated(idp)

	if err := h.cookieManager.SetCookie(header, session.ID); err != nil {
		metrics.RecordCallbackDuration(idp, time.Since(startTime).Seconds())
		return err
	}

	// Record callback duration on success path
	metrics.RecordCallbackDuration(idp, time.Since(startTime).Seconds())

	// Set the original request path in the location header
	header.Set("location", originalPath)
	return nil
}

func (h *OAuthHandlerImpl) HandleLogout(header api.RequestHeaderMap) (string, error) {
	// Extract IDP name for metrics
	idp := h.providerName

	provider := h.getProvider()
	h.logger.Debug("HandleLogout started",
		zap.String("provider_issuer", provider.Issuer),
		zap.String("end_session_endpoint", provider.EndSessionEndpoint),
		zap.Bool("has_end_session", provider.EndSessionEndpoint != ""))

	sessionID, err := h.cookieManager.GetCookie(header)
	if err != nil {
		h.logger.Debug("No session cookie found", zap.Error(err))
		// No cookie means user is effectively logged out already - success
		metrics.RecordLogout(idp, "success", "")
		return "", err
	}

	// Get the session to retrieve ID token for logout
	sess, err := h.sessionStore.Get(sessionID)
	if err != nil {
		// Session not found, just clear the cookie
		h.logger.Debug("Session not found, clearing cookie", zap.Error(err))
		h.cookieManager.DeleteCookie(header)
		// Session already gone - logout is effectively successful
		metrics.RecordLogout(idp, "success", "")
		return "/", nil
	}

	h.logger.Debug("Session found for logout",
		zap.String("user_id", sess.UserID),
		zap.Bool("has_id_token", sess.IDToken != ""))

	// Delete the session from store
	if err := h.sessionStore.Delete(sessionID); err != nil {
		metrics.RecordLogout(idp, "failure", "session_not_found")
		return "", err
	}

	// Clear the cookie
	h.cookieManager.DeleteCookie(header)

	// Record successful logout and session ended
	metrics.RecordSessionEnded(idp, "logout")
	metrics.RecordLogout(idp, "success", "")

	// If IDP supports end_session_endpoint, redirect to it
	if provider.EndSessionEndpoint != "" {
		// Build the logout URL with required parameters
		logoutURL, err := url.Parse(provider.EndSessionEndpoint)
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
			zap.String("endpoint", provider.EndSessionEndpoint),
			zap.Bool("has_id_token", sess.IDToken != ""),
			zap.String("post_logout_redirect", postLogoutRedirectURI))

		return logoutURL.String(), nil
	}

	// No IDP logout endpoint, just redirect to home
	h.logger.Debug("IDP does not support end_session_endpoint, performing local logout only")
	return "/", nil
}

// GetSessionCookie reads the provider-namespaced session cookie value from the
// request header using this handler's CookieManager. Filter code resolves the
// correct handler via cluster config (D-06) before calling this, so the cookie
// name is always the one owned by this provider (D-09).
func (h *OAuthHandlerImpl) GetSessionCookie(header api.RequestHeaderMap) (string, error) {
	return h.cookieManager.GetCookie(header)
}

// DeleteSessionCookie clears the provider-namespaced session cookie on the
// response using this handler's CookieManager. Called by the filter on
// provider-mismatch (D-05) to evict the attacker-origin cookie using the
// correct cookie name — Pitfall 3 in 03-RESEARCH.md.
func (h *OAuthHandlerImpl) DeleteSessionCookie(header api.RequestHeaderMap) {
	h.cookieManager.DeleteCookie(header)
}

// SetSessionCookie writes a Set-Cookie header whose Name is this handler's
// provider-namespaced cookie name (D-09). Delegates to the per-provider CookieManager.
func (h *OAuthHandlerImpl) SetSessionCookie(header api.RequestHeaderMap, value string) error {
	return h.cookieManager.SetCookie(header, value)
}

// FormatSessionCookie returns a pre-formatted cookie string (name=value; attrs...)
// for this handler's provider-namespaced cookie name. Used by the filter to
// attach cookies onto redirect responses.
func (h *OAuthHandlerImpl) FormatSessionCookie(value string) string {
	return h.cookieManager.FormatCookie(value)
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
	req, err := http.NewRequest("GET", h.getProvider().UserInfoEndpoint, nil)
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
						host := requestHost(header)

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
	host := requestHost(header)

	// Determine the scheme
	scheme := "http"
	if forwardedProto, _ := header.Get("x-forwarded-proto"); forwardedProto == "https" {
		scheme = "https"
	}

	// Return the welcome page URL
	return fmt.Sprintf("%s://%s/oauth/welcome", scheme, host)
}

// RefreshToken attempts to refresh an expired access token
// tokenRefreshTimeout bounds a session token refresh (same as the userinfo client).
var tokenRefreshTimeout = 10 * time.Second

// RefreshToken refreshes the session's access token. Concurrent calls for the
// same session share one token request; a call that finds the stored session
// already refreshed by another request reuses that result.
func (h *OAuthHandlerImpl) RefreshToken(sess *session.Session) error {
	if sess.ID == "" {
		_, err := h.refreshAndStore(sess)
		return err
	}
	v, err, _ := h.sessionRefresh.Do(sess.ID, func() (interface{}, error) {
		current := sess
		if stored, getErr := h.sessionStore.Get(sess.ID); getErr == nil {
			if !h.IsNeedValidateSession(stored) {
				return stored, nil // refreshed meanwhile
			}
			current = stored
		}
		return h.refreshAndStore(current)
	})
	if err != nil {
		return err
	}
	fresh := v.(*session.Session)
	sess.Token = fresh.Token
	sess.TokenExpiresAt = fresh.TokenExpiresAt
	sess.RefreshToken = fresh.RefreshToken
	return nil
}

// refreshAndStore exchanges the refresh token of a copy of sess, stores the
// copy and returns it.
func (h *OAuthHandlerImpl) refreshAndStore(sess *session.Session) (*session.Session, error) {
	if sess.RefreshToken == "" {
		return nil, fmt.Errorf("no refresh token available")
	}

	// Extract IDP name for metrics
	idp := h.providerName

	h.logger.Debug("Refreshing access token",
		zap.String("session_id", sess.ID),
		zap.Time("token_expires_at", sess.TokenExpiresAt))

	// Get new token using refresh token. The deadline matters: concurrent
	// requests for this session wait on this call (singleflight).
	ctx, cancel := context.WithTimeout(context.Background(), tokenRefreshTimeout)
	defer cancel()
	token, err := h.getOAuth2Config().TokenSource(ctx, &oauth2.Token{
		RefreshToken: sess.RefreshToken,
	}).Token()
	if err != nil {
		h.logger.Error("Failed to refresh access token", zap.Error(err))
		metrics.RecordTokenRefresh(idp, "failure")
		return nil, fmt.Errorf("failed to refresh token: %v", err)
	}

	updated := *sess
	updated.Token = token.AccessToken
	updated.TokenExpiresAt = token.Expiry
	// Update refresh token if a new one was issued
	if token.RefreshToken != "" {
		updated.RefreshToken = token.RefreshToken
	}

	h.logger.Debug("Access token refreshed successfully",
		zap.String("session_id", updated.ID),
		zap.Time("new_expiry", token.Expiry))

	metrics.RecordTokenRefresh(idp, "success")

	if err := h.sessionStore.Store(&updated); err != nil {
		return nil, err
	}
	return &updated, nil
}

// GetSessionStore returns the session store
func (h *OAuthHandlerImpl) GetSessionStore() session.SessionStore {
	return h.sessionStore
}

// ValidateBearerToken validates a bearer token and returns a session
func (h *OAuthHandlerImpl) ValidateBearerToken(ctx context.Context, token string) (*session.Session, error) {
	tv := h.getTokenValidator()
	if tv == nil {
		// Configuration issue - don't record metrics
		return nil, fmt.Errorf("bearer token validation not available")
	}

	// Extract IDP name for metrics
	idp := h.providerName

	// Try to validate as access token (more lenient)
	claims, err := tv.ValidateAccessToken(ctx, token)
	if err != nil {
		// If access token validation fails, try as ID token
		claims, err = tv.ValidateToken(ctx, token)
		if err != nil {
			metrics.RecordTokenValidation(idp, "invalid")
			return nil, fmt.Errorf("token validation failed: %v", err)
		}
	}

	// Token validated successfully
	metrics.RecordTokenValidation(idp, "valid")

	return h.sessionFromClaims(claims, token), nil
}

// ValidateBearerTokenForResource validates a bearer token for an OAuth
// protected resource: aud must contain resource, and the token may be issued
// to any client of the realm (issue #7).
func (h *OAuthHandlerImpl) ValidateBearerTokenForResource(ctx context.Context, token, resource string) (*session.Session, error) {
	tv := h.getTokenValidator()
	if tv == nil {
		// Configuration issue - don't record metrics
		return nil, fmt.Errorf("bearer token validation not available")
	}

	claims, err := tv.ValidateTokenForAudience(ctx, token, resource)
	if err != nil {
		metrics.RecordTokenValidation(h.providerName, "invalid")
		return nil, fmt.Errorf("token validation failed: %v", err)
	}
	metrics.RecordTokenValidation(h.providerName, "valid")

	return h.sessionFromClaims(claims, token), nil
}

// sessionFromClaims builds a request-scoped session from validated token claims.
func (h *OAuthHandlerImpl) sessionFromClaims(claims *TokenClaims, token string) *session.Session {
	// Create a session from the token claims
	sess := &session.Session{
		ID:             generateRandomState(), // Generate a unique session ID
		UserID:         claims.Subject,
		Token:          token,
		TokenExpiresAt: time.Unix(claims.ExpiresAt, 0), // Set token expiry from claims
		IDP:            metrics.GetIDPName(h.config.IssuerURL),
		ProviderName:   h.providerName, // Named provider registry key (SESS-02 verification)
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

	return sess
}

// refreshTokenCacheKey hashes the whole refresh token. A prefix is not enough:
// JWT refresh tokens from one realm share their header, so prefix keys collide
// across users (issue #8).
func refreshTokenCacheKey(refreshToken string) string {
	sum := sha256.Sum256([]byte(refreshToken))
	return hex.EncodeToString(sum[:])
}

// ExchangeRefreshToken exchanges a refresh token for an access token with caching
func (h *OAuthHandlerImpl) ExchangeRefreshToken(ctx context.Context, refreshToken string) (string, error) {
	cacheKey := refreshTokenCacheKey(refreshToken)

	// Check cache first
	h.cacheMu.RLock()
	if cached, ok := h.refreshTokenCache[cacheKey]; ok {
		// Check if token is still valid (with 1 minute buffer)
		if time.Now().Add(1 * time.Minute).Before(cached.expiry) {
			h.cacheMu.RUnlock()
			h.logger.Debug("Using cached access token for refresh token")
			// Cache hit - no IDP call made, don't record metrics
			return cached.accessToken, nil
		}
	}
	h.cacheMu.RUnlock()

	// Extract IDP name for metrics (only recorded for actual IDP calls)
	idp := h.providerName

	// Use OAuth2 token endpoint to exchange refresh token
	tokenSource := h.getOAuth2Config().TokenSource(ctx, &oauth2.Token{
		RefreshToken: refreshToken,
	})

	// Get new token (this will use the refresh token to get a new access token)
	token, err := tokenSource.Token()
	if err != nil {
		h.logger.Error("Failed to exchange refresh token for access token",
			zap.Error(err))
		metrics.RecordTokenRefresh(idp, "failure")
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

	metrics.RecordTokenRefresh(idp, "success")

	return token.AccessToken, nil
}

// Compile-time check: OAuthHandlerImpl must implement OAuthHandler (incl. HealthState).
var _ OAuthHandler = (*OAuthHandlerImpl)(nil)
