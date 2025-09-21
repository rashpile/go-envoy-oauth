package oauth

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

// TokenValidator validates JWT bearer tokens using OIDC discovery
type TokenValidator struct {
	provider     *oidc.Provider
	verifier     *oidc.IDTokenVerifier
	issuerURL    string
	clientID     string
	logger       *zap.Logger
	mu           sync.RWMutex
	lastRefresh  time.Time
	refreshAfter time.Duration
}

// TokenClaims represents the claims extracted from a validated token
type TokenClaims struct {
	Subject         string                 `json:"sub"`
	Email           string                 `json:"email"`
	EmailVerified   bool                   `json:"email_verified"`
	Name            string                 `json:"name"`
	PreferredUsername string               `json:"preferred_username"`
	GivenName       string                 `json:"given_name"`
	FamilyName      string                 `json:"family_name"`
	Audience        []string               `json:"aud"`
	Issuer          string                 `json:"iss"`
	IssuedAt        int64                  `json:"iat"`
	ExpiresAt       int64                  `json:"exp"`
	Nonce           string                 `json:"nonce"`
	AuthorizedParty string                 `json:"azp"`
	SessionState    string                 `json:"session_state"`
	Scopes          string                 `json:"scope"`
	Extra           map[string]interface{} `json:"-"`
}

// NewTokenValidator creates a new token validator
func NewTokenValidator(issuerURL, clientID string, logger *zap.Logger) (*TokenValidator, error) {
	ctx := context.Background()

	// Create OIDC provider which handles discovery
	provider, err := oidc.NewProvider(ctx, issuerURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create OIDC provider: %v", err)
	}

	// Create a verifier with the provider and client ID
	verifier := provider.Verifier(&oidc.Config{
		ClientID: clientID,
		// We'll accept tokens with our client ID in the audience
		// Some providers put client ID in 'azp' claim for access tokens
		SkipClientIDCheck: false,
	})

	return &TokenValidator{
		provider:     provider,
		verifier:     verifier,
		issuerURL:    issuerURL,
		clientID:     clientID,
		logger:       logger,
		lastRefresh:  time.Now(),
		refreshAfter: 24 * time.Hour, // Refresh provider every 24 hours
	}, nil
}

// ValidateToken validates a JWT bearer token and returns the claims
func (v *TokenValidator) ValidateToken(ctx context.Context, token string) (*TokenClaims, error) {
	// Check if we need to refresh the provider (for key rotation)
	v.checkRefresh(ctx)

	// Verify the token
	idToken, err := v.verifier.Verify(ctx, token)
	if err != nil {
		v.logger.Debug("Token verification failed", zap.Error(err))
		return nil, fmt.Errorf("token verification failed: %v", err)
	}

	// Extract claims
	claims := &TokenClaims{
		Extra: make(map[string]interface{}),
	}

	// Parse standard claims
	if err := idToken.Claims(claims); err != nil {
		return nil, fmt.Errorf("failed to parse token claims: %v", err)
	}

	// Set basic fields from idToken
	claims.Subject = idToken.Subject
	claims.Issuer = idToken.Issuer
	claims.IssuedAt = idToken.IssuedAt.Unix()
	claims.ExpiresAt = idToken.Expiry.Unix()

	// Handle audience claim - it might be a string or []string
	if idToken.Audience != nil {
		claims.Audience = idToken.Audience
	}

	v.logger.Debug("Token validated successfully",
		zap.String("subject", claims.Subject),
		zap.String("email", claims.Email),
		zap.String("preferred_username", claims.PreferredUsername),
		zap.Int64("expires_at", claims.ExpiresAt))

	return claims, nil
}

// ValidateAccessToken validates an access token (which might not have all ID token claims)
func (v *TokenValidator) ValidateAccessToken(ctx context.Context, token string) (*TokenClaims, error) {
	// For access tokens, we need to be more lenient as they might not have all claims
	// Try to validate as ID token first
	claims, err := v.ValidateToken(ctx, token)
	if err == nil {
		return claims, nil
	}

	// If that fails, try to validate with more lenient settings
	// Create a verifier that skips some checks for access tokens
	accessTokenVerifier := v.provider.Verifier(&oidc.Config{
		ClientID:          v.clientID,
		SkipClientIDCheck: true, // Access tokens might not have client_id in aud
		SkipExpiryCheck:   false,
	})

	// Verify the token
	idToken, err := accessTokenVerifier.Verify(ctx, token)
	if err != nil {
		v.logger.Debug("Access token verification failed", zap.Error(err))
		return nil, fmt.Errorf("access token verification failed: %v", err)
	}

	// Extract claims with lenient parsing
	claims = &TokenClaims{
		Extra: make(map[string]interface{}),
	}

	// Try to parse claims, but don't fail if some are missing
	_ = idToken.Claims(claims)

	// Set basic fields
	claims.Subject = idToken.Subject
	claims.Issuer = idToken.Issuer
	if !idToken.IssuedAt.IsZero() {
		claims.IssuedAt = idToken.IssuedAt.Unix()
	}
	if !idToken.Expiry.IsZero() {
		claims.ExpiresAt = idToken.Expiry.Unix()
	}
	if idToken.Audience != nil {
		claims.Audience = idToken.Audience
	}

	// If subject is empty, this might be an opaque token
	if claims.Subject == "" {
		return nil, fmt.Errorf("token does not contain subject claim, might be an opaque token")
	}

	v.logger.Debug("Access token validated successfully",
		zap.String("subject", claims.Subject),
		zap.String("issuer", claims.Issuer),
		zap.Int64("expires_at", claims.ExpiresAt))

	return claims, nil
}

// checkRefresh checks if the provider needs to be refreshed for key rotation
func (v *TokenValidator) checkRefresh(ctx context.Context) {
	v.mu.RLock()
	needsRefresh := time.Since(v.lastRefresh) > v.refreshAfter
	v.mu.RUnlock()

	if !needsRefresh {
		return
	}

	v.mu.Lock()
	defer v.mu.Unlock()

	// Double-check after acquiring write lock
	if time.Since(v.lastRefresh) <= v.refreshAfter {
		return
	}

	// Try to refresh the provider (this will refresh JWKS)
	provider, err := oidc.NewProvider(ctx, v.issuerURL)
	if err != nil {
		v.logger.Error("Failed to refresh OIDC provider", zap.Error(err))
		return
	}

	v.provider = provider
	v.verifier = provider.Verifier(&oidc.Config{
		ClientID:          v.clientID,
		SkipClientIDCheck: false,
	})
	v.lastRefresh = time.Now()

	v.logger.Info("OIDC provider refreshed successfully")
}

// GetUserInfo fetches additional user information using the access token
func (v *TokenValidator) GetUserInfo(ctx context.Context, accessToken string) (map[string]interface{}, error) {
	userInfo, err := v.provider.UserInfo(ctx, oauth2StaticTokenSource(accessToken))
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %v", err)
	}

	var claims map[string]interface{}
	if err := userInfo.Claims(&claims); err != nil {
		return nil, fmt.Errorf("failed to parse user info claims: %v", err)
	}

	return claims, nil
}

// oauth2StaticTokenSource creates a static token source for the UserInfo endpoint
func oauth2StaticTokenSource(accessToken string) oauth2.TokenSource {
	return oauth2.StaticTokenSource(&oauth2.Token{
		AccessToken: accessToken,
	})
}

// Close cleans up any resources (for future use)
func (v *TokenValidator) Close() {
	// Currently no resources to clean up
	// This is here for future extensions (e.g., if we add connection pools)
}