package filter

import (
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/envoyproxy/envoy/contrib/golang/common/go/api"
	"github.com/rashpile/go-envoy-oauth/oauth"
	"github.com/rashpile/go-envoy-oauth/session"
	"go.uber.org/zap"
)

// Session represents a user session
type Session struct {
	ID        string
	UserID    string
	ExpiresAt time.Time
}

// Filter implements the Envoy HTTP filter
type Filter struct {
	config        *OAuthConfig
	oauthHandler  oauth.OAuthHandler
	sessionStore  session.SessionStore
	cookieManager *session.CookieManager
	callbacks     api.FilterCallbackHandler
	logger        *zap.Logger
}

// NewFilter creates a new filter instance
func NewFilter(config *OAuthConfig, callbacks api.FilterCallbackHandler) (*Filter, error) {
	// Create session store and cookie manager
	sessionStore := session.NewInMemorySessionStore()
	hashKey, err := session.GenerateRandomKey(32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate hash key: %v", err)
	}
	blockKey, err := session.GenerateRandomKey(32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate block key: %v", err)
	}

	cookieConfig := &session.CookieConfig{
		Name:     config.SessionCookieName,
		Path:     config.SessionPath,
		Domain:   config.SessionDomain,
		MaxAge:   int(config.SessionMaxAge.Seconds()),
		Secure:   config.SessionSecure,
		HTTPOnly: config.SessionHttpOnly,
		SameSite: convertSameSite(config.SessionSameSite),
	}

	cookieManager, err := session.NewCookieManager(hashKey, blockKey, cookieConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create cookie manager: %v", err)
	}

	// Create OAuth handler
	oauthConfig := &oauth.OIDCConfig{
		IssuerURL:    config.IssuerURL,
		ClientID:     config.ClientID,
		ClientSecret: config.ClientSecret,
		RedirectURL:  config.RedirectURL,
		Scopes:       config.Scopes,
	}

	oauthHandler, err := oauth.NewOAuthHandler(oauthConfig, sessionStore, cookieManager)
	if err != nil {
		return nil, fmt.Errorf("failed to create OAuth handler: %v", err)
	}

	logger := GetLogger()
	logger.Debug("Creating new OAuth filter",
		zap.String("issuer_url", config.IssuerURL),
		zap.String("client_id", config.ClientID),
		zap.String("redirect_url", config.RedirectURL),
		zap.Strings("scopes", config.Scopes),
	)

	return &Filter{
		config:        config,
		oauthHandler:  oauthHandler,
		sessionStore:  sessionStore,
		cookieManager: cookieManager,
		callbacks:     callbacks,
		logger:        logger,
	}, nil
}

// DecodeHeaders is called when request headers are received
func (f *Filter) DecodeHeaders(header api.RequestHeaderMap, endStream bool) api.StatusType {
	method, _ := header.Get(":method")
	path, _ := header.Get(":path")
	host, _ := header.Get(":authority")

	f.logger.Debug("Processing request headers",
		zap.String("method", method),
		zap.String("path", path),
		zap.String("host", host),
	)

	// Get the request path and cluster
	cluster, _ := header.Get(":authority")

	log.Printf("path: %s, cluster: %s", path, cluster)

	// Handle OAuth endpoints
	if strings.HasPrefix(path, "/oauth/") {
		return f.handleOAuthEndpoints(header, path)
	}

	// Check if the path should be excluded
	if f.isPathExcluded(path, cluster) {
		f.logger.Debug("Path is excluded from authentication",
			zap.String("path", path))
		return api.Continue
	}

	// Check for bearer token
	token := f.extractBearerToken(header)
	if token != "" {
		// TODO: Validate bearer token
		return api.Continue
	}

	// Check for session cookie
	sessionID, err := f.cookieManager.GetCookie(header)
	if err == nil {
		session, err := f.sessionStore.Get(sessionID)
		if err == nil {
			// Validate and refresh session if needed
			if err := f.oauthHandler.ValidateSession(session); err == nil {
				// Add user info to headers
				header.Set("X-User-ID", session.UserID)
				f.logger.Debug("Request authenticated successfully",
					zap.String("session_id", session.ID),
					zap.String("user_id", session.UserID))
				return api.Continue
			}
		}
	}

	f.logger.Debug("No valid authentication found, redirecting to login",
		zap.String("path", path))

	// No valid authentication found, redirect to login
	header.Set(":status", "302")
	header.Set("location", "/oauth/login?redirect_uri="+url.QueryEscape(path))
	return api.LocalReply
}

// handleOAuthEndpoints processes OAuth-related endpoints
func (f *Filter) handleOAuthEndpoints(header api.RequestHeaderMap, path string) api.StatusType {
	switch path {
	case "/oauth/login":
		return f.handleLogin(header)
	case "/oauth/callback":
		return f.handleCallback(header)
	case "/oauth/logout":
		return f.handleLogout(header)
	default:
		// Return 404 for unknown OAuth endpoints
		header.Set(":status", "404")
		return api.LocalReply
	}
}

// handleLogin initiates the OAuth flow
func (f *Filter) handleLogin(header api.RequestHeaderMap) api.StatusType {
	f.logger.Debug("Handling login request")
	// Get redirect URI from query parameter
	path, _ := header.Get(":path")
	if idx := strings.Index(path, "?"); idx != -1 {
		query := path[idx+1:]
		values, err := url.ParseQuery(query)
		if err != nil {
			header.Set(":status", "400")
			header.Set("content-type", "text/plain")
			return api.LocalReply
		}
		redirectURI := values.Get("redirect_uri")
		if redirectURI == "" {
			redirectURI = "/"
		}

		// Start OAuth flow
		err = f.oauthHandler.HandleAuthRedirect(header, redirectURI)
		if err != nil {
			header.Set(":status", "500")
			header.Set("content-type", "text/plain")
			return api.LocalReply
		}

		return api.LocalReply
	}

	// If no redirect URI is provided, use the root path
	err := f.oauthHandler.HandleAuthRedirect(header, "/")
	if err != nil {
		header.Set(":status", "500")
		header.Set("content-type", "text/plain")
		return api.LocalReply
	}

	return api.LocalReply
}

// handleCallback processes the OAuth callback
func (f *Filter) handleCallback(header api.RequestHeaderMap) api.StatusType {
	f.logger.Debug("Handling OAuth callback")
	// Get query parameters
	query, _ := header.Get(":path")
	if idx := strings.Index(query, "?"); idx != -1 {
		query = query[idx+1:]
	}

	// Process the callback
	err := f.oauthHandler.HandleCallback(header, query)
	if err != nil {
		header.Set(":status", "400")
		header.Set("content-type", "text/plain")
		return api.LocalReply
	}

	// Redirect to the original URL or home page
	redirectURI := "/"
	if state, _ := header.Get("state"); state != "" {
		// TODO: Validate state and get original URL
		redirectURI = state
	}

	header.Set(":status", "302")
	header.Set("location", redirectURI)
	return api.LocalReply
}

// handleLogout processes user logout
func (f *Filter) handleLogout(header api.RequestHeaderMap) api.StatusType {
	f.logger.Debug("Handling logout request")
	err := f.oauthHandler.HandleLogout(header)
	if err != nil {
		header.Set(":status", "500")
		header.Set("content-type", "text/plain")
		return api.LocalReply
	}

	// Redirect to home page after logout
	header.Set(":status", "302")
	header.Set("location", "/")
	return api.LocalReply
}

// EncodeHeaders is called when response headers are being sent
// This can be used to add cookies to responses after successful auth
func (f *Filter) EncodeHeaders(header api.ResponseHeaderMap, endStream bool) api.StatusType {
	return api.Continue
}

func (f *Filter) isPathExcluded(path, cluster string) bool {
	// Check global exclude paths
	for _, excluded := range f.config.ExcludePaths {
		if path == excluded || strings.HasPrefix(path, excluded) {
			return true
		}
	}

	// Check cluster-specific configuration
	if clusterConfig, ok := f.config.Clusters[cluster]; ok {
		if clusterConfig.Exclude {
			return true
		}
		for _, excluded := range clusterConfig.ExcludePaths {
			if path == excluded || strings.HasPrefix(path, excluded) {
				return true
			}
		}
	}

	return false
}

func (f *Filter) extractBearerToken(header api.RequestHeaderMap) string {
	auth, _ := header.Get("authorization")
	if auth == "" {
		return ""
	}

	parts := strings.Split(auth, " ")
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		return ""
	}

	return parts[1]
}

func (f *Filter) OnLog(reqHeaders api.RequestHeaderMap, reqTrailers api.RequestTrailerMap,
	respHeaders api.ResponseHeaderMap, respTrailers api.ResponseTrailerMap) {
}

func (f *Filter) OnDestroy(reason api.DestroyReason) {
}

// FilterFactory creates a new Filter instance
func FilterFactory(c interface{}, callbacks api.FilterCallbackHandler) api.StreamFilter {
	// The configuration comes as a map[string]interface{}
	config, ok := c.(*OAuthConfig)
	if !ok {
		panic("invalid configuration type: expected OAuthConfig")
	}

	filter, err := NewFilter(config, callbacks)
	if err != nil {
		panic(fmt.Sprintf("failed to create filter: %v", err))
	}

	return filter
}

func convertSameSite(s string) http.SameSite {
	switch strings.ToLower(s) {
	case "lax":
		return http.SameSiteLaxMode
	case "strict":
		return http.SameSiteStrictMode
	case "none":
		return http.SameSiteNoneMode
	default:
		return http.SameSiteDefaultMode
	}
}

// Implement required StreamFilter interface methods
func (f *Filter) DecodeData(buffer api.BufferInstance, endStream bool) api.StatusType {
	return api.Continue
}

func (f *Filter) EncodeData(buffer api.BufferInstance, endStream bool) api.StatusType {
	return api.Continue
}

func (f *Filter) DecodeTrailers(trailers api.RequestTrailerMap) api.StatusType {
	return api.Continue
}

func (f *Filter) EncodeTrailers(trailers api.ResponseTrailerMap) api.StatusType {
	return api.Continue
}

func (f *Filter) OnLogDownstreamPeriodic(reqHeaders api.RequestHeaderMap, reqTrailers api.RequestTrailerMap,
	respHeaders api.ResponseHeaderMap, respTrailers api.ResponseTrailerMap) {
}

func (f *Filter) OnLogDownstreamStart(reqHeaders api.RequestHeaderMap) {
}

func (f *Filter) OnStreamComplete() {
}

func (f *Filter) getSession(headers api.RequestHeaderMap) (*session.Session, error) {
	f.logger.Debug("Attempting to get session from request")
	sessionID, err := f.cookieManager.GetCookie(headers)
	if err != nil {
		return nil, err
	}
	return f.sessionStore.Get(sessionID)
}

func (f *Filter) isValidSession(session *session.Session) bool {
	f.logger.Debug("Validating session",
		zap.String("session_id", session.ID),
		zap.Time("expires_at", session.ExpiresAt))
	return session.ExpiresAt.After(time.Now())
}
