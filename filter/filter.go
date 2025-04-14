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

// handleAuthFailure creates appropriate response for authentication failures
func (f *Filter) handleAuthFailure(statusCode int, message string) api.StatusType {
	headers := createAuthErrorHeaders()

	f.callbacks.DecoderFilterCallbacks().SendLocalReply(
		statusCode,     // responseCode
		message,        // bodyText
		headers,        // headers
		-1,             // grpcStatus
		"auth_failure", // details
	)

	return api.LocalReply
}

// handleAuthSuccess processes a successful authentication
func (f *Filter) handleAuthSuccess(header api.RequestHeaderMap, session *session.Session) api.StatusType {
	traceID := f.getTraceID(header)

	// Add user info to headers for downstream services
	header.Set("X-User-ID", session.UserID)
	f.logger.Debug("Request authenticated successfully",
		zap.String("session_id", session.ID),
		zap.String("user_id", session.UserID),
		zap.String("trace_id", traceID))

	// Authentication successful, continue the filter chain
	return api.Continue
}

// createAuthErrorHeaders creates standard headers for authentication errors
func createAuthErrorHeaders() map[string][]string {
	headers := make(map[string][]string)
	headers["content-type"] = []string{"text/plain"}
	headers["www-authenticate"] = []string{"Bearer"}
	return headers
}

// handleRedirect creates a redirect response using SendLocalReply
func (f *Filter) handleRedirect(url string, cookieValue string) api.StatusType {
	headers := map[string][]string{
		"Location":     {url},
		"Content-Type": {"text/html"},
	}
	if cookieValue != "" {
		headers["Set-Cookie"] = []string{cookieValue}
	}

	f.callbacks.DecoderFilterCallbacks().SendLocalReply(
		http.StatusFound, // 302
		"",               // empty body
		headers,
		0,  // no grpc status
		"", // no details
	)

	return api.LocalReply
}

// getTraceID extracts the trace ID from the request headers
func (f *Filter) getTraceID(header api.RequestHeaderMap) string {
	traceID, _ := header.Get("x-b3-traceid")
	if traceID == "" {
		traceID, _ = header.Get("x-request-id")
	}
	return traceID
}

// DecodeHeaders is called when request headers are received
func (f *Filter) DecodeHeaders(header api.RequestHeaderMap, endStream bool) api.StatusType {
	method, _ := header.Get(":method")
	path, _ := header.Get(":path")
	host, _ := header.Get(":authority")
	traceID := f.getTraceID(header)

	f.logger.Debug("Processing request headers",
		zap.String("method", method),
		zap.String("path", path),
		zap.String("host", host),
		zap.String("trace_id", traceID),
	)

	// Get the request path and cluster
	cluster, _ := header.Get(":authority")

	log.Printf("path: %s, cluster: %s, trace_id: %s", path, cluster, traceID)

	// Handle OAuth endpoints
	if strings.HasPrefix(path, "/oauth/") {
		return f.handleOAuthEndpoints(header, path)
	}

	// Check if the path should be excluded
	if f.isPathExcluded(path, cluster) {
		f.logger.Debug("Path is excluded from authentication",
			zap.String("path", path),
			zap.String("trace_id", traceID))
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
	if err != nil {
		f.logger.Debug("No session cookie found, redirecting to login",
			zap.String("path", path),
			zap.String("trace_id", traceID))
		// Redirect to login with the current path as redirect_uri
		return f.handleRedirect("/oauth/login?redirect_uri="+url.QueryEscape(path), "")
	}

	session, err := f.sessionStore.Get(sessionID)
	if err != nil {
		f.logger.Debug("Invalid session ID, redirecting to login",
			zap.String("session_id", sessionID),
			zap.String("trace_id", traceID),
			zap.Error(err))
		// Redirect to login with the current path as redirect_uri
		return f.handleRedirect("/oauth/login?redirect_uri="+url.QueryEscape(path), "")
	}

	// Validate and refresh session if needed
	if err := f.oauthHandler.ValidateSession(session); err != nil {
		f.logger.Debug("Session validation failed, redirecting to login",
			zap.String("session_id", session.ID),
			zap.String("trace_id", traceID),
			zap.Error(err))
		// Redirect to login with the current path as redirect_uri
		return f.handleRedirect("/oauth/login?redirect_uri="+url.QueryEscape(path), "")
	}

	return f.handleAuthSuccess(header, session)
}

// handleOAuthEndpoints processes OAuth-related endpoints
func (f *Filter) handleOAuthEndpoints(header api.RequestHeaderMap, path string) api.StatusType {
	// Extract the base path without query parameters
	basePath := path
	if idx := strings.Index(path, "?"); idx != -1 {
		basePath = path[:idx]
	}

	traceID := f.getTraceID(header)

	f.logger.Debug("Handling OAuth endpoint",
		zap.String("base_path", basePath),
		zap.String("full_path", path),
		zap.String("trace_id", traceID))

	switch basePath {
	case "/oauth/login":
		return f.handleLogin(header)
	case "/oauth/callback":
		return f.handleCallback(header)
	case "/oauth/logout":
		return f.handleLogout(header)
	default:
		return f.handleAuthFailure(404, "Not Found: Unknown OAuth endpoint")
	}
}

// handleLogin initiates the OAuth flow
func (f *Filter) handleLogin(header api.RequestHeaderMap) api.StatusType {
	traceID := f.getTraceID(header)

	f.logger.Debug("Handling login request",
		zap.String("trace_id", traceID))
	// Get redirect URI from query parameter
	path, _ := header.Get(":path")
	values, err := url.ParseQuery(path[strings.Index(path, "?")+1:])
	if err != nil {
		return f.handleAuthFailure(400, "Bad Request: Invalid query parameters")
	}

	redirectURI := values.Get("redirect_uri")
	if redirectURI == "" {
		redirectURI = "/"
	}

	// Start OAuth flow
	err = f.oauthHandler.HandleAuthRedirect(header, redirectURI)
	if err != nil {
		f.logger.Error("Failed to handle auth redirect",
			zap.String("trace_id", traceID),
			zap.Error(err))
		return f.handleAuthFailure(500, "Internal Server Error: Failed to initiate OAuth flow")
	}

	// Get the authorization URL from the location header
	authURL, _ := header.Get("location")
	if authURL == "" {
		return f.handleAuthFailure(500, "Internal Server Error: No authorization URL generated")
	}

	return f.handleRedirect(authURL, "")
}

// handleCallback processes the OAuth callback
func (f *Filter) handleCallback(header api.RequestHeaderMap) api.StatusType {
	traceID := f.getTraceID(header)

	f.logger.Debug("Handling OAuth callback",
		zap.String("trace_id", traceID))
	// Get query parameters
	path, _ := header.Get(":path")
	query := path[strings.Index(path, "?")+1:]

	// Process the callback
	err := f.oauthHandler.HandleCallback(header, query)
	if err != nil {
		f.logger.Error("Failed to handle OAuth callback",
			zap.String("trace_id", traceID),
			zap.Error(err))
		return f.handleAuthFailure(400, "Bad Request: Invalid OAuth callback")
	}

	// Redirect to the original URL or home page
	redirectURI := "/"
	if state, _ := header.Get("state"); state != "" {
		// TODO: Validate state and get original URL
		redirectURI = state
	}

	return f.handleRedirect(redirectURI, "")
}

// handleLogout processes user logout
func (f *Filter) handleLogout(header api.RequestHeaderMap) api.StatusType {
	traceID := f.getTraceID(header)

	f.logger.Debug("Handling logout request",
		zap.String("trace_id", traceID))
	err := f.oauthHandler.HandleLogout(header)
	if err != nil {
		f.logger.Error("Failed to handle logout",
			zap.String("trace_id", traceID),
			zap.Error(err))
		return f.handleAuthFailure(500, "Internal Server Error: Failed to process logout")
	}

	return f.handleRedirect("/", "")
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
