package filter

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
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
	mu            sync.Mutex
}

// NewFilter creates a new filter instance
func NewFilter(config *OAuthConfig, callbacks api.FilterCallbackHandler) (*Filter, error) {
	logger := GetLogger()
	logger.Debug("Setting up cookie configuration",
		zap.String("cookie_name", config.SessionCookieName),
		zap.String("cookie_path", config.SessionPath),
		zap.String("cookie_domain", config.SessionDomain),
		zap.Int("cookie_max_age", int(config.SessionMaxAge.Seconds())),
		zap.Bool("cookie_secure", config.SessionSecure),
		zap.Bool("cookie_http_only", config.SessionHttpOnly),
		zap.String("cookie_same_site", config.SessionSameSite))

	cookieConfig := &session.CookieConfig{
		Name:     config.SessionCookieName,
		Path:     config.SessionPath,
		Domain:   config.SessionDomain,
		MaxAge:   int(config.SessionMaxAge.Seconds()),
		Secure:   config.SessionSecure,
		HTTPOnly: config.SessionHttpOnly,
		SameSite: convertSameSite(config.SessionSameSite),
	}

	cookieManager, err := session.NewCookieManager(nil, nil, cookieConfig)
	if err != nil {
		logger.Error("Failed to create cookie manager",
			zap.Error(err))
		return nil, fmt.Errorf("failed to create cookie manager: %v", err)
	}

	logger.Debug("Creating new OAuth filter",
		zap.String("issuer_url", config.IssuerURL),
		zap.String("client_id", config.ClientID),
		zap.String("redirect_url", config.RedirectURL),
		zap.Strings("scopes", config.Scopes),
	)

	return &Filter{
		config:        config,
		oauthHandler:  config.OAuthHandler,
		sessionStore:  config.SessionStore,
		cookieManager: cookieManager,
		callbacks:     callbacks,
		logger:        logger,
	}, nil
}

func (f *Filter) createOAuthHandler(config *OAuthConfig, cookieManager *session.CookieManager) (oauth.OAuthHandler, error) {
	// Create OAuth handler
	oauthConfig := &oauth.OIDCConfig{
		IssuerURL:    config.IssuerURL,
		ClientID:     config.ClientID,
		ClientSecret: config.ClientSecret,
		RedirectURL:  config.RedirectURL,
		Scopes:       config.Scopes,
	}

	oauthHandler, err := oauth.NewOAuthHandler(oauthConfig, config.SessionStore, cookieManager)
	if err != nil {
		logger.Error("Failed to create OAuth handler",
			zap.Error(err),
			zap.String("issuer_url", config.IssuerURL),
			zap.String("client_id", config.ClientID))
		return nil, fmt.Errorf("failed to create OAuth handler: %v", err)
	}
	config.OAuthHandler = oauthHandler
	f.oauthHandler = config.OAuthHandler

	return oauthHandler, nil
}

// handleAuthFailure creates appropriate response for authentication failures
func (f *Filter) handleAuthFailure(statusCode int, message string) api.StatusType {
	f.logger.Debug("Authentication failure",
		zap.Int("status_code", statusCode),
		zap.String("message", message))

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

	// Get header names from config or use defaults
	userIDHeader := f.config.UserIDHeaderName
	if userIDHeader == "" {
		userIDHeader = "X-User-ID"
	}
	userEmailHeader := f.config.UserEmailHeaderName
	if userEmailHeader == "" {
		userEmailHeader = "X-User-Email"
	}
	userUsernameHeader := f.config.UserUsernameHeaderName
	if userUsernameHeader == "" {
		userUsernameHeader = "X-User-Username"
	}

	// Add user info to headers for downstream services
	header.Set(userIDHeader, session.UserID)

	// Add user email from claims if available
	if email, ok := session.Claims["email"].(string); ok {
		header.Set(userEmailHeader, email)
	}

	// Add username from claims if available
	if username, ok := session.Claims["preferred_username"].(string); ok {
		header.Set(userUsernameHeader, username)
	}

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
	f.logger.Debug("Handling redirect",
		zap.String("url", url),
		zap.Bool("has_cookie", cookieValue != ""))

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

// isBrowserRequest checks if the request is from a browser based on Accept header
func (f *Filter) isBrowserRequest(header api.RequestHeaderMap) bool {
	accept, _ := header.Get("accept")
	return strings.Contains(accept, "text/html") ||
		strings.Contains(accept, "application/xhtml+xml") ||
		strings.Contains(accept, "application/xml")
}

// handleUnauthenticatedRequest handles unauthenticated requests based on request type
func (f *Filter) handleUnauthenticatedRequest(header api.RequestHeaderMap, path string, traceID string, err error, context string) api.StatusType {
	if f.isBrowserRequest(header) {
		f.logger.Debug(fmt.Sprintf("Unauthenticated browser request: %s", context),
			zap.String("path", path),
			zap.String("trace_id", traceID),
			zap.Error(err))
		return f.handleRedirect("/oauth/login?redirect_uri="+url.QueryEscape(path), "")
	} else {
		f.logger.Debug(fmt.Sprintf("Unauthenticated API request: %s", context),
			zap.String("path", path),
			zap.String("trace_id", traceID),
			zap.Error(err))
		return f.handleAuthFailure(401, fmt.Sprintf("Unauthorized: %s", context))
	}
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
	// cluster, _ := header.Get(":authority")
	cluster := getClusterName(f.callbacks)

	f.logger.Debug(fmt.Sprintf("path: %s, cluster: %s, trace_id: %s", path, cluster, traceID))

	if f.config.SkipAuthHeaderName != "" {
		if username, exists := header.Get(f.config.SkipAuthHeaderName); exists && username != "" {
			f.logger.Debug("Skipping authentication - header already exists",
				zap.String("header", f.config.SkipAuthHeaderName),
				zap.String("username", username),
				zap.String("trace_id", traceID))
			return api.Continue
		}
	}

	// Check if the path should be excluded
	if !strings.HasPrefix(path, "/oauth/") && f.isPathExcluded(path, cluster) {
		f.logger.Debug("Path is excluded from authentication",
			zap.String("path", path),
			zap.String("trace_id", traceID))
		return api.Continue
	}

	if f.oauthHandler == nil {
		f.mu.Lock()
		// Double check after acquiring lock
		if f.oauthHandler == nil {
			f.logger.Debug("Creating OAuth handler",
				zap.String("trace_id", traceID))
			_, err := f.createOAuthHandler(f.config, f.cookieManager)
			if err != nil {
				f.mu.Unlock()
				f.logger.Error("Failed to create OAuth handler",
					zap.Error(err))
				return f.handleAuthFailure(500, "Internal Server Error: Failed to create OAuth handler")
			}
		}
		f.mu.Unlock()
	}

	// Handle OAuth endpoints
	if strings.HasPrefix(path, "/oauth/") {
		go func() {
			status := f.handleOAuthEndpoints(header, path)
			f.callbacks.DecoderFilterCallbacks().Continue(status)
		}()
		return api.Running
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
		return f.handleUnauthenticatedRequest(header, path, traceID, err, "No valid session or token found")
	}

	session, err := f.sessionStore.Get(sessionID)
	if err != nil {
		return f.handleUnauthenticatedRequest(header, path, traceID, err, "Invalid session")
	}

	// Validate and refresh session if needed
	if err := f.oauthHandler.ValidateSession(session); err != nil {
		return f.handleUnauthenticatedRequest(header, path, traceID, err, "Session validation failed")
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

	// Get the session ID from the set-cookie header
	sessionID, exists := header.Get("set-cookie")
	if !exists || sessionID == "" {
		f.logger.Error("Failed to get session cookie",
			zap.String("trace_id", traceID),
			zap.Error(err))
		return f.handleAuthFailure(500, "Internal Server Error: Failed to get session cookie")
	}

	// Get the redirect URI from the location header
	redirectURI, exists := header.Get("location")
	if !exists || redirectURI == "" {
		redirectURI = "/"
	}

	return f.handleRedirect(redirectURI, sessionID)
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
		f.logger.Debug("Failed to get session cookie", zap.Error(err))
		return nil, err
	}
	f.logger.Debug("Retrieved session ID from cookie", zap.String("session_id", sessionID))

	session, err := f.sessionStore.Get(sessionID)
	if err != nil {
		f.logger.Debug("Failed to get session from store",
			zap.String("session_id", sessionID),
			zap.Error(err))
		return nil, err
	}
	f.logger.Debug("Successfully retrieved session from store",
		zap.String("session_id", session.ID),
		zap.String("user_id", session.UserID),
		zap.Time("expires_at", session.ExpiresAt))
	return session, nil
}

func (f *Filter) isValidSession(session *session.Session) bool {
	f.logger.Debug("Validating session",
		zap.String("session_id", session.ID),
		zap.Time("expires_at", session.ExpiresAt))

	isValid := session.ExpiresAt.After(time.Now())
	if !isValid {
		f.logger.Debug("Session is expired",
			zap.String("session_id", session.ID),
			zap.Time("expires_at", session.ExpiresAt))
	}
	return isValid
}

func getClusterName(callbacks api.FilterCallbackHandler) string {
	streamInfo := callbacks.StreamInfo()
	clusterName, exists := streamInfo.UpstreamClusterName()
	if !exists {
		return ""
	}
	return clusterName
}
