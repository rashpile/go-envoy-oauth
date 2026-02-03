package filter

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/envoyproxy/envoy/contrib/golang/common/go/api"
	"github.com/rashpile/go-envoy-oauth/plugin/metrics"
	"github.com/rashpile/go-envoy-oauth/plugin/oauth"
	"github.com/rashpile/go-envoy-oauth/plugin/session"
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
	config              *OAuthConfig
	cluster             string
	oauthHandler        oauth.OAuthHandler
	offlineTokenHandler *oauth.OfflineTokenHandler
	sessionStore        session.SessionStore
	cookieManager       *session.CookieManager
	callbacks           api.FilterCallbackHandler
	logger              *zap.Logger
	errorHandler        *ErrorHandler
	mu                  sync.Mutex
	// Access log fields
	requestStart  time.Time
	requestMethod string
	requestPath   string
	requestHost   string
	clientIP      string
	userAgent     string
	// SSO script injection
	shouldInjectSSO bool
	currentSession  *session.Session
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

	filter := &Filter{
		config:              config,
		oauthHandler:        config.OAuthHandler,
		offlineTokenHandler: nil, // Will be initialized when OAuth handler is created
		sessionStore:        config.SessionStore,
		cookieManager:       cookieManager,
		callbacks:           callbacks,
		logger:              logger,
	}

	// Create error handler with metrics recording closure
	filter.errorHandler = NewErrorHandler(logger, callbacks, func(statusCode int) {
		if !filter.requestStart.IsZero() {
			duration := time.Since(filter.requestStart)
			metrics.RecordRequest(statusCode, duration.Seconds())
			if IsAccessLogEnabled() {
				responseTime := duration.Seconds() * 1000
				LogAccess(filter.requestMethod, filter.requestPath, filter.requestHost,
					filter.clientIP, filter.userAgent, statusCode, responseTime)
			}
			filter.requestStart = time.Time{}
		}
	})

	// If OAuth handler already exists and API key feature is enabled, try to create offline handler
	if config.EnableAPIKey && filter.oauthHandler != nil && filter.offlineTokenHandler == nil {
		if oauthHandlerImpl, ok := filter.oauthHandler.(*oauth.OAuthHandlerImpl); ok {
			logger.Debug("Creating offline token handler during filter initialization (API key feature enabled)")
			offlineHandler, err := oauth.NewOfflineTokenHandler(oauthHandlerImpl, logger)
			if err != nil {
				logger.Error("Failed to create offline token handler during initialization", zap.Error(err))
			} else {
				filter.offlineTokenHandler = offlineHandler
				logger.Debug("Offline token handler created successfully during initialization")
			}
		} else {
			logger.Warn("OAuth handler exists but is not OAuthHandlerImpl type",
				zap.String("actual_type", fmt.Sprintf("%T", filter.oauthHandler)))
		}
	} else if config.EnableAPIKey {
		logger.Debug("API key feature is enabled, handler will be created when OAuth handler is initialized")
	} else {
		logger.Debug("API key feature is disabled in configuration")
	}

	return filter, nil
}

// ensureHandlersInitialized makes sure OAuth and offline handlers are initialized
func (f *Filter) ensureHandlersInitialized() error {
	f.mu.Lock()
	defer f.mu.Unlock()

	// If handler already exists, nothing to do
	if f.oauthHandler != nil {
		return nil
	}

	// Check if we should retry based on exponential backoff
	if !f.config.RetryManager.ShouldRetry() {
		retryInfo := f.config.RetryManager.GetRetryInfo()
		f.logger.Debug("OAuth handler initialization in backoff period",
			zap.String("retry_info", retryInfo))
		// When in backoff, IDP is considered down
		idp := metrics.GetIDPName(f.config.IssuerURL)
		metrics.UpdateIDPAvailability(idp, false)
		return f.config.RetryManager.GetError()
	}

	// Try to create the handler
	f.logger.Info("Attempting to initialize OAuth handler")
	_, err := f.createOAuthHandler(f.config, f.cookieManager)
	if err != nil {
		f.logger.Warn("Failed to create OAuth handler, will retry later",
			zap.String("error", err.Error()),
			zap.String("retry_info", f.config.RetryManager.GetRetryInfo()))

		// Record error with exponential backoff
		f.config.RetryManager.RecordError(fmt.Errorf("OAuth provider unavailable: %v", err))
		return f.config.RetryManager.GetError()
	}

	f.logger.Info("OAuth handler created successfully")
	// Clear error state on success
	f.config.RetryManager.ClearError()

	// Create offline handler if needed and if API key feature is enabled
	if f.config.EnableAPIKey && f.offlineTokenHandler == nil && f.oauthHandler != nil {
		if oauthHandlerImpl, ok := f.oauthHandler.(*oauth.OAuthHandlerImpl); ok {
			f.logger.Debug("Creating offline token handler separately (API key feature enabled)")
			offlineHandler, err := oauth.NewOfflineTokenHandler(oauthHandlerImpl, f.logger)
			if err != nil {
				f.logger.Error("Failed to create offline token handler", zap.Error(err))
				// Non-fatal: offline token functionality will be disabled
			} else {
				f.offlineTokenHandler = offlineHandler
				f.logger.Debug("Offline token handler created successfully in ensureHandlersInitialized")
			}
		} else {
			f.logger.Error("Failed to cast OAuth handler to OAuthHandlerImpl in ensureHandlersInitialized",
				zap.String("actual_type", fmt.Sprintf("%T", f.oauthHandler)))
		}
	}

	return nil
}

func (f *Filter) createOAuthHandler(config *OAuthConfig, cookieManager *session.CookieManager) (oauth.OAuthHandler, error) {
	// Extract IDP name for metrics
	idp := metrics.GetIDPName(config.IssuerURL)

	// Create OAuth handler
	oauthConfig := &oauth.OIDCConfig{
		IssuerURL:    config.IssuerURL,
		ClientID:     config.ClientID,
		ClientSecret: config.ClientSecret,
		RedirectURL:  config.RedirectURL,
		Scopes:       config.Scopes,
	}

	oauthHandler, err := oauth.NewOAuthHandler(oauthConfig, config.SessionStore, cookieManager, logger)
	if err != nil {
		// Use Warn level but without stack trace for expected IDP connectivity issues
		logger.Warn("Failed to create OAuth handler (IDP may be unavailable)",
			zap.String("error", err.Error()),
			zap.String("issuer_url", config.IssuerURL),
			zap.String("client_id", config.ClientID))
		// Mark IDP as unavailable
		metrics.UpdateIDPAvailability(idp, false)
		return nil, fmt.Errorf("failed to create OAuth handler: %v", err)
	}
	config.OAuthHandler = oauthHandler
	f.oauthHandler = config.OAuthHandler

	// Mark IDP as available
	metrics.UpdateIDPAvailability(idp, true)

	// Create offline token handler if API key feature is enabled
	if config.EnableAPIKey {
		if oauthHandlerImpl, ok := oauthHandler.(*oauth.OAuthHandlerImpl); ok {
			f.logger.Debug("Creating offline token handler (API key feature enabled)")
			offlineHandler, err := oauth.NewOfflineTokenHandler(oauthHandlerImpl, f.logger)
			if err != nil {
				f.logger.Error("Failed to create offline token handler", zap.Error(err))
				// Non-fatal: offline token functionality will be disabled
			} else {
				f.offlineTokenHandler = offlineHandler
				f.logger.Debug("Offline token handler created successfully")
			}
		} else {
			f.logger.Error("Failed to cast OAuth handler to OAuthHandlerImpl",
				zap.String("actual_type", fmt.Sprintf("%T", oauthHandler)))
		}
	} else {
		f.logger.Debug("API key feature is disabled, skipping offline token handler creation")
	}

	return oauthHandler, nil
}

// recordAndSendLocalReply wraps SendLocalReply with metrics recording and access logging.
// This ensures that locally-generated responses (auth failures, redirects, etc.) are
// properly tracked in metrics, closing the gap where SendLocalReply bypasses EncodeHeaders.
func (f *Filter) recordAndSendLocalReply(statusCode int, bodyText string,
	headers map[string][]string, grpcStatus int64, details string) api.StatusType {

	// Record metrics and access log if request tracking is active
	if !f.requestStart.IsZero() {
		duration := time.Since(f.requestStart)

		// Record request metrics (nil-safe, always record)
		metrics.RecordRequest(statusCode, duration.Seconds())

		// Log access if enabled
		if IsAccessLogEnabled() {
			responseTime := duration.Seconds() * 1000 // convert to ms
			LogAccess(f.requestMethod, f.requestPath, f.requestHost,
				f.clientIP, f.userAgent, statusCode, responseTime)
		}

		// Reset the request tracking to prevent double-counting in EncodeHeaders
		f.requestStart = time.Time{}
	}

	// Send the local reply
	f.callbacks.DecoderFilterCallbacks().SendLocalReply(
		statusCode,
		bodyText,
		headers,
		grpcStatus,
		details,
	)

	return api.LocalReply
}

// knownClusterNames builds a map of configured cluster names for cardinality-bounded metrics.
func (f *Filter) knownClusterNames() map[string]bool {
	known := make(map[string]bool, len(f.config.Clusters))
	for name := range f.config.Clusters {
		known[name] = true
	}
	return known
}

// handleAuthFailure creates appropriate response for authentication failures
func (f *Filter) handleAuthFailure(statusCode int, message string) api.StatusType {
	f.logger.Debug("Authentication failure",
		zap.Int("status_code", statusCode),
		zap.String("message", message))

	// Record cluster auth failure metric
	clusterLabel := metrics.GetClusterLabel(f.cluster, f.knownClusterNames())
	realm := metrics.GetRealm(f.config.IssuerURL)
	metrics.RecordClusterAuth(clusterLabel, realm, "failure")

	headers := createAuthErrorHeaders()

	return f.recordAndSendLocalReply(statusCode, message, headers, -1, "auth_failure")
}

// handleAuthSuccess processes a successful authentication
func (f *Filter) handleAuthSuccess(header api.RequestHeaderMap, session *session.Session) api.StatusType {
	traceID := f.getTraceID(header)

	// Check user permissions before granting access
	if !f.isUserPermitted(session) {
		username := ""
		if u, ok := session.Claims["preferred_username"].(string); ok {
			username = u
		}

		// Audit log: permission denied
		f.logger.Info("Access denied: user not permitted",
			zap.String("user", username),
			zap.String("cluster", f.cluster),
			zap.String("trace_id", traceID),
			zap.String("action", "DENY"))

		return f.handleAccessDenied(header)
	}

	// Audit log: permission granted (only if allowed_users is configured)
	if clusterConfig, exists := f.config.Clusters[f.cluster]; exists && len(clusterConfig.AllowedUsers) > 0 {
		username := ""
		if u, ok := session.Claims["preferred_username"].(string); ok {
			username = u
		}
		f.logger.Info("Access permitted",
			zap.String("user", username),
			zap.String("cluster", f.cluster),
			zap.String("trace_id", traceID),
			zap.String("action", "PERMIT"))
	}

	// Record cluster auth success metric (after permission check, before header manipulation)
	clusterLabel := metrics.GetClusterLabel(f.cluster, f.knownClusterNames())
	realm := metrics.GetRealm(f.config.IssuerURL)
	metrics.RecordClusterAuth(clusterLabel, realm, "success")

	// Store the current session for SSO script injection
	f.currentSession = session

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

	if f.config.Clusters[f.cluster].TokenInclude && session.Token != "" {
		header.Set("authorization", "Bearer "+session.Token)
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

// handleAccessDenied redirects to the access denied page
func (f *Filter) handleAccessDenied(header api.RequestHeaderMap) api.StatusType {
	return f.handleRedirect("/oauth/access-denied", "")
}

// handleAccessDeniedPage renders the access denied page
func (f *Filter) handleAccessDeniedPage(header api.RequestHeaderMap) api.StatusType {
	return f.errorHandler.HandleAccessDenied()
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

	return f.recordAndSendLocalReply(http.StatusFound, "", headers, 0, "")
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
	// Check if IDP is unavailable and we're still in backoff period
	f.mu.Lock()
	if f.config.RetryManager.GetError() != nil && !f.config.RetryManager.ShouldRetry() {
		// IDP is unavailable and we're still in backoff, return a user-friendly error message
		f.mu.Unlock()
		retryInfo := f.config.RetryManager.GetRetryInfo()
		f.logger.Warn("Identity provider is temporarily unavailable (in backoff period)",
			zap.String("path", sanitizePathForLogging(path)),
			zap.String("trace_id", traceID),
			zap.String("error", f.config.RetryManager.GetError().Error()),
			zap.String("retry_info", retryInfo))
		return f.errorHandler.HandleIDPUnavailable()
	}
	f.mu.Unlock()

	if f.isBrowserRequest(header) {
		f.logger.Debug(fmt.Sprintf("Unauthenticated browser request: %s", context),
			zap.String("path", sanitizePathForLogging(path)),
			zap.String("trace_id", traceID),
			zap.Error(err))
		return f.handleRedirect("/oauth/login?redirect_uri="+url.QueryEscape(path), "")
	} else {
		f.logger.Debug(fmt.Sprintf("Unauthenticated API request: %s", context),
			zap.String("path", sanitizePathForLogging(path)),
			zap.String("trace_id", traceID),
			zap.Error(err))
		return f.handleAuthFailure(401, fmt.Sprintf("Unauthorized: %s", context))
	}
}

func (f *Filter) handleDecodeHeaders(header api.RequestHeaderMap, path string, traceID string) api.StatusType {

	// Handle OAuth endpoints
	if strings.HasPrefix(path, "/oauth/") {
		status := f.handleOAuthEndpoints(header, path)
		return status
	}

	// Check for API token (refresh token) if enabled
	if f.config.EnableAPIKey && f.config.EnableBearerToken {
		apiToken := f.extractAPIToken(header)
		if apiToken != "" {
			f.logger.Debug("API token found",
				zap.Int("token_length", len(apiToken)),
				zap.Bool("from_query", f.isAPITokenFromQuery(header)),
				zap.String("trace_id", traceID))

			// Ensure handlers are initialized
			if err := f.ensureHandlersInitialized(); err != nil {
				f.logger.Error("Failed to initialize handlers for API token exchange",
					zap.String("trace_id", traceID),
					zap.Error(err))
				return f.handleAuthFailure(500, fmt.Sprintf("Failed to initialize handlers: %v", err))
			}

			// Exchange refresh token for access token
			accessToken, err := f.oauthHandler.ExchangeRefreshToken(context.Background(), apiToken)
			if err != nil {
				f.logger.Debug("Failed to exchange API token for access token",
					zap.String("trace_id", traceID),
					zap.Error(err))
				// Don't fail here, let it continue to check for other auth methods
			} else {
				// Successfully exchanged
				f.logger.Debug("Successfully exchanged API token for access token",
					zap.String("trace_id", traceID))

				// If API token came from query parameter, create session and redirect
				if f.isAPITokenFromQuery(header) {
					// Validate the access token to get user info
					sess, err := f.oauthHandler.ValidateBearerToken(context.Background(), accessToken)
					if err != nil {
						f.logger.Error("Failed to validate access token for session creation",
							zap.String("trace_id", traceID),
							zap.Error(err))
						// Fall back to injecting as bearer token
						header.Set("authorization", "Bearer "+accessToken)
					} else {
						// Store the refresh token in the session for future use
						sess.RefreshToken = apiToken
						sess.Token = accessToken

						// Store the session
						if err := f.config.SessionStore.Store(sess); err != nil {
							f.logger.Error("Failed to store session",
								zap.String("trace_id", traceID),
								zap.Error(err))
							// Fall back to injecting as bearer token
							header.Set("authorization", "Bearer "+accessToken)
						} else {
							// Set session cookie
							if err := f.cookieManager.SetCookie(header, sess.ID); err != nil {
								f.logger.Error("Failed to set session cookie",
									zap.String("trace_id", traceID),
									zap.Error(err))
								// Fall back to injecting as bearer token
								header.Set("authorization", "Bearer "+accessToken)
							} else {
								// Redirect to clean URL without the API key parameter
								cleanPath := removeQueryParam(path, "auth-api-key")
								// Format the cookie properly for the redirect
								cookieStr := f.cookieManager.FormatCookie(sess.ID)
								f.logger.Info("API key authenticated, creating session and redirecting",
									zap.String("from", sanitizePathForLogging(path)),
									zap.String("to", cleanPath),
									zap.String("session_id", sess.ID[:8]+"..."),
									zap.String("trace_id", traceID))
								return f.handleRedirect(cleanPath, cookieStr)
							}
						}
					}
				} else {
					// API token from header, just inject as bearer token
					header.Set("authorization", "Bearer "+accessToken)
				}
			}
		}
	}

	// Check for bearer token authentication if enabled
	f.logger.Debug("Checking bearer token authentication",
		zap.Bool("enabled", f.config.EnableBearerToken),
		zap.String("trace_id", traceID))

	if f.config.EnableBearerToken {
		token := f.extractBearerToken(header)
		f.logger.Debug("Extracted bearer token",
			zap.Bool("has_token", token != ""),
			zap.Int("token_length", len(token)),
			zap.String("trace_id", traceID))

		if token != "" {
			// Ensure handlers are initialized before validating bearer token
			if err := f.ensureHandlersInitialized(); err != nil {
				f.logger.Error("Failed to initialize handlers for bearer token validation",
					zap.String("trace_id", traceID),
					zap.Error(err))
				return f.handleAuthFailure(500, fmt.Sprintf("Failed to initialize handlers: %v", err))
			}

			f.logger.Debug("Bearer token found, attempting validation",
				zap.String("trace_id", traceID))

			// Validate the bearer token
			session, err := f.oauthHandler.ValidateBearerToken(context.Background(), token)
			if err != nil {
				f.logger.Debug("Bearer token validation failed",
					zap.String("trace_id", traceID),
					zap.Error(err))
				return f.handleUnauthenticatedRequest(
					header,
					path,
					traceID,
					err,
					"Invalid bearer token",
				)
			}

			f.logger.Debug("Bearer token validated successfully",
				zap.String("user_id", session.UserID),
				zap.String("trace_id", traceID))

			return f.handleAuthSuccess(header, session)
		}
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

	// Check if session needs validation/refresh
	if f.oauthHandler.IsNeedValidateSession(session) {
		// Perform async validation to avoid blocking
		return f.handleAsyncValidateSession(header, session, path, traceID, f.handleAuthSuccess)
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

	switch {
	case basePath == "/oauth/login":
		return f.handleLogin(header)
	case basePath == "/oauth/callback":
		return f.handleCallback(header)
	case basePath == "/oauth/logout":
		return f.handleLogout(header)
	case basePath == "/oauth/welcome":
		return f.handleWelcome(header)
	case basePath == "/oauth/user":
		return f.handleUserInfo(header)
	case basePath == "/oauth/consent":
		return f.handleOfflineConsent(header)
	case basePath == "/oauth/offline":
		return f.handleOfflineRedirect(header)
	case basePath == "/oauth/offline-callback":
		return f.handleOfflineCallback(header, path)
	case basePath == "/oauth/access-denied":
		return f.handleAccessDeniedPage(header)
	case strings.HasPrefix(basePath, "/oauth/assets/"):
		return f.handleAssets(header)
	default:
		return f.handleAuthFailure(404, "Not Found: Unknown OAuth endpoint")
	}
}

// handleLogin initiates the OAuth flow
func (f *Filter) handleLogin(header api.RequestHeaderMap) api.StatusType {
	traceID := f.getTraceID(header)

	f.logger.Debug("Handling login request",
		zap.String("trace_id", traceID))

	// Ensure handlers are initialized
	if err := f.ensureHandlersInitialized(); err != nil {
		f.logger.Warn("OAuth handler unavailable for login",
			zap.String("trace_id", traceID),
			zap.String("error", err.Error()))
		return f.errorHandler.HandleIDPUnavailable()
	}

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

	// Ensure handlers are initialized
	if err := f.ensureHandlersInitialized(); err != nil {
		f.logger.Warn("OAuth handler unavailable for callback",
			zap.String("trace_id", traceID),
			zap.String("error", err.Error()))
		return f.errorHandler.HandleIDPUnavailable()
	}

	// Get query parameters
	path, _ := header.Get(":path")
	query := path[strings.Index(path, "?")+1:]

	return f.handleAsyncCallback(header, query, traceID)
}

// handleLogout processes user logout
func (f *Filter) handleLogout(header api.RequestHeaderMap) api.StatusType {
	traceID := f.getTraceID(header)

	f.logger.Debug("Handling logout request",
		zap.String("trace_id", traceID))
	logoutURL, err := f.oauthHandler.HandleLogout(header)
	if err != nil {
		f.logger.Error("Failed to handle logout",
			zap.String("trace_id", traceID),
			zap.Error(err))
		return f.handleAuthFailure(500, "Internal Server Error: Failed to process logout")
	}

	return f.handleRedirect(logoutURL, "")
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

// isUserPermitted checks if the user is permitted to access the current cluster
// Default: all users denied unless explicitly permitted via super_users or allowed_users
// Use "*" in allowed_users to allow any authenticated user for a specific cluster
func (f *Filter) isUserPermitted(session *session.Session) bool {
	// Get username from session claims
	username := ""
	if u, ok := session.Claims["preferred_username"].(string); ok {
		username = strings.ToLower(u)
	}

	if username == "" {
		f.logger.Warn("No preferred_username in session claims")
		return false
	}

	// Check super users first (always permitted)
	for _, superUser := range f.config.SuperUsers {
		if username == superUser {
			return true
		}
	}

	// Get cluster config
	clusterConfig, exists := f.config.Clusters[f.cluster]
	if !exists {
		// No cluster config = deny by default
		return false
	}

	// Check if user is in allowed list
	for _, allowedUser := range clusterConfig.AllowedUsers {
		// Wildcard "*" allows any authenticated user
		if allowedUser == "*" || username == allowedUser {
			return true
		}
	}

	// Default: deny access
	return false
}
