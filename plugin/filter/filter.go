package filter

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
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
	config           *OAuthConfig
	cluster          string
	providerRegistry *ProviderRegistry
	sessionStore     session.SessionStore
	callbacks        api.FilterCallbackHandler
	logger           *zap.Logger
	errorHandler *ErrorHandler
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
	logger.Debug("Creating new OAuth filter",
		zap.String("issuer_url", config.IssuerURL),
		zap.String("client_id", config.ClientID),
		zap.String("redirect_url", config.RedirectURL),
		zap.Strings("scopes", config.Scopes),
	)

	filter := &Filter{
		config:           config,
		providerRegistry: config.ProviderRegistry,
		sessionStore:     config.SessionStore,
		callbacks:        callbacks,
		logger:           logger,
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

	return filter, nil
}

// getProviderHandler resolves the OAuth handler for the current request's cluster.
// It first looks up the cluster's ProviderName, then falls back to DefaultProvider.
//
// HLTH-02 / D-03: if the resolved handler reports StateDown, an error is returned
// so that all call sites immediately return 503 "Identity provider unavailable"
// without invoking any provider operation.
func (f *Filter) getProviderHandler() (oauth.OAuthHandler, error) {
	providerName := ""
	if clusterConfig, ok := f.config.Clusters[f.cluster]; ok {
		providerName = clusterConfig.ProviderName
	}
	if providerName == "" {
		providerName = f.config.DefaultProvider
	}
	h, err := f.providerRegistry.GetHandler(providerName)
	if err != nil {
		return nil, err
	}
	if h.HealthState() == oauth.StateDown {
		return nil, fmt.Errorf("provider %q is down", providerName)
	}
	return h, nil
}

// resolveProviderName returns the provider registry key for the current cluster,
// falling back to DefaultProvider. Used for SESS-02 verification and cookie-name
// derivation. NEVER reads from session data (D-06, D-07).
func (f *Filter) resolveProviderName() string {
	if clusterConfig, ok := f.config.Clusters[f.cluster]; ok && clusterConfig.ProviderName != "" {
		return clusterConfig.ProviderName
	}
	return f.config.DefaultProvider
}

// verifySessionProvider returns whether sess.ProviderName matches the
// cluster-derived provider (D-05). Empty sess.ProviderName is treated as
// matched to allow legacy sessions created before the ProviderName field
// was added to transition gracefully.
func (f *Filter) verifySessionProvider(sess *session.Session) (bool, string) {
	expected := f.resolveProviderName()
	if sess.ProviderName == "" || sess.ProviderName == expected {
		return true, expected
	}
	return false, expected
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
	return f.handleAuthFailureWithCookie(statusCode, message, "")
}

// handleAuthFailureWithCookie is like handleAuthFailure but includes a Set-Cookie header.
// Use this when a cookie must be cleared as part of the failure response (e.g. SESS-02 mismatch).
func (f *Filter) handleAuthFailureWithCookie(statusCode int, message, deleteCookieStr string) api.StatusType {
	f.logger.Debug("Authentication failure",
		zap.Int("status_code", statusCode),
		zap.String("message", message))

	// Record cluster auth failure metric
	clusterLabel := metrics.GetClusterLabel(f.cluster, f.knownClusterNames())
	realm := metrics.GetRealm(f.config.IssuerURL)
	metrics.RecordClusterAuth(clusterLabel, realm, "failure")

	headers := createAuthErrorHeaders()
	if deleteCookieStr != "" {
		headers["Set-Cookie"] = []string{deleteCookieStr}
	}

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

	// Add auth provider header for downstream services (REQ-01).
	// Source: session.ProviderName (verified at session creation), with cluster-derived
	// fallback for legacy sessions predating the ProviderName field. D-01 prohibits
	// reading from route metadata; resolveProviderName reads cluster config only.
	authProviderHeader := f.config.AuthProviderHeaderName
	if authProviderHeader == "" {
		authProviderHeader = "X-Auth-Provider"
	}
	if session.ProviderName != "" {
		header.Set(authProviderHeader, session.ProviderName)
	} else if fallback := f.resolveProviderName(); fallback != "" {
		header.Set(authProviderHeader, fallback)
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

// stripUntrustedHeaders deletes the headers listed in f.config.RemoveHeaders
// from the incoming request (T-04-01). Called from DecodeHeaders before any
// early-return so client-supplied identity/provider headers cannot spoof
// upstream services even on excluded or skip-auth paths.
func (f *Filter) stripUntrustedHeaders(header api.RequestHeaderMap) {
	if f.config == nil {
		return
	}
	for _, name := range f.config.RemoveHeaders {
		if name != "" {
			header.Del(name)
		}
	}
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
	if f.isBrowserRequest(header) {
		f.logger.Debug(fmt.Sprintf("Unauthenticated browser request: %s", context),
			zap.String("path", sanitizePathForLogging(path)),
			zap.String("trace_id", traceID),
			zap.Error(err))
		// Include provider name in login redirect so handleLogin uses the correct provider
		providerName := f.config.DefaultProvider
		if clusterConfig, ok := f.config.Clusters[f.cluster]; ok && clusterConfig.ProviderName != "" {
			providerName = clusterConfig.ProviderName
		}
		loginURL := "/oauth/login?redirect_uri=" + url.QueryEscape(path) + "&provider=" + url.QueryEscape(providerName)
		return f.handleRedirect(loginURL, "")
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

			// Resolve provider handler for this cluster
			apiHandler, err := f.getProviderHandler()
			if err != nil {
				f.logger.Error("Failed to resolve provider handler for API token exchange",
					zap.String("trace_id", traceID),
					zap.Error(err))
				return f.recordAndSendLocalReply(503, "Identity provider unavailable",
					createAuthErrorHeaders(), -1, "provider_unavailable")
			}

			// Exchange refresh token for access token
			accessToken, err := apiHandler.ExchangeRefreshToken(context.Background(), apiToken)
			if err != nil {
				// Record API key authentication failure with classified reason
				reason := metrics.ClassifyAPIKeyError(err)
				metrics.RecordAPIKeyAuth("failure", reason)

				f.logger.Debug("Failed to exchange API token for access token",
					zap.String("trace_id", traceID),
					zap.Error(err))
				// Don't fail here, let it continue to check for other auth methods
			} else {
				// Record API key authentication success
				metrics.RecordAPIKeyAuth("success", "")

				// Successfully exchanged
				f.logger.Debug("Successfully exchanged API token for access token",
					zap.String("trace_id", traceID))

				// If API token came from query parameter, create session and redirect
				if f.isAPITokenFromQuery(header) {
					// Validate the access token to get user info
					sess, err := apiHandler.ValidateBearerToken(context.Background(), accessToken)
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
							if err := apiHandler.SetSessionCookie(header, sess.ID); err != nil {
								f.logger.Error("Failed to set session cookie",
									zap.String("trace_id", traceID),
									zap.Error(err))
								// Fall back to injecting as bearer token
								header.Set("authorization", "Bearer "+accessToken)
							} else {
								// Redirect to clean URL without the API key parameter
								cleanPath := removeQueryParam(path, "auth-api-key")
								// Format the cookie properly for the redirect
								cookieStr := apiHandler.FormatSessionCookie(sess.ID)
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
			// Resolve provider handler for bearer token validation
			bearerHandler, err := f.getProviderHandler()
			if err != nil {
				// Per D-10: provider unavailable -> 503
				f.logger.Error("Failed to resolve provider handler for bearer token validation",
					zap.String("trace_id", traceID),
					zap.Error(err))
				return f.recordAndSendLocalReply(503, "Identity provider unavailable",
					createAuthErrorHeaders(), -1, "provider_unavailable")
			}

			f.logger.Debug("Bearer token found, attempting validation",
				zap.String("trace_id", traceID))

			// Validate the bearer token
			session, err := bearerHandler.ValidateBearerToken(context.Background(), token)
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

	// Check for session cookie using per-provider cookie name (D-08, D-09).
	// Resolve the handler first so we read the correct namespaced cookie.
	sessionHandler, err := f.getProviderHandler()
	if err != nil {
		f.logger.Error("Failed to resolve provider for session lookup",
			zap.String("trace_id", traceID),
			zap.Error(err))
		return f.recordAndSendLocalReply(503, "Identity provider unavailable",
			createAuthErrorHeaders(), -1, "provider_unavailable")
	}
	sessionID, err := sessionHandler.GetSessionCookie(header)
	if err != nil {
		return f.handleUnauthenticatedRequest(header, path, traceID, err, "No valid session or token found")
	}

	session, err := f.sessionStore.Get(sessionID)
	if err != nil {
		return f.handleUnauthenticatedRequest(header, path, traceID, err, "Invalid session")
	}

	// SESS-02: verify session-provider binding (D-05).
	// The session's ProviderName must match the cluster-derived provider.
	// Mismatch => best-effort delete stored session, clear cookie via the
	// per-provider handler, log WARN, return unauthenticated to trigger re-auth.
	if matched, expectedProvider := f.verifySessionProvider(session); !matched {
		f.logger.Warn("Session provider mismatch — rejecting session",
			zap.String("session_provider", session.ProviderName),
			zap.String("expected_provider", expectedProvider),
			zap.String("session_id", session.ID),
			zap.String("cluster", f.cluster),
			zap.String("trace_id", traceID))
		if delErr := f.sessionStore.Delete(session.ID); delErr != nil {
			f.logger.Warn("Failed to delete mismatched session (best-effort)",
				zap.String("session_id", session.ID),
				zap.Error(delErr))
		}
		// Build the deletion cookie string before overwriting request headers.
		// DeleteSessionCookie writes to the request header map; SendLocalReply does not
		// forward request headers to the response, so we must pass the cookie explicitly.
		sessionHandler.DeleteSessionCookie(header)
		deleteCookieStr, _ := header.Get("set-cookie")
		if f.isBrowserRequest(header) {
			providerName := f.resolveProviderName()
			loginURL := "/oauth/login?redirect_uri=" + url.QueryEscape(path) + "&provider=" + url.QueryEscape(providerName)
			return f.handleRedirect(loginURL, deleteCookieStr)
		}
		return f.handleAuthFailureWithCookie(401, "Unauthorized: Session from wrong provider", deleteCookieStr)
	}

	if sessionHandler.IsNeedValidateSession(session) {
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
	case basePath == "/oauth/llms.txt" && f.config.EnableLLMsTxt:
		return f.handleLLMsTxt(header)
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

	// Get redirect URI and provider from query parameters
	path, _ := header.Get(":path")
	values := url.Values{}
	if idx := strings.Index(path, "?"); idx != -1 {
		var parseErr error
		values, parseErr = url.ParseQuery(path[idx+1:])
		if parseErr != nil {
			return f.handleAuthFailure(400, "Bad Request: Invalid query parameters")
		}
	}

	redirectURI := values.Get("redirect_uri")
	// Reject any redirect_uri that is not a safe relative path. Explicit
	// second-character check handles browser-normalised bypasses:
	//   "//evil.com"  → protocol-relative
	//   "///evil.com" → triple-slash (parsed as path by Go, but browser collapses)
	//   "/\evil.com"  → backslash-normalised to // by Chromium
	if parsed, err := url.Parse(redirectURI); err != nil ||
		parsed.Host != "" || parsed.Scheme != "" ||
		!strings.HasPrefix(redirectURI, "/") ||
		(len(redirectURI) > 1 && (redirectURI[1] == '/' || redirectURI[1] == '\\')) {
		redirectURI = "/"
	}

	// Resolve provider handler. The provider query param is set by our own
	// handleUnauthenticatedRequest; validate it against registered providers.
	// If absent or invalid, fall back to cluster-based resolution.
	providerName := values.Get("provider")
	var loginHandler oauth.OAuthHandler
	var err error
	if providerName != "" {
		if h, regErr := f.providerRegistry.GetHandler(providerName); regErr != nil {
			// Unknown provider in query param — ignore it, use cluster resolution
			f.logger.Warn("Ignoring unknown provider in login query param",
				zap.String("provider", providerName))
			loginHandler, err = f.getProviderHandler()
		} else if h.HealthState() == oauth.StateDown {
			// Provider is registered but currently down — gate with 503 (D-03).
			f.logger.Warn("Provider is down, rejecting login",
				zap.String("provider", providerName),
				zap.String("trace_id", traceID))
			return f.errorHandler.HandleIDPUnavailable()
		} else {
			loginHandler = h
		}
	} else {
		loginHandler, err = f.getProviderHandler()
	}
	if err != nil {
		f.logger.Warn("OAuth provider unavailable for login",
			zap.String("trace_id", traceID),
			zap.String("provider", providerName),
			zap.Error(err))
		return f.errorHandler.HandleIDPUnavailable()
	}

	// Start OAuth flow
	err = loginHandler.HandleAuthRedirect(header, redirectURI)
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
	query := ""
	if idx := strings.Index(path, "?"); idx != -1 {
		query = path[idx+1:]
	}

	// Resolve the provider from the nonce stored in the pending-auth entry.
	// This uses PeekPendingAuthProvider so the entry is NOT consumed here —
	// HandleCallback will consume it via GetPendingAuth.
	values, _ := url.ParseQuery(query)
	nonce := values.Get("state")
	if nonce == "" {
		return f.handleAuthFailure(400, "Missing state parameter in OAuth callback")
	}
	providerName, err := session.PeekPendingAuthProvider(f.sessionStore, nonce)
	if err != nil {
		f.logger.Warn("Failed to peek pending-auth provider from nonce",
			zap.String("trace_id", traceID),
			zap.String("nonce", nonce),
			zap.Error(err))
		return f.handleAuthFailure(400, "Invalid or expired state parameter")
	}

	callbackHandler, err := f.providerRegistry.GetHandler(providerName)
	if err != nil {
		f.logger.Error("Provider from pending-auth not found in registry",
			zap.String("trace_id", traceID),
			zap.String("provider", providerName),
			zap.Error(err))
		return f.recordAndSendLocalReply(503, "Identity provider unavailable",
			createAuthErrorHeaders(), -1, "provider_unavailable")
	}
	// HLTH-02 / D-03: gate — provider found but currently down.
	if callbackHandler.HealthState() == oauth.StateDown {
		f.logger.Warn("Provider is down, rejecting callback",
			zap.String("trace_id", traceID),
			zap.String("provider", providerName))
		return f.recordAndSendLocalReply(503, "Identity provider unavailable",
			createAuthErrorHeaders(), -1, "provider_unavailable")
	}

	return f.handleAsyncCallback(header, query, traceID, callbackHandler)
}

// handleLogout processes user logout
func (f *Filter) handleLogout(header api.RequestHeaderMap) api.StatusType {
	traceID := f.getTraceID(header)

	f.logger.Debug("Handling logout request",
		zap.String("trace_id", traceID))

	logoutHandler, err := f.getProviderHandler()
	if err != nil {
		f.logger.Warn("OAuth provider unavailable for logout",
			zap.String("trace_id", traceID),
			zap.Error(err))
		return f.errorHandler.HandleIDPUnavailable()
	}

	logoutURL, err := logoutHandler.HandleLogout(header)
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
