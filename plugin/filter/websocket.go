package filter

import (
	"context"
	"strings"

	"github.com/envoyproxy/envoy/contrib/golang/common/go/api"
	"go.uber.org/zap"
)

// isWebSocketUpgrade checks if the request is a WebSocket upgrade request
func (f *Filter) isWebSocketUpgrade(header api.RequestHeaderMap) bool {
	connection, _ := header.Get("connection")
	upgrade, _ := header.Get("upgrade")

	// WebSocket upgrade requires both headers
	// Connection header may contain multiple values (e.g., "keep-alive, Upgrade")
	connectionLower := strings.ToLower(connection)
	hasUpgrade := strings.Contains(connectionLower, "upgrade")
	isWebSocket := strings.EqualFold(upgrade, "websocket")

	return hasUpgrade && isWebSocket
}

// isWebSocketPathExcluded checks if a WebSocket path should skip authentication
func (f *Filter) isWebSocketPathExcluded(path, cluster string) bool {
	if isExcludedPath(path, f.config.WebSocketExcludePaths) {
		return true
	}

	// Check cluster-specific WebSocket exclusions
	if clusterConfig, ok := f.config.Clusters[cluster]; ok {
		return isExcludedPath(path, clusterConfig.WebSocketExcludePaths)
	}

	return false
}

// handleWebSocketAuth authenticates WebSocket upgrade requests
// Unlike regular HTTP requests, WebSocket handshakes cannot follow redirects,
// so we return 401 Unauthorized instead of redirecting to login
func (f *Filter) handleWebSocketAuth(header api.RequestHeaderMap, path string, traceID string) api.StatusType {
	// Check for bearer token authentication first (common for WebSocket)
	if f.config.EnableBearerToken {
		token := f.extractBearerToken(header)
		if token != "" {
			f.logger.Debug("WebSocket: Bearer token found, validating",
				zap.String("trace_id", traceID))

			wsHandler, err := f.getProviderHandler()
			if err != nil {
				f.logger.Warn("WebSocket: Provider unavailable for bearer token validation",
					zap.String("trace_id", traceID),
					zap.Error(err))
				return f.handleAuthFailure(503, "Service Unavailable: Authentication service temporarily unavailable")
			}

			session, err := wsHandler.ValidateBearerToken(context.Background(), token)
			if err != nil {
				f.logger.Debug("WebSocket: Bearer token validation failed",
					zap.String("trace_id", traceID),
					zap.Error(err))
				return f.handleAuthFailure(401, "Unauthorized: Invalid bearer token")
			}

			f.logger.Debug("WebSocket: Bearer token validated successfully",
				zap.String("user_id", session.UserID),
				zap.String("trace_id", traceID))
			return f.handleAuthSuccess(header, session)
		}
	}

	// Check for session cookie using per-provider cookie name (D-08, D-09).
	wsSessionHandler, err := f.getProviderHandler()
	if err != nil {
		f.logger.Error("WebSocket: Failed to resolve provider for session lookup",
			zap.String("trace_id", traceID),
			zap.Error(err))
		return f.handleAuthFailure(503, "Service Unavailable: Authentication service temporarily unavailable")
	}
	sessionID, err := wsSessionHandler.GetSessionCookie(header)
	if err != nil {
		f.logger.Debug("WebSocket: No valid session cookie found",
			zap.String("path", sanitizePathForLogging(path)),
			zap.String("trace_id", traceID),
			zap.Error(err))
		return f.handleAuthFailure(401, "Unauthorized: No valid session or token found")
	}

	session, err := f.sessionStore.Get(sessionID)
	if err != nil {
		f.logger.Debug("WebSocket: Invalid session",
			zap.String("session_id", sessionID),
			zap.String("trace_id", traceID),
			zap.Error(err))
		return f.handleAuthFailure(401, "Unauthorized: Invalid session")
	}

	// SESS-02: verify session-provider binding (D-05).
	if matched, expectedProvider := f.verifySessionProvider(session); !matched {
		f.logger.Warn("WebSocket: Session provider mismatch — rejecting session",
			zap.String("session_provider", session.ProviderName),
			zap.String("expected_provider", expectedProvider),
			zap.String("session_id", session.ID))
		_ = f.sessionStore.Delete(session.ID)
		wsSessionHandler.DeleteSessionCookie(header)
		deleteCookieStr, _ := header.Get("set-cookie")
		return f.handleAuthFailureWithCookie(401, "Unauthorized: Session from wrong provider", deleteCookieStr)
	}

	// Check if session is expired
	if !f.isValidSession(session) {
		f.logger.Debug("WebSocket: Session expired",
			zap.String("session_id", session.ID),
			zap.String("trace_id", traceID))
		return f.handleAuthFailure(401, "Unauthorized: Session expired")
	}

	// Same IdP revalidation and refresh as the HTTP path, so a revoked or
	// disabled user loses WebSocket access too (issue #13). Handshakes cannot
	// follow a login redirect, so an invalid session gets 401.
	if wsSessionHandler.IsNeedValidateSession(session) {
		return f.handleAsyncValidateSession(header, session, traceID, func(err error) {
			f.logger.Debug("WebSocket: Session revalidation failed",
				zap.String("session_id", session.ID),
				zap.String("trace_id", traceID),
				zap.Error(err))
			f.handleAuthFailure(401, "Unauthorized: Session expired")
		})
	}

	f.logger.Debug("WebSocket: Session validated successfully",
		zap.String("session_id", session.ID),
		zap.String("user_id", session.UserID),
		zap.String("trace_id", traceID))

	return f.handleAuthSuccess(header, session)
}
