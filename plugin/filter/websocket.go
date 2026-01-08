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
	// Check global WebSocket exclude paths
	for _, excluded := range f.config.WebSocketExcludePaths {
		if path == excluded || strings.HasPrefix(path, excluded) {
			return true
		}
	}

	// Check cluster-specific WebSocket exclusions
	if clusterConfig, ok := f.config.Clusters[cluster]; ok {
		for _, excluded := range clusterConfig.WebSocketExcludePaths {
			if path == excluded || strings.HasPrefix(path, excluded) {
				return true
			}
		}
	}

	return false
}

// handleWebSocketAuth authenticates WebSocket upgrade requests
// Unlike regular HTTP requests, WebSocket handshakes cannot follow redirects,
// so we return 401 Unauthorized instead of redirecting to login
func (f *Filter) handleWebSocketAuth(header api.RequestHeaderMap, path string, traceID string) api.StatusType {
	// Initialize OAuth handler if needed
	if f.oauthHandler == nil {
		if err := f.ensureHandlersInitialized(); err != nil {
			f.logger.Warn("OAuth handler unavailable for WebSocket auth",
				zap.String("path", sanitizePathForLogging(path)),
				zap.String("trace_id", traceID),
				zap.Error(err))
			return f.handleAuthFailure(503, "Service Unavailable: Authentication service temporarily unavailable")
		}
	}

	// Check for bearer token authentication first (common for WebSocket)
	if f.config.EnableBearerToken {
		token := f.extractBearerToken(header)
		if token != "" {
			f.logger.Debug("WebSocket: Bearer token found, validating",
				zap.String("trace_id", traceID))

			session, err := f.oauthHandler.ValidateBearerToken(context.Background(), token)
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

	// Check for session cookie
	sessionID, err := f.cookieManager.GetCookie(header)
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

	// Check if session is expired
	if !f.isValidSession(session) {
		f.logger.Debug("WebSocket: Session expired",
			zap.String("session_id", session.ID),
			zap.String("trace_id", traceID))
		return f.handleAuthFailure(401, "Unauthorized: Session expired")
	}

	f.logger.Debug("WebSocket: Session validated successfully",
		zap.String("session_id", session.ID),
		zap.String("user_id", session.UserID),
		zap.String("trace_id", traceID))

	return f.handleAuthSuccess(header, session)
}