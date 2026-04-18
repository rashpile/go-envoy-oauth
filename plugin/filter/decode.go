package filter

import (
	"fmt"
	"strings"
	"time"

	"github.com/envoyproxy/envoy/contrib/golang/common/go/api"
	"go.uber.org/zap"
)

// DecodeHeaders is called when request headers are received
func (f *Filter) DecodeHeaders(header api.RequestHeaderMap, endStream bool) api.StatusType {
	method, _ := header.Get(":method")
	path, _ := header.Get(":path")
	host, _ := header.Get(":authority")
	traceID := f.getTraceID(header)

	// Start request timing for metrics (always, independent of access logging)
	f.requestStart = time.Now()

	// Capture additional request information for access logging
	if IsAccessLogEnabled() {
		f.requestMethod = method
		f.requestPath = path
		f.requestHost = host
		f.clientIP, _ = header.Get("x-forwarded-for")
		if f.clientIP == "" {
			f.clientIP, _ = header.Get("x-real-ip")
		}
		f.userAgent, _ = header.Get("user-agent")
	}

	f.logger.Debug("Processing request headers",
		zap.String("method", method),
		zap.String("path", sanitizePathForLogging(path)),
		zap.String("host", host),
		zap.String("trace_id", traceID),
	)

	// Strip client-supplied identity headers (T-04-01) before any early-return
	// branch so the guarantee holds on excluded paths and skip-auth paths too.
	// Authenticated paths re-Set these headers from the verified session.
	// Skip-auth deployments must carry identity in skip_auth_header_name itself;
	// this filter does not forward client-supplied X-User-* / X-Auth-Provider.
	f.stripUntrustedHeaders(header)

	// Get the request path and cluster
	// cluster, _ := header.Get(":authority")
	cluster := getClusterName(f.callbacks)
	f.cluster = cluster

	f.logger.Debug(fmt.Sprintf("path: %s, cluster: %s, trace_id: %s", sanitizePathForLogging(path), cluster, traceID))

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
			zap.String("path", sanitizePathForLogging(path)),
			zap.String("trace_id", traceID))
		return api.Continue
	}

	// Check if this is a WebSocket upgrade request
	isWebSocket := f.isWebSocketUpgrade(header)
	if isWebSocket {
		f.logger.Debug("WebSocket upgrade request detected",
			zap.String("path", sanitizePathForLogging(path)),
			zap.String("trace_id", traceID))

		// Check if WebSocket path is excluded from auth
		if f.isWebSocketPathExcluded(path, cluster) {
			f.logger.Debug("WebSocket path excluded from authentication",
				zap.String("path", sanitizePathForLogging(path)),
				zap.String("trace_id", traceID))
			return api.Continue
		}

		// For WebSocket, we authenticate but handle failures differently
		// Browsers cannot follow redirects during WebSocket handshake,
		// so we return 401 instead of redirecting to login
		return f.handleWebSocketAuth(header, path, traceID)
	}

	// Safety check: registry must be non-nil (guaranteed if Parse() succeeded)
	if f.providerRegistry == nil {
		f.logger.Error("Provider registry is nil — configuration error, rejecting request",
			zap.String("trace_id", traceID))
		return f.recordAndSendLocalReply(503, "Identity provider unavailable",
			createAuthErrorHeaders(), -1, "provider_unavailable")
	}
	if f.config.EnableAPIKey && f.config.EnableBearerToken && f.extractAPIToken(header) != "" {
		return f.handleAsyncDecodeHeaders(header, path, traceID, f.handleDecodeHeaders)
	}
	return f.handleDecodeHeaders(header, path, traceID)
}
