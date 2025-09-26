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

	// Capture request information for access logging
	if IsAccessLogEnabled() {
		f.requestStart = time.Now()
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

	// Initialize OAuth handler if needed (before handling any OAuth endpoints)
	if f.oauthHandler == nil {
		return f.handleAsyncOAuthHandler(header, traceID, path, f.handleDecodeHeaders)
	}
	if f.config.EnableAPIKey && f.config.EnableBearerToken && f.extractAPIToken(header) != "" {
		return f.handleAsyncDecodeHeaders(header, path, traceID, f.handleDecodeHeaders)
	}
	return f.handleDecodeHeaders(header, path, traceID)
}
