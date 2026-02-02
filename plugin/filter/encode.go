package filter

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/envoyproxy/envoy/contrib/golang/common/go/api"
	"github.com/rashpile/go-envoy-oauth/plugin/metrics"
	"go.uber.org/zap"
)

func (f *Filter) EncodeData(buffer api.BufferInstance, endStream bool) api.StatusType {
	// Only process if we need to inject SSO script
	c := f.config.Clusters[f.cluster]

	if !c.SsoInjection || !f.shouldInjectSSO {
		return api.Continue
	}

	// Get the buffer content
	content := buffer.Bytes()
	if len(content) == 0 {
		return api.Continue
	}

	// Check if this is HTML content (by looking for head tag)
	contentStr := string(content)

	// Find the position to inject the script (after <head> or </head>)
	injectionPoint := f.findInjectionPoint(contentStr)
	if injectionPoint == -1 {
		// No head tag found, don't modify
		return api.Continue
	}

	// Build the script tag with user info
	scriptTag := f.buildSSOScriptTag()

	// Inject the script
	modified := contentStr[:injectionPoint] + scriptTag + contentStr[injectionPoint:]

	// Update the buffer
	if err := buffer.SetString(modified); err != nil {
		f.logger.Error("Failed to inject SSO script",
			zap.Error(err))
		return api.Continue
	}

	f.logger.Debug("SSO script injected successfully",
		zap.Int("injection_point", injectionPoint),
		zap.Int("original_size", len(content)),
		zap.Int("modified_size", len(modified)))

	// Mark that we've injected the script for this response
	f.shouldInjectSSO = false

	return api.Continue
}

// findInjectionPoint finds the best position to inject the SSO script
func (f *Filter) findInjectionPoint(html string) int {
	htmlLower := strings.ToLower(html)

	// Try to find opening head tag and inject after it
	headStart := strings.Index(htmlLower, "<head")
	if headStart != -1 {
		// Find the end of the opening tag
		tagEnd := strings.Index(html[headStart:], ">")
		if tagEnd != -1 {
			return headStart + tagEnd + 1
		}
	}

	// If no opening head tag, try to find closing head tag and inject before it
	headEnd := strings.Index(htmlLower, "</head>")
	if headEnd != -1 {
		return headEnd
	}

	// No suitable injection point found
	return -1
}

// buildSSOScriptTag builds the script tag
func (f *Filter) buildSSOScriptTag() string {
	// Simply inject the script tag - user data will be fetched via /oauth/user API
	return "\n<script src=\"/oauth/assets/sso.js\" defer></script>\n"
}

// EncodeHeaders is called when response headers are being sent
// This can be used to add cookies to responses after successful auth
func (f *Filter) EncodeHeaders(header api.ResponseHeaderMap, endStream bool) api.StatusType {
	// Check if we should inject SSO script
	contentType, _ := header.Get("content-type")
	if contentType != "" && strings.Contains(strings.ToLower(contentType), "text/html") {
		// This is an HTML response, we should inject SSO script if user is authenticated
		if f.currentSession != nil {
			f.shouldInjectSSO = true
			f.logger.Debug("HTML response detected, will inject SSO script",
				zap.String("content_type", contentType),
				zap.Bool("has_session", f.currentSession != nil))
		}
	}
	c := f.config.Clusters[f.cluster]

	if f.currentSession != nil && c.SsoInjection && f.shouldInjectSSO {
		contentLength, _ := header.Get("content-length")
		if contentLength != "" {
			contentLengthInt, _ := strconv.Atoi(contentLength)
			if contentLengthInt > 0 {
				header.Set("content-length", strconv.Itoa(contentLengthInt+len(f.buildSSOScriptTag())))
			}
		}
	}

	// Record metrics and access log if request tracking is active
	if !f.requestStart.IsZero() {
		statusStr, _ := header.Get(":status")
		statusCode := parseStatusCode(statusStr)
		duration := time.Since(f.requestStart)

		// Record request metrics (always, even if access log is disabled)
		metrics.RecordRequest(statusCode, duration.Seconds())

		// Log access if enabled
		if IsAccessLogEnabled() {
			responseTime := duration.Seconds() * 1000 // convert to ms
			LogAccess(f.requestMethod, f.requestPath, f.requestHost,
				f.clientIP, f.userAgent, statusCode, responseTime)
		}

		// Reset the request tracking to prevent double-counting
		f.requestStart = time.Time{}
	}

	return api.Continue
}

// parseStatusCode parses an HTTP status code from a string.
// Returns 200 as default if parsing fails.
func parseStatusCode(statusStr string) int {
	if statusStr == "" {
		return 200
	}

	// Try to parse the actual numeric code
	var code int
	if n, _ := fmt.Sscanf(statusStr, "%d", &code); n == 1 {
		return code
	}

	// Fallback: determine from first digit
	if len(statusStr) >= 1 {
		switch statusStr[0] {
		case '2':
			return 200
		case '3':
			return 300
		case '4':
			return 400
		case '5':
			return 500
		}
	}

	return 200
}
