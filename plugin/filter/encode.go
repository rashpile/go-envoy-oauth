package filter

import (
	"fmt"
	"strings"
	"time"

	"github.com/envoyproxy/envoy/contrib/golang/common/go/api"
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

// buildSSOScriptTag builds the script tag with user info
func (f *Filter) buildSSOScriptTag() string {
	var builder strings.Builder

	// Add meta tags for user info if available
	if f.currentSession != nil && f.currentSession.Claims != nil {
		// Try to extract user info from claims
		userName := ""
		userEmail := ""

		if name, ok := f.currentSession.Claims["name"].(string); ok {
			userName = name
		} else if name, ok := f.currentSession.Claims["preferred_username"].(string); ok {
			userName = name
		}

		if email, ok := f.currentSession.Claims["email"].(string); ok {
			userEmail = email
		}

		// Add meta tags if we have user info
		if userName != "" {
			builder.WriteString(fmt.Sprintf("\n<meta name=\"sso-user-name\" content=\"%s\">", escapeHTMLAttribute(userName)))
		}
		if userEmail != "" {
			builder.WriteString(fmt.Sprintf("\n<meta name=\"sso-user-email\" content=\"%s\">", escapeHTMLAttribute(userEmail)))
		}
	}

	// Add app URLs and names from all clusters with SSO configuration
	appIndex := 0
	for _, cluster := range f.config.Clusters {
		if cluster.SsoAppURL != "" && cluster.SsoAppName != "" {
			builder.WriteString(fmt.Sprintf("\n<meta name=\"sso-app-%d-url\" content=\"%s\">", appIndex, escapeHTMLAttribute(cluster.SsoAppURL)))
			builder.WriteString(fmt.Sprintf("\n<meta name=\"sso-app-%d-name\" content=\"%s\">", appIndex, escapeHTMLAttribute(cluster.SsoAppName)))
			appIndex++
		}
	}

	// Add the script tag
	builder.WriteString("\n<script src=\"/oauth/assets/sso.js\" defer></script>\n")

	return builder.String()
}

// escapeHTMLAttribute escapes a string for use in HTML attribute
func escapeHTMLAttribute(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, "\"", "&quot;")
	s = strings.ReplaceAll(s, "'", "&#39;")
	return s
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

	// Log access if enabled
	if IsAccessLogEnabled() && f.requestStart.Unix() > 0 {
		statusStr, _ := header.Get(":status")
		statusCode := 200 // default
		if statusStr != "" {
			// Parse status code from string
			if len(statusStr) >= 3 {
				switch statusStr[0] {
				case '2':
					statusCode = 200
				case '3':
					statusCode = 300
				case '4':
					statusCode = 400
				case '5':
					statusCode = 500
				}
				// Try to parse the actual code
				var code int
				if n, _ := fmt.Sscanf(statusStr, "%d", &code); n == 1 {
					statusCode = code
				}
			}
		}

		// Calculate response time
		responseTime := time.Since(f.requestStart).Seconds() * 1000 // convert to ms

		// Log the access
		LogAccess(f.requestMethod, f.requestPath, f.requestHost,
			f.clientIP, f.userAgent, statusCode, responseTime)

		// Reset the request tracking
		f.requestStart = time.Time{}
	}

	return api.Continue
}
