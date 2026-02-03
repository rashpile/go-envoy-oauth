package filter

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/envoyproxy/envoy/contrib/golang/common/go/api"
)

// handleOfflineConsent displays the consent page for API key generation
func (f *Filter) handleOfflineConsent(header api.RequestHeaderMap) api.StatusType {
	// Check if API key feature is enabled
	if !f.config.EnableAPIKey {
		return f.handleAuthFailure(404, "API key generation feature is disabled")
	}

	// Ensure handlers are initialized
	if err := f.ensureHandlersInitialized(); err != nil {
		return f.handleAuthFailure(500, fmt.Sprintf("Failed to initialize handlers: %v", err))
	}

	if f.offlineTokenHandler == nil {
		return f.handleAuthFailure(500, "API key generation feature not available")
	}

	statusCode, body, headers := f.offlineTokenHandler.HandleConsentPage(header)
	return f.recordAndSendLocalReply(statusCode, body, headers, 0, "")
}

// handleOfflineRedirect initiates OAuth flow for API key generation
func (f *Filter) handleOfflineRedirect(header api.RequestHeaderMap) api.StatusType {
	// Check if API key feature is enabled
	if !f.config.EnableAPIKey {
		return f.handleAuthFailure(404, "API key generation feature is disabled")
	}

	// Ensure handlers are initialized
	if err := f.ensureHandlersInitialized(); err != nil {
		return f.handleAuthFailure(500, fmt.Sprintf("Failed to initialize handlers: %v", err))
	}

	if f.offlineTokenHandler == nil {
		return f.handleAuthFailure(500, "API key generation feature not available")
	}

	statusCode, body, headers := f.offlineTokenHandler.HandleOfflineAuthRedirect(header)
	return f.recordAndSendLocalReply(statusCode, body, headers, 0, "")
}

// handleOfflineCallback processes OAuth callback for API key generation
func (f *Filter) handleOfflineCallback(header api.RequestHeaderMap, path string) api.StatusType {
	// Check if API key feature is enabled
	if !f.config.EnableAPIKey {
		return f.handleAuthFailure(404, "API key generation feature is disabled")
	}

	// Ensure handlers are initialized
	if err := f.ensureHandlersInitialized(); err != nil {
		return f.handleAuthFailure(500, fmt.Sprintf("Failed to initialize handlers: %v", err))
	}

	if f.offlineTokenHandler == nil {
		return f.handleAuthFailure(500, "API key generation feature not available")
	}

	// Extract query parameters
	query := ""
	if idx := strings.Index(path, "?"); idx != -1 {
		query = path[idx+1:]
	}

	statusCode, body, headers := f.offlineTokenHandler.HandleOfflineCallback(header, query)
	return f.recordAndSendLocalReply(statusCode, body, headers, 0, "")
}

func (f *Filter) extractAPIToken(header api.RequestHeaderMap) string {
	// Check API-KEY header first
	if apiKey, _ := header.Get("api-key"); apiKey != "" {
		return apiKey
	}

	// Also check X-API-KEY header (common variation)
	if apiKey, _ := header.Get("x-api-key"); apiKey != "" {
		return apiKey
	}

	// Check query parameter
	path, _ := header.Get(":path")
	if path != "" {
		// Parse query string from path
		if idx := strings.Index(path, "?"); idx > 0 {
			query := path[idx+1:]
			values, err := url.ParseQuery(query)
			if err == nil {
				if apiKey := values.Get("auth-api-key"); apiKey != "" {
					return apiKey
				}
			}
		}
	}

	return ""
}

// isAPITokenFromQuery checks if API token came from query parameter
func (f *Filter) isAPITokenFromQuery(header api.RequestHeaderMap) bool {
	path, _ := header.Get(":path")
	if path == "" {
		return false
	}
	return strings.Contains(path, "auth-api-key=") && !strings.Contains(path, "redirect=false")
}
