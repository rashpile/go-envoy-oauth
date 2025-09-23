package filter

import (
	"fmt"
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
	f.callbacks.DecoderFilterCallbacks().SendLocalReply(
		statusCode,
		body,
		headers,
		0,
		"",
	)
	return api.LocalReply
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
	f.callbacks.DecoderFilterCallbacks().SendLocalReply(
		statusCode,
		body,
		headers,
		0,
		"",
	)
	return api.LocalReply
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
	f.callbacks.DecoderFilterCallbacks().SendLocalReply(
		statusCode,
		body,
		headers,
		0,
		"",
	)
	return api.LocalReply
}
