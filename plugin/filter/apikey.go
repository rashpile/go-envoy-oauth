package filter

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/envoyproxy/envoy/contrib/golang/common/go/api"
	"github.com/rashpile/go-envoy-oauth/plugin/oauth"
	"go.uber.org/zap"
)

// getOfflineTokenHandler resolves an OfflineTokenHandler from the provider registry.
// The offline token handler is created on-demand from the resolved OAuthHandler.
func (f *Filter) getOfflineTokenHandler() (*oauth.OfflineTokenHandler, error) {
	handler, err := f.getProviderHandler()
	if err != nil {
		return nil, fmt.Errorf("failed to resolve provider handler: %w", err)
	}
	oauthHandlerImpl, ok := handler.(*oauth.OAuthHandlerImpl)
	if !ok {
		return nil, fmt.Errorf("provider handler unavailable (type: %T)", handler)
	}
	offlineHandler, err := oauth.NewOfflineTokenHandler(oauthHandlerImpl, f.logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create offline token handler: %w", err)
	}
	return offlineHandler, nil
}

// handleOfflineConsent displays the consent page for API key generation
func (f *Filter) handleOfflineConsent(header api.RequestHeaderMap) api.StatusType {
	// Check if API key feature is enabled
	if !f.config.EnableAPIKey {
		return f.handleAuthFailure(404, "API key generation feature is disabled")
	}

	offlineHandler, err := f.getOfflineTokenHandler()
	if err != nil {
		f.logger.Error("Failed to get offline token handler for consent", zap.Error(err))
		return f.errorHandler.HandleIDPUnavailable()
	}

	statusCode, body, headers := offlineHandler.HandleConsentPage(header)
	return f.recordAndSendLocalReply(statusCode, body, headers, 0, "")
}

// handleOfflineRedirect initiates OAuth flow for API key generation
func (f *Filter) handleOfflineRedirect(header api.RequestHeaderMap) api.StatusType {
	// Check if API key feature is enabled
	if !f.config.EnableAPIKey {
		return f.handleAuthFailure(404, "API key generation feature is disabled")
	}

	offlineHandler, err := f.getOfflineTokenHandler()
	if err != nil {
		f.logger.Error("Failed to get offline token handler for redirect", zap.Error(err))
		return f.errorHandler.HandleIDPUnavailable()
	}

	statusCode, body, headers := offlineHandler.HandleOfflineAuthRedirect(header)
	return f.recordAndSendLocalReply(statusCode, body, headers, 0, "")
}

// handleOfflineCallback processes OAuth callback for API key generation
func (f *Filter) handleOfflineCallback(header api.RequestHeaderMap, path string) api.StatusType {
	// Check if API key feature is enabled
	if !f.config.EnableAPIKey {
		return f.handleAuthFailure(404, "API key generation feature is disabled")
	}

	offlineHandler, err := f.getOfflineTokenHandler()
	if err != nil {
		f.logger.Error("Failed to get offline token handler for callback", zap.Error(err))
		return f.errorHandler.HandleIDPUnavailable()
	}

	// Extract query parameters
	query := ""
	if idx := strings.Index(path, "?"); idx != -1 {
		query = path[idx+1:]
	}

	statusCode, body, headers := offlineHandler.HandleOfflineCallback(header, query)
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
