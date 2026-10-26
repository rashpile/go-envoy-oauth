package filter

import (
	"fmt"
	"net/http"
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
	if statusCode == http.StatusFound && !f.attachOfflineStateCookie(headers) {
		return f.handleAuthFailure(500, "Internal Server Error: OAuth state could not be bound to the browser")
	}
	return f.recordAndSendLocalReply(statusCode, body, headers, 0, "")
}

// attachOfflineStateCookie turns the binding secret returned by the offline
// handler into the state cookie on the redirect response and removes the
// internal header. It reports false if the redirect has no state or secret.
func (f *Filter) attachOfflineStateCookie(headers map[string][]string) bool {
	var state, bindingSecret string
	if locs := headers["Location"]; len(locs) > 0 {
		state = stateFromAuthURL(locs[0])
	}
	if secrets := headers[oauth.StateBindingHeader]; len(secrets) > 0 {
		bindingSecret = secrets[0]
	}
	delete(headers, oauth.StateBindingHeader)
	if state == "" || bindingSecret == "" {
		return false
	}
	headers["Set-Cookie"] = append(headers["Set-Cookie"], f.stateSetCookie(state, bindingSecret, offlineCallback, stateCookieMaxAge))
	return true
}

// offlineStateBound reports whether the offline callback for state comes from
// the browser that started it.
func (f *Filter) offlineStateBound(header api.RequestHeaderMap, state string) bool {
	bindingHash := ""
	if stateSession, err := f.sessionStore.Get(state); err == nil && stateSession != nil {
		bindingHash, _ = stateSession.Claims["binding_hash"].(string)
	}
	return stateCookieMatches(header, state, bindingHash)
}

// handleOfflineCallback processes OAuth callback for API key generation
func (f *Filter) handleOfflineCallback(header api.RequestHeaderMap, path string) api.StatusType {
	// Check if API key feature is enabled
	if !f.config.EnableAPIKey {
		return f.handleAuthFailure(404, "API key generation feature is disabled")
	}

	// Extract query parameters
	query := ""
	if idx := strings.Index(path, "?"); idx != -1 {
		query = path[idx+1:]
	}

	// The API-key login must finish in the browser that started it (issue #11).
	values, _ := url.ParseQuery(query)
	state := values.Get("state")
	if !f.offlineStateBound(header, state) {
		return f.handleAuthFailure(400, "This sign-in was started in another browser. Start again from /oauth/offline.")
	}

	offlineHandler, err := f.getOfflineTokenHandler()
	if err != nil {
		f.logger.Error("Failed to get offline token handler for callback", zap.Error(err))
		return f.errorHandler.HandleIDPUnavailable()
	}

	// The code exchange calls the IdP, which may be served through this same
	// Envoy: run it off the worker thread, like handleAsyncCallback.
	clearState := f.stateSetCookie(state, "", offlineCallback, -1)
	go func() {
		defer f.callbacks.DecoderFilterCallbacks().RecoverPanic()
		statusCode, body, headers := offlineHandler.HandleOfflineCallback(header, query)
		if headers == nil {
			headers = map[string][]string{}
		}
		headers["Set-Cookie"] = append(headers["Set-Cookie"], clearState)
		f.recordAndSendLocalReply(statusCode, body, headers, 0, "")
	}()
	return api.Running
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
