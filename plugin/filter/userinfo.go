package filter

import (
	"encoding/json"

	"github.com/envoyproxy/envoy/contrib/golang/common/go/api"
	"go.uber.org/zap"
)

// UserInfo represents the user information response
type UserInfo struct {
	Name  string    `json:"name"`
	Email string    `json:"email"`
	Apps  []AppInfo `json:"apps"`
}

// AppInfo represents application information
type AppInfo struct {
	App string `json:"app"`
	URL string `json:"url"`
}

// serveUserInfo serves the user information endpoint
func (f *Filter) serveUserInfo(header api.RequestHeaderMap) api.StatusType {
	// Check if user is authenticated
	if f.currentSession == nil {
		f.logger.Debug("User info requested but no session found")
		return f.handleAuthFailure(401, "Unauthorized: No active session")
	}

	// Extract user info from session claims
	userName := ""
	userEmail := ""

	if f.currentSession.Claims != nil {
		// Try to get name from various possible claims
		if name, ok := f.currentSession.Claims["name"].(string); ok && name != "" {
			userName = name
		} else if name, ok := f.currentSession.Claims["preferred_username"].(string); ok && name != "" {
			userName = name
		} else if name, ok := f.currentSession.Claims["given_name"].(string); ok && name != "" {
			// If we have given_name and family_name, combine them
			if familyName, ok := f.currentSession.Claims["family_name"].(string); ok && familyName != "" {
				userName = name + " " + familyName
			} else {
				userName = name
			}
		}

		// Get email
		if email, ok := f.currentSession.Claims["email"].(string); ok {
			userEmail = email
		}
	}

	// Collect applications from all clusters with SSO configuration
	apps := []AppInfo{}
	for _, cluster := range f.config.Clusters {
		if cluster.SsoAppURL != "" && cluster.SsoAppName != "" {
			apps = append(apps, AppInfo{
				App: cluster.SsoAppName,
				URL: cluster.SsoAppURL,
			})
		}
	}

	// Create response
	userInfo := UserInfo{
		Name:  userName,
		Email: userEmail,
		Apps:  apps,
	}

	// Marshal to JSON
	jsonData, err := json.Marshal(userInfo)
	if err != nil {
		f.logger.Error("Failed to marshal user info",
			zap.Error(err))
		return f.handleAuthFailure(500, "Internal Server Error: Failed to generate user info")
	}

	// Set response headers
	header.Set(":status", "200")
	header.Set("content-type", "application/json; charset=utf-8")
	header.Set("cache-control", "no-cache, no-store, must-revalidate")

	// Send the JSON response
	f.logger.Debug("User info served successfully",
		zap.String("name", userName),
		zap.String("email", userEmail),
		zap.Int("app_count", len(apps)))

	return f.recordAndSendLocalReply(
		200,
		string(jsonData),
		map[string][]string{
			"content-type":  {"application/json; charset=utf-8"},
			"cache-control": {"no-cache, no-store, must-revalidate"},
		},
		-1,
		"",
	)
}

// handleUserInfo handles the /oauth/user endpoint
func (f *Filter) handleUserInfo(header api.RequestHeaderMap) api.StatusType {
	path, _ := header.Get(":path")
	traceID := f.getTraceID(header)

	f.logger.Debug("Handling user info request",
		zap.String("path", sanitizePathForLogging(path)),
		zap.String("trace_id", traceID))

	// Check for session cookie using per-provider cookie name (D-08, D-09).
	userInfoHandler, err := f.getProviderHandler()
	if err != nil {
		f.logger.Error("Failed to resolve provider for user info request",
			zap.String("trace_id", traceID),
			zap.Error(err))
		return f.handleAuthFailure(503, "Service Unavailable: Authentication service temporarily unavailable")
	}
	sessionID, err := userInfoHandler.GetSessionCookie(header)
	if err != nil {
		f.logger.Debug("No session cookie found for user info request",
			zap.String("trace_id", traceID),
			zap.Error(err))
		return f.handleAuthFailure(401, "Unauthorized: No session cookie")
	}

	// Get session from store
	session, err := f.sessionStore.Get(sessionID)
	if err != nil {
		f.logger.Debug("Invalid session for user info request",
			zap.String("session_id", sessionID),
			zap.String("trace_id", traceID),
			zap.Error(err))
		return f.handleAuthFailure(401, "Unauthorized: Invalid session")
	}

	// SESS-02: verify session-provider binding (D-05).
	if matched, expectedProvider := f.verifySessionProvider(session); !matched {
		f.logger.Warn("User info: Session provider mismatch — rejecting session",
			zap.String("session_provider", session.ProviderName),
			zap.String("expected_provider", expectedProvider),
			zap.String("session_id", session.ID))
		_ = f.sessionStore.Delete(session.ID)
		userInfoHandler.DeleteSessionCookie(header)
		deleteCookieStr, _ := header.Get("set-cookie")
		return f.handleAuthFailureWithCookie(401, "Unauthorized: Session from wrong provider", deleteCookieStr)
	}

	// Store the session for use in serveUserInfo
	f.currentSession = session

	// Serve the user info
	return f.serveUserInfo(header)
}
