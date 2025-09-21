package oauth

import (
	"context"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/envoyproxy/envoy/contrib/golang/common/go/api"
	"github.com/rashpile/go-envoy-oauth/plugin/session"
	"golang.org/x/oauth2"
	"go.uber.org/zap"
)

const consentPageHTML = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OAuth Offline Access Consent</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        .container {
            background: white;
            border-radius: 12px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            max-width: 500px;
            width: 100%;
            padding: 40px;
        }
        h1 {
            color: #333;
            margin-bottom: 10px;
            font-size: 28px;
        }
        .subtitle {
            color: #666;
            margin-bottom: 30px;
            font-size: 16px;
        }
        .info-box {
            background: #f7f9fc;
            border-left: 4px solid #667eea;
            padding: 20px;
            margin-bottom: 30px;
            border-radius: 4px;
        }
        .info-box h3 {
            color: #333;
            margin-bottom: 10px;
            font-size: 18px;
        }
        .info-box p {
            color: #555;
            line-height: 1.6;
            margin-bottom: 10px;
        }
        .info-box ul {
            margin-left: 20px;
            color: #555;
        }
        .info-box li {
            margin-bottom: 5px;
        }
        .warning {
            background: #fff3cd;
            border: 1px solid #ffc107;
            padding: 15px;
            border-radius: 4px;
            margin-bottom: 30px;
        }
        .warning-icon {
            color: #856404;
            font-weight: bold;
            margin-right: 5px;
        }
        .btn {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            padding: 14px 30px;
            font-size: 16px;
            border-radius: 6px;
            cursor: pointer;
            width: 100%;
            font-weight: 600;
            transition: transform 0.2s, box-shadow 0.2s;
        }
        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 20px rgba(102, 126, 234, 0.4);
        }
        .btn:active {
            transform: translateY(0);
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>API Key Generation</h1>
        <p class="subtitle">Generate an API key for programmatic access</p>

        <div class="info-box">
            <h3>What is an API Key?</h3>
            <p>An API key allows you to access protected resources programmatically without requiring browser-based authentication. This key can be used to:</p>
            <ul>
                <li>Automate API requests</li>
                <li>Access resources from scripts or CI/CD pipelines</li>
                <li>Maintain long-term access without browser sessions</li>
            </ul>
        </div>

        <div class="warning">
            <span class="warning-icon">⚠️</span>
            <strong>Security Notice:</strong> The API key you'll receive has long-term access to your account. Keep it secure and never share it publicly.
        </div>

        <div class="info-box">
            <p><strong>Authentication Required:</strong> For security reasons, you will be asked to re-authenticate even if you're already logged in.</p>
        </div>

        <form action="/oauth/offline" method="GET">
            <button type="submit" class="btn">Generate API Key</button>
        </form>
    </div>
</body>
</html>
`

const tokenDisplayHTML = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Your API Key</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        .container {
            background: white;
            border-radius: 12px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            max-width: 600px;
            width: 100%;
            padding: 40px;
        }
        h1 {
            color: #333;
            margin-bottom: 10px;
            font-size: 28px;
        }
        .success-icon {
            color: #28a745;
            font-size: 48px;
            margin-bottom: 20px;
        }
        .subtitle {
            color: #666;
            margin-bottom: 30px;
            font-size: 16px;
        }
        .token-container {
            background: #f7f9fc;
            border: 2px solid #e1e4e8;
            border-radius: 6px;
            padding: 20px;
            margin-bottom: 20px;
        }
        .token-label {
            color: #555;
            font-size: 14px;
            font-weight: 600;
            margin-bottom: 10px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .token-input {
            width: 100%;
            padding: 12px;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            font-size: 14px;
            background: white;
            color: #333;
            margin-bottom: 10px;
            word-break: break-all;
            min-height: 100px;
            resize: vertical;
        }
        .btn-group {
            display: flex;
            gap: 10px;
        }
        .btn {
            padding: 10px 20px;
            font-size: 14px;
            border-radius: 4px;
            cursor: pointer;
            border: none;
            font-weight: 600;
            transition: all 0.2s;
            flex: 1;
        }
        .btn-primary {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }
        .btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(102, 126, 234, 0.4);
        }
        .btn-secondary {
            background: #e1e4e8;
            color: #333;
        }
        .btn-secondary:hover {
            background: #d1d5da;
        }
        .info-box {
            background: #e3f2fd;
            border-left: 4px solid #2196F3;
            padding: 15px;
            margin-bottom: 20px;
            border-radius: 4px;
        }
        .info-box p {
            color: #1565C0;
            font-size: 14px;
            line-height: 1.6;
        }
        .copy-notification {
            position: fixed;
            bottom: 20px;
            right: 20px;
            background: #28a745;
            color: white;
            padding: 12px 20px;
            border-radius: 4px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
            opacity: 0;
            transform: translateY(20px);
            transition: all 0.3s;
            pointer-events: none;
        }
        .copy-notification.show {
            opacity: 1;
            transform: translateY(0);
        }
        code {
            background: #f1f3f5;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
            font-size: 13px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="success-icon">✓</div>
        <h1>API Key Generated Successfully</h1>
        <p class="subtitle">Your API key has been generated. Store it securely.</p>

        <div class="info-box">
            <p><strong>How to use this API key:</strong></p>
            <p>Exchange this API key for an access token using: <code>POST /token</code> endpoint with <code>grant_type=refresh_token</code></p>
        </div>

        <div class="token-container">
            <div class="token-label">API Key</div>
            <textarea id="apiKey" class="token-input" readonly>{{.RefreshToken}}</textarea>
            <div class="btn-group">
                <button onclick="copyToken('apiKey')" class="btn btn-primary">Copy API Key</button>
                <button onclick="downloadToken()" class="btn btn-secondary">Download as File</button>
            </div>
        </div>


        <div class="copy-notification" id="notification">
            API key copied to clipboard!
        </div>
    </div>

    <script>
        function copyToken(elementId) {
            const tokenElement = document.getElementById(elementId);
            tokenElement.select();
            tokenElement.setSelectionRange(0, 99999); // For mobile devices

            try {
                document.execCommand('copy');
                showNotification();
            } catch (err) {
                // Fallback for modern browsers
                navigator.clipboard.writeText(tokenElement.value).then(function() {
                    showNotification();
                }, function(err) {
                    console.error('Could not copy text: ', err);
                });
            }
        }

        function showNotification() {
            const notification = document.getElementById('notification');
            notification.classList.add('show');
            setTimeout(() => {
                notification.classList.remove('show');
            }, 3000);
        }

        function downloadToken() {
            const apiKey = document.getElementById('apiKey').value;
            const blob = new Blob([apiKey], { type: 'text/plain' });
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'api_key.txt';
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            document.body.removeChild(a);
        }
    </script>
</body>
</html>
`

// OfflineTokenHandler handles offline token requests
type OfflineTokenHandler struct {
	handler       *OAuthHandlerImpl
	logger        *zap.Logger
	consentTmpl   *template.Template
	tokenTmpl     *template.Template
}

// NewOfflineTokenHandler creates a new offline token handler
func NewOfflineTokenHandler(handler *OAuthHandlerImpl, logger *zap.Logger) (*OfflineTokenHandler, error) {
	consentTmpl, err := template.New("consent").Parse(consentPageHTML)
	if err != nil {
		return nil, fmt.Errorf("failed to parse consent template: %v", err)
	}

	tokenTmpl, err := template.New("token").Parse(tokenDisplayHTML)
	if err != nil {
		return nil, fmt.Errorf("failed to parse token template: %v", err)
	}

	return &OfflineTokenHandler{
		handler:     handler,
		logger:      logger,
		consentTmpl: consentTmpl,
		tokenTmpl:   tokenTmpl,
	}, nil
}

// HandleConsentPage displays the consent page for API key generation
func (h *OfflineTokenHandler) HandleConsentPage(header api.RequestHeaderMap) (int, string, map[string][]string) {
	h.logger.Debug("Displaying API key consent page")

	var buf strings.Builder
	if err := h.consentTmpl.Execute(&buf, nil); err != nil {
		h.logger.Error("Failed to render consent page", zap.Error(err))
		return http.StatusInternalServerError, "Internal Server Error", nil
	}

	headers := map[string][]string{
		"Content-Type": {"text/html; charset=utf-8"},
	}

	return http.StatusOK, buf.String(), headers
}

// HandleOfflineAuthRedirect initiates OAuth flow with offline_access scope for API key
func (h *OfflineTokenHandler) HandleOfflineAuthRedirect(header api.RequestHeaderMap) (int, string, map[string][]string) {
	h.logger.Debug("Initiating API key OAuth flow")

	// Generate state for offline flow
	state := generateRandomState() + "|offline"

	// Store state in temporary session
	stateSession := &session.Session{
		ID:        state,
		UserID:    "",
		Token:     "",
		Claims:    map[string]interface{}{"type": "offline_token"},
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}

	if err := h.handler.GetSessionStore().Store(stateSession); err != nil {
		h.logger.Error("Failed to store state", zap.Error(err))
		return http.StatusInternalServerError, "Failed to initiate OAuth flow", nil
	}

	// Create OAuth config with offline_access scope
	oauth2Config := h.handler.GetOAuthConfig(header)

	// Modify redirect URL to use offline-callback endpoint
	redirectURL := oauth2Config.RedirectURL
	if strings.Contains(redirectURL, "/oauth/callback") {
		redirectURL = strings.Replace(redirectURL, "/oauth/callback", "/oauth/offline-callback", 1)
	} else {
		// If no callback in URL, append offline-callback
		if !strings.HasSuffix(redirectURL, "/") {
			redirectURL += "/"
		}
		redirectURL += "oauth/offline-callback"
	}
	oauth2Config.RedirectURL = redirectURL

	// Add offline_access scope if not already present
	hasOfflineScope := false
	for _, scope := range oauth2Config.Scopes {
		if scope == "offline_access" {
			hasOfflineScope = true
			break
		}
	}
	if !hasOfflineScope {
		oauth2Config.Scopes = append(oauth2Config.Scopes, "offline_access")
	}

	// Generate auth URL with access_type=offline for refresh token and prompt=login to force re-authentication
	authURL := oauth2Config.AuthCodeURL(state,
		oauth2.AccessTypeOffline,
		oauth2.SetAuthURLParam("prompt", "login"))

	headers := map[string][]string{
		"Location": {authURL},
	}

	return http.StatusFound, "", headers
}

// HandleOfflineCallback processes the OAuth callback for API key generation
func (h *OfflineTokenHandler) HandleOfflineCallback(header api.RequestHeaderMap, query string) (int, string, map[string][]string) {
	h.logger.Debug("Processing API key OAuth callback")

	values, err := url.ParseQuery(query)
	if err != nil {
		h.logger.Error("Failed to parse query parameters", zap.Error(err))
		return http.StatusBadRequest, "Invalid request parameters", nil
	}

	// Validate state
	state := values.Get("state")
	if state == "" {
		return http.StatusBadRequest, "State parameter not found", nil
	}

	// Verify this is an API key generation flow
	if !strings.Contains(state, "|offline") {
		return http.StatusBadRequest, "Invalid state for API key generation flow", nil
	}

	// Get state session
	stateSession, err := h.handler.GetSessionStore().Get(state)
	if err != nil || time.Now().After(stateSession.ExpiresAt) {
		return http.StatusBadRequest, "Invalid or expired state parameter", nil
	}

	// Delete state session
	_ = h.handler.GetSessionStore().Delete(state)

	// Get authorization code
	code := values.Get("code")
	if code == "" {
		return http.StatusBadRequest, "Authorization code not found", nil
	}

	// Exchange code for tokens
	oauth2Config := h.handler.GetOAuthConfig(header)

	// Modify redirect URL to use offline-callback endpoint (must match the one used in auth redirect)
	redirectURL := oauth2Config.RedirectURL
	if strings.Contains(redirectURL, "/oauth/callback") {
		redirectURL = strings.Replace(redirectURL, "/oauth/callback", "/oauth/offline-callback", 1)
	} else {
		// If no callback in URL, append offline-callback
		if !strings.HasSuffix(redirectURL, "/") {
			redirectURL += "/"
		}
		redirectURL += "oauth/offline-callback"
	}
	oauth2Config.RedirectURL = redirectURL

	// Ensure offline_access scope
	hasOfflineScope := false
	for _, scope := range oauth2Config.Scopes {
		if scope == "offline_access" {
			hasOfflineScope = true
			break
		}
	}
	if !hasOfflineScope {
		oauth2Config.Scopes = append(oauth2Config.Scopes, "offline_access")
	}

	token, err := oauth2Config.Exchange(context.Background(), code, oauth2.AccessTypeOffline)
	if err != nil {
		h.logger.Error("Failed to exchange code for token", zap.Error(err))
		return http.StatusInternalServerError, "Failed to obtain token", nil
	}

	// Prepare token data for display
	tokenData := struct {
		RefreshToken string
	}{
		RefreshToken: token.RefreshToken,
	}

	// If no refresh token was returned, show error
	if tokenData.RefreshToken == "" {
		h.logger.Error("No refresh token received from provider")
		return http.StatusInternalServerError, "Failed to obtain API key. Ensure offline_access scope is configured in your OAuth provider.", nil
	}

	// Render token display page
	var buf strings.Builder
	if err := h.tokenTmpl.Execute(&buf, tokenData); err != nil {
		h.logger.Error("Failed to render API key display page", zap.Error(err))
		return http.StatusInternalServerError, "Failed to display API key", nil
	}

	headers := map[string][]string{
		"Content-Type": {"text/html; charset=utf-8"},
		"Cache-Control": {"no-store, no-cache, must-revalidate, private"},
	}

	return http.StatusOK, buf.String(), headers
}