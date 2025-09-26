package filter

import (
	"net/url"
	"strings"

	"github.com/envoyproxy/envoy/contrib/golang/common/go/api"
	"go.uber.org/zap"
)

// handleWelcome renders the welcome page after logout
func (f *Filter) handleWelcome(header api.RequestHeaderMap) api.StatusType {
	traceID := f.getTraceID(header)

	// Check if there's a state parameter (from IDP logout redirect)
	path, _ := header.Get(":path")
	f.logger.Debug("Handling welcome page request",
		zap.String("trace_id", traceID),
		zap.String("path", path))

	// Extract home-url parameter if present
	homeURL := "/"
	if strings.Contains(path, "?") {
		if idx := strings.Index(path, "?"); idx > 0 {
			queryString := path[idx+1:]
			if params, err := url.ParseQuery(queryString); err == nil {
				if paramHomeURL := params.Get("home-url"); paramHomeURL != "" {
					homeURL = paramHomeURL
				}
				// Check if we need to redirect to clean URL (removing state but keeping home-url)
				if params.Get("state") != "" {
					// Remove state parameter but keep home-url
					cleanParams := url.Values{}
					if paramHomeURL := params.Get("home-url"); paramHomeURL != "" {
						cleanParams.Set("home-url", paramHomeURL)
					}
					cleanURL := "/oauth/welcome"
					if len(cleanParams) > 0 {
						cleanURL += "?" + cleanParams.Encode()
					}
					f.logger.Debug("Redirecting to clean welcome URL without state param",
						zap.String("trace_id", traceID),
						zap.String("clean_url", cleanURL))
					return f.handleRedirect(cleanURL, "")
				}
			}
		}
	}

	// Set response headers
	header.Set(":status", "200")
	header.Set("content-type", "text/html; charset=utf-8")
	header.Set("cache-control", "no-cache, no-store, must-revalidate")

	// Send the welcome page HTML
	f.callbacks.DecoderFilterCallbacks().SendLocalReply(
		200, // HTTP 200 OK
		getWelcomeHTML(homeURL),
		map[string][]string{
			"content-type":  {"text/html; charset=utf-8"},
			"cache-control": {"no-cache, no-store, must-revalidate"},
		},
		-1, // grpcStatus (-1 means not a gRPC response)
		"", // no additional details
	)

	return api.LocalReply
}

// getWelcomeHTML returns the HTML content for the welcome page
func getWelcomeHTML(homeURL string) string {
	// Escape the URL for safe inclusion in HTML
	if homeURL == "" {
		homeURL = "/"
	}

	// Escape HTML special characters in the URL
	homeURL = strings.ReplaceAll(homeURL, "&", "&amp;")
	homeURL = strings.ReplaceAll(homeURL, "<", "&lt;")
	homeURL = strings.ReplaceAll(homeURL, ">", "&gt;")
	homeURL = strings.ReplaceAll(homeURL, "\"", "&quot;")
	homeURL = strings.ReplaceAll(homeURL, "'", "&#39;")

	return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Welcome</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }
        .container {
            text-align: center;
            padding: 2rem;
            background: rgba(255, 255, 255, 0.1);
            border-radius: 10px;
            backdrop-filter: blur(10px);
            box-shadow: 0 8px 32px 0 rgba(31, 38, 135, 0.37);
            max-width: 400px;
        }
        h1 {
            margin: 0 0 1rem 0;
            font-size: 2.5rem;
        }
        p {
            margin: 1rem 0;
            font-size: 1.2rem;
            opacity: 0.9;
        }
        .buttons {
            margin-top: 2rem;
        }
        a {
            display: inline-block;
            margin: 0.5rem;
            padding: 0.75rem 2rem;
            background: white;
            color: #667eea;
            text-decoration: none;
            border-radius: 5px;
            font-weight: 600;
            transition: transform 0.2s, box-shadow 0.2s;
        }
        a:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 20px rgba(0, 0, 0, 0.2);
        }
        .home-link {
            background: rgba(255, 255, 255, 0.2);
            color: white;
            border: 2px solid white;
        }
        .home-link:hover {
            background: rgba(255, 255, 255, 0.3);
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Welcome!</h1>
        <p>You have been successfully logged out.</p>
        <p>Thank you for using our service.</p>
        <div class="buttons">
            <a href="/oauth/login">Sign In Again</a>
            <a href="` + homeURL + `" class="home-link">Go to Home</a>
        </div>
    </div>
</body>
</html>`
}