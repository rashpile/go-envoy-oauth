package filter

import (
	"fmt"
	"strings"

	"github.com/envoyproxy/envoy/contrib/golang/common/go/api"
)

// CookieSettings represents the settings for cookies
type CookieSettings struct {
	Enabled      bool
	MaxAge       int    // in seconds
	Domain       string // optional domain
	Path         string // default "/"
	Secure       bool   // secure flag
	HttpOnly     bool   // HttpOnly flag
	SameSite     string // None, Lax, Strict
	SaveToCookie bool   // Whether to save API key to cookie after successful auth
}

func DefaultCookieSettings() CookieSettings {
	return CookieSettings{
		Enabled:      true,
		MaxAge:       86400 * 30, // 30 days
		Path:         "/",
		Secure:       true,
		HttpOnly:     true,
		SameSite:     "Lax",
		SaveToCookie: true,
	}
}

// CookieHelper provides methods for working with cookies
type CookieHelper struct {
	settings CookieSettings
}

// NewCookieHelper creates a new cookie helper
func NewCookieHelper(settings CookieSettings) CookieHelper {
	return CookieHelper{
		settings: settings,
	}
}

// ParseCookies parses a Cookie header into a map of cookie names to values
func (h *CookieHelper) ParseCookies(cookieHeader string) map[string]string {
	cookies := make(map[string]string)

	// Split by semicolon and process each cookie
	parts := strings.Split(cookieHeader, ";")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		// Split by = to get key and value
		kv := strings.SplitN(part, "=", 2)
		if len(kv) == 2 {
			cookies[kv[0]] = kv[1]
		}
	}

	return cookies
}

// GetCookieAPIKey extracts the API key from cookies
func (h *CookieHelper) GetCookieAPIKey(config *Config, header api.RequestHeaderMap) (string, bool) {
	// Skip if cookie auth is disabled
	if config.APIKeyCookie == "" {
		return "", false
	}

	// Get Cookie header
	cookieHeader, exists := header.Get("Cookie")
	if !exists || cookieHeader == "" {
		return "", false
	}

	// Parse cookies
	cookies := h.ParseCookies(cookieHeader)
	value, exists := cookies[config.APIKeyCookie]
	return value, exists && value != ""
}

// SetCookie adds or updates a cookie in the response headers
func (h *CookieHelper) SetCookie(header api.ResponseHeaderMap, name, value string) {
	if !h.settings.Enabled {
		return
	}

	// Build cookie string
	cookieValue := h.buildCookieString(name, value)

	// Add the cookie to the response headers
	header.Add("Set-Cookie", cookieValue)
}

// buildCookieString creates a cookie string with all the configured attributes
func (h *CookieHelper) buildCookieString(name, value string) string {
	// Start with the base name=value pair
	cookieValue := fmt.Sprintf("%s=%s; Max-Age=%d; Path=%s",
		name, value, h.settings.MaxAge, h.settings.Path)

	// Add domain if specified
	if h.settings.Domain != "" {
		cookieValue += fmt.Sprintf("; Domain=%s", h.settings.Domain)
	}

	// Add secure flag if enabled
	if h.settings.Secure {
		cookieValue += "; Secure"
	}

	// Add HttpOnly flag if enabled
	if h.settings.HttpOnly {
		cookieValue += "; HttpOnly"
	}

	// Add SameSite if specified
	if h.settings.SameSite != "" {
		cookieValue += fmt.Sprintf("; SameSite=%s", h.settings.SameSite)
	}

	return cookieValue
}
