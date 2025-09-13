package session

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"

	"github.com/envoyproxy/envoy/contrib/golang/common/go/api"
)

// CookieManager handles cookie operations
type CookieManager struct {
	config *CookieConfig
}

// CookieConfig holds cookie configuration
type CookieConfig struct {
	Name     string        // Cookie name
	Domain   string        // Cookie domain
	Path     string        // Cookie path
	MaxAge   int           // Cookie max age in seconds
	Secure   bool          // Whether cookie should be secure
	HTTPOnly bool          // Whether cookie should be HTTP only
	SameSite http.SameSite // SameSite attribute
}

// DefaultCookieConfig returns default cookie configuration
func DefaultCookieConfig() *CookieConfig {
	return &CookieConfig{
		Name:     "session_id",
		Path:     "/",
		MaxAge:   3600, // 1 hour
		Secure:   true,
		HTTPOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
}

// NewCookieManager creates a new cookie manager
func NewCookieManager(hashKey, blockKey []byte, config *CookieConfig) (*CookieManager, error) {
	if config == nil {
		config = DefaultCookieConfig()
	}

	return &CookieManager{
		config: config,
	}, nil
}

// SetCookie sets a cookie with the session ID
func (cm *CookieManager) SetCookie(header api.RequestHeaderMap, value string) error {
	// Build cookie string with configuration
	cookie := fmt.Sprintf("%s=%s; Path=%s; Max-Age=%d",
		cm.config.Name, value, cm.config.Path, cm.config.MaxAge)

	// Add cookie attributes based on configuration
	if cm.config.HTTPOnly {
		cookie += "; HttpOnly"
	}
	if cm.config.Secure {
		cookie += "; Secure"
	}
	if cm.config.SameSite != 0 {
		switch cm.config.SameSite {
		case http.SameSiteLaxMode:
			cookie += "; SameSite=Lax"
		case http.SameSiteStrictMode:
			cookie += "; SameSite=Strict"
		case http.SameSiteNoneMode:
			cookie += "; SameSite=None"
		}
	}
	if cm.config.Domain != "" {
		cookie += "; Domain=" + cm.config.Domain
	}

	header.Set("set-cookie", cookie)
	return nil
}

// GetCookie retrieves the session ID from the cookie
func (cm *CookieManager) GetCookie(header api.RequestHeaderMap) (string, error) {
	cookie, _ := header.Get("cookie")
	if cookie == "" {
		return "", fmt.Errorf("no cookie found")
	}

	cookies := strings.Split(cookie, ";")
	for _, c := range cookies {
		c = strings.TrimSpace(c)
		if strings.HasPrefix(c, cm.config.Name+"=") {
			value := strings.TrimPrefix(c, cm.config.Name+"=")
			return value, nil
		}
	}

	return "", fmt.Errorf("session cookie not found")
}

// DeleteCookie removes the session cookie
func (cm *CookieManager) DeleteCookie(header api.RequestHeaderMap) {
	header.Set("set-cookie", cm.formatCookie(""))
}

func (cm *CookieManager) formatCookie(value string) string {
	cookie := fmt.Sprintf("%s=%s", cm.config.Name, value)
	if cm.config.Domain != "" {
		cookie += "; Domain=" + cm.config.Domain
	}
	if cm.config.Path != "" {
		cookie += "; Path=" + cm.config.Path
	}
	if cm.config.MaxAge > 0 {
		cookie += fmt.Sprintf("; Max-Age=%d", cm.config.MaxAge)
	}
	if cm.config.Secure {
		cookie += "; Secure"
	}
	if cm.config.HTTPOnly {
		cookie += "; HttpOnly"
	}
	if cm.config.SameSite != http.SameSiteDefaultMode {
		cookie += "; SameSite=" + sameSiteString(cm.config.SameSite)
	}
	return cookie
}

func sameSiteString(sameSite http.SameSite) string {
	switch sameSite {
	case http.SameSiteLaxMode:
		return "Lax"
	case http.SameSiteStrictMode:
		return "Strict"
	case http.SameSiteNoneMode:
		return "None"
	default:
		return ""
	}
}

// GenerateRandomKey generates a random key of the specified length
func GenerateRandomKey(length int) ([]byte, error) {
	key := make([]byte, length)
	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}
	return key, nil
}

// GenerateRandomKeyBase64 generates a random key and returns it as a base64 string
func GenerateRandomKeyBase64(length int) (string, error) {
	key, err := GenerateRandomKey(length)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(key), nil
}
