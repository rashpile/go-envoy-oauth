package config

import (
	"time"
)

// OAuthConfig represents the OAuth configuration settings
type OAuthConfig struct {
	// OpenID Connect configuration
	IssuerURL    string   `json:"issuer_url"`
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	RedirectURL  string   `json:"redirect_url"`
	Scopes       []string `json:"scopes"`

	// Session configuration
	SessionCookieName string        `json:"session_cookie_name"`
	SessionMaxAge     time.Duration `json:"session_max_age"`
	SessionPath       string        `json:"session_path"`
	SessionDomain     string        `json:"session_domain"`
	SessionSecure     bool          `json:"session_secure"`
	SessionHttpOnly   bool          `json:"session_http_only"`
	SessionSameSite   string        `json:"session_same_site"`

	// Paths that should be excluded from authentication
	ExcludePaths []string `json:"exclude_paths"`

	// Cluster-specific configurations
	Clusters map[string]ClusterConfig `json:"clusters"`
}

// ClusterConfig represents cluster-specific OAuth configuration
type ClusterConfig struct {
	Exclude      bool     `json:"exclude"`
	ExcludePaths []string `json:"exclude_paths"`
}

// DefaultOAuthConfig returns default OAuth configuration
func DefaultOAuthConfig() *OAuthConfig {
	return &OAuthConfig{
		Scopes:            []string{"openid", "profile", "email"},
		SessionCookieName: "session",
		SessionMaxAge:     24 * time.Hour,
		SessionPath:       "/",
		SessionSecure:     true,
		SessionHttpOnly:   true,
		SessionSameSite:   "Lax",
		ExcludePaths:      []string{"/health"},
		Clusters:          make(map[string]ClusterConfig),
	}
}
