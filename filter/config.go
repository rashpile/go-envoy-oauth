package filter

import (
	"encoding/json"
	"time"
)

// OAuthConfig represents the configuration for the OAuth filter
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

// ClusterConfig represents cluster-specific configuration
type ClusterConfig struct {
	Exclude      bool     `json:"exclude"`
	ExcludePaths []string `json:"exclude_paths"`
}

// ParseConfig parses the configuration from Envoy's TypedStruct
func ParseConfig(c interface{}) (*OAuthConfig, error) {
	config := &OAuthConfig{}

	// Convert the configuration to JSON
	jsonData, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}

	// Parse the JSON into our config structure
	if err := json.Unmarshal(jsonData, config); err != nil {
		return nil, err
	}

	return config, nil
}
