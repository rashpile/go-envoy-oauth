package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

type GatewayConfig struct {
	Plugin   PluginConfig   `yaml:"plugin"`
	OAuth    OAuthConfig    `yaml:"oauth"`
	Clients  []ClientConfig `yaml:"clients"`
	Template string         `yaml:"template,omitempty"` // Path to template config file
	Listener ListenerConfig `yaml:"listener,omitempty"`
	SSL      SSLConfig      `yaml:"ssl,omitempty"` // SSL/TLS configuration for listener
}

type PluginConfig struct {
	LibraryPath string `yaml:"library_path"`
}

type OAuthConfig struct {
	IssuerURL         string   `yaml:"issuer_url"`
	ClientID          string   `yaml:"client_id"`
	ClientSecret      string   `yaml:"client_secret"`
	RedirectURL       string   `yaml:"redirect_url"`
	Scopes            []string `yaml:"scopes,omitempty"`
	EnableAPIKey      bool     `yaml:"enable_api_key,omitempty"`
	EnableBearerToken bool     `yaml:"enable_bearer_token,omitempty"`
	SessionCookieName string   `yaml:"session_cookie_name,omitempty"`
	SessionMaxAge     int      `yaml:"session_max_age,omitempty"`
	SessionPath       string   `yaml:"session_path,omitempty"`
	SessionDomain     string   `yaml:"session_domain,omitempty"`
	SessionSecure     bool     `yaml:"session_secure,omitempty"`
	SessionHTTPOnly   bool     `yaml:"session_http_only,omitempty"`
	SessionSameSite   string   `yaml:"session_same_site,omitempty"`
}

type ListenerConfig struct {
	Address string `yaml:"address,omitempty"`
	Port    uint32 `yaml:"port,omitempty"`     // HTTP listener port
	TLSPort uint32 `yaml:"tls_port,omitempty"` // HTTPS listener port
	TLS     bool   `yaml:"tls,omitempty"`      // Deprecated: Enable TLS on listener (use tls_port instead)
}

type SSLConfig struct {
	Enabled     bool   `yaml:"enabled,omitempty"`      // Enable SSL certificate management
	Staging     bool   `yaml:"staging,omitempty"`      // Use Let's Encrypt staging
	ACMEEmail   string `yaml:"acme_email,omitempty"`   // Email for ACME account
	HTTPPort    uint32 `yaml:"http_port,omitempty"`    // Port for HTTP-01 challenge
	StoragePath string `yaml:"storage_path,omitempty"` // Certificate storage path
}

type ClientConfig struct {
	ID                 string   `yaml:"id"`
	Domain             string   `yaml:"domain,omitempty"`
	HostRewrite        string   `yaml:"host_rewrite,omitempty"`
	Address            string   `yaml:"address"`
	Port               uint32   `yaml:"port"`
	SSL                bool     `yaml:"ssl"`           // Upstream uses SSL/TLS
	TLS                bool     `yaml:"tls,omitempty"` // Request certificate for this domain
	Exclude            bool     `yaml:"exclude"`
	Prefix             string   `yaml:"prefix"`
	ExcludePaths       []string `yaml:"exclude_paths,omitempty"`
	SsoInjection       bool     `yaml:"sso_injection,omitempty"`
	SsoAppURL          string   `yaml:"sso_appurl,omitempty"`
	SsoAppName         string   `yaml:"sso_appname,omitempty"`
	AddToken           bool     `yaml:"add_token,omitempty"`
	ClusterIdleTimeout string   `yaml:"cluster_idle_timeout,omitempty"`
	RouteTimeout       string   `yaml:"route_timeout,omitempty"`
}

// overrideFromEnv overrides configuration values from environment variables
func overrideFromEnv(config *GatewayConfig) {
	// Plugin config overrides
	if val := os.Getenv("PLUGIN_LIBRARYPATH"); val != "" {
		config.Plugin.LibraryPath = val
	}

	// OAuth config overrides
	if val := os.Getenv("OAUTH_ISSUERURL"); val != "" {
		config.OAuth.IssuerURL = val
	}
	if val := os.Getenv("OAUTH_CLIENTID"); val != "" {
		config.OAuth.ClientID = val
	}
	if val := os.Getenv("OAUTH_CLIENTSECRET"); val != "" {
		config.OAuth.ClientSecret = val
	}
	if val := os.Getenv("OAUTH_REDIRECTURL"); val != "" {
		config.OAuth.RedirectURL = val
	}
	if val := os.Getenv("OAUTH_SCOPES"); val != "" {
		config.OAuth.Scopes = strings.Split(val, ",")
	}
	if val := os.Getenv("OAUTH_ENABLE_API_KEY"); val != "" {
		config.OAuth.EnableAPIKey = val == "true" || val == "1"
	}
	if val := os.Getenv("OAUTH_ENABLE_BEARER_TOKEN"); val != "" {
		config.OAuth.EnableBearerToken = val == "true" || val == "1"
	}
	if val := os.Getenv("OAUTH_SESSION_COOKIE_NAME"); val != "" {
		config.OAuth.SessionCookieName = val
	}
	if val := os.Getenv("OAUTH_SESSION_MAX_AGE"); val != "" {
		if maxAge, err := strconv.Atoi(val); err == nil {
			config.OAuth.SessionMaxAge = maxAge
		}
	}
	if val := os.Getenv("OAUTH_SESSION_PATH"); val != "" {
		config.OAuth.SessionPath = val
	}
	if val := os.Getenv("OAUTH_SESSION_DOMAIN"); val != "" {
		config.OAuth.SessionDomain = val
	}
	if val := os.Getenv("OAUTH_SESSION_SECURE"); val != "" {
		config.OAuth.SessionSecure = val == "true" || val == "1"
	}
	if val := os.Getenv("OAUTH_SESSION_HTTP_ONLY"); val != "" {
		config.OAuth.SessionHTTPOnly = val == "true" || val == "1"
	}
	if val := os.Getenv("OAUTH_SESSION_SAME_SITE"); val != "" {
		config.OAuth.SessionSameSite = val
	}

	// Listener config overrides
	if val := os.Getenv("LISTENER_ADDRESS"); val != "" {
		config.Listener.Address = val
	}
	if val := os.Getenv("LISTENER_PORT"); val != "" {
		if port, err := strconv.ParseUint(val, 10, 32); err == nil {
			config.Listener.Port = uint32(port)
		}
	}
	if val := os.Getenv("LISTENER_TLS_PORT"); val != "" {
		if port, err := strconv.ParseUint(val, 10, 32); err == nil {
			config.Listener.TLSPort = uint32(port)
		}
	}
	if val := os.Getenv("LISTENER_TLS"); val != "" {
		config.Listener.TLS = val == "true" || val == "1"
	}

	// SSL config overrides
	if val := os.Getenv("SSL_ENABLE"); val != "" {
		config.SSL.Enabled = val == "true" || val == "1"
	}
	if val := os.Getenv("SSL_STAGING"); val != "" {
		config.SSL.Staging = val == "true" || val == "1"
	}
	if val := os.Getenv("SSL_ACME_EMAIL"); val != "" {
		config.SSL.ACMEEmail = val
	}
	if val := os.Getenv("CERT_HTTP_PORT"); val != "" {
		if port, err := strconv.ParseUint(val, 10, 32); err == nil {
			config.SSL.HTTPPort = uint32(port)
		}
	}
	if val := os.Getenv("XDG_DATA_HOME"); val != "" {
		config.SSL.StoragePath = val
	}
}

func LoadConfig(path string) (*GatewayConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config GatewayConfig

	// Set defaults BEFORE unmarshaling to handle missing fields
	config.OAuth.EnableBearerToken = true // Default to true
	config.OAuth.SessionSecure = true     // Default to true
	config.OAuth.SessionHTTPOnly = true   // Default to true

	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	// Override from environment variables
	overrideFromEnv(&config)

	// Set defaults for session configuration
	if config.Plugin.LibraryPath == "" {
		config.Plugin.LibraryPath = "/app/go-envoy-oauth.so"
	}

	if config.Listener.Address == "" {
		config.Listener.Address = "0.0.0.0"
	}
	if config.Listener.Port == 0 {
		config.Listener.Port = 8080
	}
	// Set TLS port default when SSL is enabled or legacy TLS flag is set
	if config.Listener.TLSPort == 0 && (config.SSL.Enabled || config.Listener.TLS) {
		config.Listener.TLSPort = 8443
	}

	if config.OAuth.RedirectURL == "" {
		config.OAuth.RedirectURL = "/oauth/callback"
	}

	if config.OAuth.Scopes == nil {
		config.OAuth.Scopes = []string{"openid", "profile", "email"}
	}

	// Set session configuration defaults
	if config.OAuth.SessionCookieName == "" {
		config.OAuth.SessionCookieName = "session"
	}
	if config.OAuth.SessionMaxAge == 0 {
		config.OAuth.SessionMaxAge = 86400 // 24 hours
	}
	if config.OAuth.SessionPath == "" {
		config.OAuth.SessionPath = "/"
	}
	// SessionDomain defaults to empty (will be determined from request headers)
	// SessionSecure defaults to true (already set above)
	// SessionHTTPOnly defaults to true (already set above)
	if config.OAuth.SessionSameSite == "" {
		config.OAuth.SessionSameSite = "Lax"
	}

	for i := range config.Clients {
		if config.Clients[i].Port == 0 {
			config.Clients[i].Port = 8080
		}
		if config.Clients[i].Prefix == "" {
			config.Clients[i].Prefix = "/"
		}
	}

	// Validate required fields
	if config.OAuth.IssuerURL == "" {
		return nil, fmt.Errorf("oauth.issuer_url is required")
	}
	if config.OAuth.ClientID == "" {
		return nil, fmt.Errorf("oauth.client_id is required")
	}

	for _, client := range config.Clients {
		if client.ID == "" {
			return nil, fmt.Errorf("client.id is required")
		}
		if client.Address == "" {
			return nil, fmt.Errorf("client.address is required for client %s", client.ID)
		}
	}

	return &config, nil
}
