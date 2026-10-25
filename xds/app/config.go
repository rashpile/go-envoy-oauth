package main

import (
	"fmt"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// validProviderName matches provider names: alphanumeric start, followed by alphanumeric or hyphens
var validProviderName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9-]*$`)

// ProviderConfig holds OAuth 2.0/OIDC provider credentials and endpoints.
// Multiple providers can be configured to support multi-tenant or multi-IDP deployments.
type ProviderConfig struct {
	IssuerURL    string   `yaml:"issuer_url"`
	ClientID     string   `yaml:"client_id"`
	ClientSecret string   `yaml:"client_secret"`
	RedirectURL  string   `yaml:"redirect_url,omitempty"`
	Scopes       []string `yaml:"scopes,omitempty"`
	AllowedUsers []string `yaml:"allowed_users,omitempty"` // Provider-scoped OR-grant (matched against preferred_username, case-insensitive)
}

type GatewayConfig struct {
	Plugin          PluginConfig              `yaml:"plugin"`
	OAuth           OAuthConfig               `yaml:"oauth"`
	Providers       map[string]ProviderConfig `yaml:"providers,omitempty"`
	DefaultProvider string                    `yaml:"default_provider,omitempty"`
	Clients         []ClientConfig            `yaml:"clients"`
	Template        string                    `yaml:"template,omitempty"` // Path to template config file
	Listener        ListenerConfig            `yaml:"listener,omitempty"`
	SSL             SSLConfig                 `yaml:"ssl,omitempty"` // SSL/TLS configuration for listener
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
	ID string `yaml:"id"`
	// Description is operator-only metadata (not propagated to Envoy or filter).
	Description           string   `yaml:"description,omitempty"`
	Domain                string   `yaml:"domain,omitempty"`
	HostRewrite           string   `yaml:"host_rewrite,omitempty"`
	Address               string   `yaml:"address"`
	Port                  uint32   `yaml:"port"`
	SSL                   bool     `yaml:"ssl"`           // Upstream uses SSL/TLS
	TLS                   bool     `yaml:"tls,omitempty"` // Request certificate for this domain
	Exclude               bool     `yaml:"exclude"`
	Enabled               *bool    `yaml:"enabled,omitempty"` // Default: true. Set to false to skip this client at xDS generation.
	Prefix                string   `yaml:"prefix"`
	PrefixRewrite         string   `yaml:"prefix_rewrite,omitempty"`
	ExcludePaths          []string `yaml:"exclude_paths,omitempty"`
	WebSocketExcludePaths []string `yaml:"websocket_exclude_paths,omitempty"` // WebSocket paths that skip auth
	SsoInjection          bool     `yaml:"sso_injection,omitempty"`
	SsoAppURL             string   `yaml:"sso_appurl,omitempty"`
	SsoAppName            string   `yaml:"sso_appname,omitempty"`
	AddToken              bool     `yaml:"add_token,omitempty"`
	ClusterIdleTimeout    string   `yaml:"cluster_idle_timeout,omitempty"`
	RouteTimeout          string   `yaml:"route_timeout,omitempty"`
	AllowedUsers          []string `yaml:"allowed_users,omitempty"` // Per-client allowed users
	Provider              string   `yaml:"provider,omitempty"`      // Named provider reference; empty means use default_provider
}

// IsEnabled reports whether this client should be served by Envoy.
// A nil Enabled pointer (field absent in YAML) is treated as enabled.
// IsEnabled is independent of Exclude: Exclude bypasses authentication for a
// still-routed cluster, while !IsEnabled() skips the client entirely at xDS
// generation (no cluster, no route, no per-cluster filter config).
func (c ClientConfig) IsEnabled() bool {
	return c.Enabled == nil || *c.Enabled
}

// normalizeProviders ensures the providers map is populated.
// For legacy configs (no providers map), it builds a "default" provider from the oauth.* fields.
// For configs that already have a providers map, it warns if legacy env vars are also set.
func normalizeProviders(config *GatewayConfig) error {
	if len(config.Providers) == 0 {
		// Legacy config path: build providers map from oauth.* fields
		if config.OAuth.IssuerURL == "" || config.OAuth.ClientID == "" || config.OAuth.ClientSecret == "" {
			return fmt.Errorf("legacy 'oauth' block requires issuer_url, client_id, and client_secret when no 'providers' map is set")
		}
		config.Providers = map[string]ProviderConfig{
			"default": {
				IssuerURL:    config.OAuth.IssuerURL,
				ClientID:     config.OAuth.ClientID,
				ClientSecret: config.OAuth.ClientSecret,
				RedirectURL:  config.OAuth.RedirectURL,
				Scopes:       config.OAuth.Scopes,
			},
		}
		config.DefaultProvider = "default"
		return nil
	}

	// Named providers map is set — warn if legacy env vars are also present
	if os.Getenv("OAUTH_ISSUERURL") != "" || os.Getenv("OAUTH_CLIENTID") != "" || os.Getenv("OAUTH_CLIENTSECRET") != "" {
		log.Printf("WARNING: environment variables OAUTH_ISSUERURL/OAUTH_CLIENTID/OAUTH_CLIENTSECRET are ignored when 'providers' map is configured (per D-11)")
	}
	return nil
}

// validateProviders checks all provider registry rules:
// - Provider names must be alphanumeric with optional hyphens, not starting with hyphen
// - Each provider must have issuer_url, client_id, client_secret
// - default_provider must reference a defined provider
// - Each client's provider field (if non-empty) must reference a defined provider
// - No two providers may share the same issuer_url + client_id combination
func validateProviders(config *GatewayConfig) error {
	// Validate provider names and required fields
	seen := make(map[string]string) // "issuerURL|clientID" -> provider name
	for name, p := range config.Providers {
		if !validProviderName.MatchString(name) {
			return fmt.Errorf("provider name %q is invalid: must be alphanumeric with hyphens, no leading hyphen", name)
		}
		if p.IssuerURL == "" {
			return fmt.Errorf("provider %q: issuer_url is required", name)
		}
		if p.ClientID == "" {
			return fmt.Errorf("provider %q: client_id is required", name)
		}
		if p.ClientSecret == "" {
			return fmt.Errorf("provider %q: client_secret is required", name)
		}
		key := p.IssuerURL + "|" + p.ClientID
		if existingName, ok := seen[key]; ok {
			return fmt.Errorf("providers %q and %q have duplicate issuer_url/client_id combination", existingName, name)
		}
		seen[key] = name
	}

	// Validate default_provider references a defined provider
	if config.DefaultProvider != "" {
		if _, ok := config.Providers[config.DefaultProvider]; !ok {
			return fmt.Errorf("default_provider %q does not reference a defined provider", config.DefaultProvider)
		}
	}

	// Validate per-client provider references (skip excluded clients — they don't participate in OAuth;
	// also skip disabled clients — they are filtered out at xDS generation time and never reach the filter).
	for _, client := range config.Clients {
		// Excluded clients bypass auth; disabled clients never reach the filter.
		if client.Exclude || !client.IsEnabled() {
			continue
		}
		if client.Provider != "" {
			if _, ok := config.Providers[client.Provider]; !ok {
				return fmt.Errorf("client %q references undefined provider %q", client.ID, client.Provider)
			}
		} else if config.DefaultProvider == "" {
			return fmt.Errorf("client %q has no provider and no default_provider is set", client.ID)
		}
	}

	return nil
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

// reservedClusterNames are static clusters in the Envoy bootstrap
// (xds/envoy-xds.yaml). A client with the same ID would not override them:
// Envoy keeps the static cluster and routes the client's traffic to it.
var reservedClusterNames = map[string]struct{}{
	"xds_cluster":          {},
	"envoy_admin_loopback": {},
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

	if err := yaml.Unmarshal([]byte(os.ExpandEnv(string(data))), &config); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	// Override from environment variables
	overrideFromEnv(&config)

	// Normalize legacy config to providers map
	if err := normalizeProviders(&config); err != nil {
		return nil, err
	}
	// Validate provider registry
	if err := validateProviders(&config); err != nil {
		return nil, err
	}

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

	// Defaults run for all clients (including disabled) so flipping `enabled: true` needs no further edits.
	for i := range config.Clients {
		if config.Clients[i].Port == 0 {
			config.Clients[i].Port = 8080
		}
		if config.Clients[i].Prefix == "" {
			config.Clients[i].Prefix = "/"
		}
	}

	// Provider-level validation is handled by validateProviders above.
	// Validate per-client required fields. Disabled clients are skipped so operators
	// may keep partially-populated historical entries in YAML for rollback.
	for _, client := range config.Clients {
		if !client.IsEnabled() {
			continue
		}
		if client.ID == "" {
			return nil, fmt.Errorf("client.id is required")
		}
		if _, reserved := reservedClusterNames[client.ID]; reserved {
			return nil, fmt.Errorf("client.id %q is reserved for a static Envoy cluster", client.ID)
		}
		if client.Address == "" {
			return nil, fmt.Errorf("client.address is required for client %s", client.ID)
		}
	}

	return &config, nil
}
