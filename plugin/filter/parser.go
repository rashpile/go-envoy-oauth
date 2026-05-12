package filter

import (
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"slices"

	xds "github.com/cncf/xds/go/xds/type/v3"
	"github.com/envoyproxy/envoy/contrib/golang/common/go/api"
	"github.com/rashpile/go-envoy-oauth/plugin/metrics"
	"github.com/rashpile/go-envoy-oauth/plugin/oauth"
	"github.com/rashpile/go-envoy-oauth/plugin/session"
	"go.uber.org/zap"

	"google.golang.org/protobuf/types/known/anypb"
)

// ProviderConfig represents a named OAuth provider's configuration.
// This is an independent definition from the XDS-side ProviderConfig —
// the two modules are separate and must not import each other.
type ProviderConfig struct {
	IssuerURL    string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
	AllowedUsers []string // Provider-scoped OR-grant (normalized to lowercase)
}

// ClusterConfig represents the configuration for a specific cluster
type ClusterConfig struct {
	Exclude               bool
	SsoInjection          bool
	SsoAppURL             string
	SsoAppName            string
	ExcludePaths          []string
	TokenInclude          bool
	WebSocketExcludePaths []string
	AllowedUsers          []string // Per-client allowed users (normalized to lowercase)
	ProviderName          string   // Resolved provider name for this cluster
}

// OAuthConfig represents the OAuth filter configuration
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

	// Header configuration
	UserIDHeaderName       string   `json:"user_id_header_name"`
	UserEmailHeaderName    string   `json:"user_email_header_name"`
	UserUsernameHeaderName string   `json:"user_username_header_name"`
	AuthProviderHeaderName string   `json:"auth_provider_header_name"`
	SkipAuthHeaderName     string   `json:"skip_auth_header_name"`
	RemoveHeaders          []string `json:"remove_headers"`

	// Paths that should be excluded from authentication
	ExcludePaths []string `json:"exclude_paths"`

	// WebSocket paths that should be excluded from authentication
	WebSocketExcludePaths []string `json:"websocket_exclude_paths"`

	// Cluster-specific configurations
	Clusters map[string]ClusterConfig `json:"clusters"`

	// API Key generation feature (offline token)
	EnableAPIKey bool `json:"enable_api_key"`

	// Bearer token authentication
	EnableBearerToken bool `json:"enable_bearer_token"`

	// Whether the /oauth/llms.txt agent-integration documentation endpoint
	// is enabled (default: true). When false, the endpoint returns 404
	// indistinguishably from any other unknown /oauth/* path.
	EnableLLMsTxt bool `json:"enable_llms_txt"`

	// Provider registry
	Providers       map[string]ProviderConfig `json:"providers"`
	DefaultProvider string                    `json:"default_provider"`

	// Session store
	SessionStore session.SessionStore

	// Provider registry — initialized eagerly in Parse() (D-07).
	// All auth operations resolve the correct handler via this registry.
	ProviderRegistry *ProviderRegistry
}

// Parser parses the filter configuration
type Parser struct {
}

// parseRawConfig extracts a partially-populated OAuthConfig from an anypb.Any value.
// It does NOT perform OIDC discovery or initialize a ProviderRegistry.
// Used internally by Parse() and in tests that verify config field population.
func (p *Parser) parseRawConfig(any *anypb.Any) (*OAuthConfig, error) {
	configStruct := &xds.TypedStruct{}
	if err := any.UnmarshalTo(configStruct); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %v", err)
	}

	v := configStruct.Value
	// Cache the map to avoid repeated deserialization on every access.
	m := v.AsMap()

	conf := &OAuthConfig{
		Scopes:             []string{"openid", "profile", "email"},
		SessionCookieName:  "session",
		SessionMaxAge:      24 * time.Hour,
		SessionPath:        "/",
		SessionSecure:      true,
		SessionHttpOnly:    true,
		SessionSameSite:    "Lax",
		ExcludePaths:       []string{"/health"},
		Clusters:           make(map[string]ClusterConfig),
		Providers:          make(map[string]ProviderConfig),
		SessionStore:       session.NewInMemorySessionStore(),
		SkipAuthHeaderName: "",
		RemoveHeaders:      []string{"X-User-ID", "X-User-Email", "X-User-Username", "X-Auth-Provider"},
		EnableAPIKey:       false, // API key generation disabled by default
		EnableBearerToken:  true,  // Bearer token authentication enabled by default
		EnableLLMsTxt:      true,  // /oauth/llms.txt agent docs enabled by default
	}

	if err := p.populateConfig(conf, m); err != nil {
		return nil, err
	}
	ensureIdentityHeadersStripped(conf)
	return conf, nil
}

// ensureIdentityHeadersStripped guarantees every identity header the filter
// writes downstream is present in RemoveHeaders so client-supplied values are
// always stripped (T-04-01). Operators can override RemoveHeaders wholesale
// and/or rename identity headers, so this enforces the security invariant
// regardless of configuration.
func ensureIdentityHeadersStripped(conf *OAuthConfig) {
	effective := []string{
		valueOr(conf.AuthProviderHeaderName, "X-Auth-Provider"),
		valueOr(conf.UserIDHeaderName, "X-User-ID"),
		valueOr(conf.UserEmailHeaderName, "X-User-Email"),
		valueOr(conf.UserUsernameHeaderName, "X-User-Username"),
	}
	for _, name := range effective {
		if !slices.Contains(conf.RemoveHeaders, name) {
			conf.RemoveHeaders = append(conf.RemoveHeaders, name)
		}
	}
}

func valueOr(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

// populateConfig fills conf fields from the decoded config map m.
func (p *Parser) populateConfig(conf *OAuthConfig, m map[string]interface{}) error {
	// Parse OpenID Connect configuration
	if issuerURL, ok := m["issuer_url"].(string); ok {
		conf.IssuerURL = issuerURL
	}
	if clientID, ok := m["client_id"].(string); ok {
		conf.ClientID = clientID
	}
	if clientSecret, ok := m["client_secret"].(string); ok {
		conf.ClientSecret = clientSecret
	}
	if redirectURL, ok := m["redirect_url"].(string); ok {
		// If redirect URL is relative, it will be handled by the OAuth handler
		conf.RedirectURL = redirectURL
	}
	if os.Getenv("CLIENT_SECRET") != "" {
		conf.ClientSecret = os.Getenv("CLIENT_SECRET")
	}
	if os.Getenv("CLIENT_ID") != "" {
		conf.ClientID = os.Getenv("CLIENT_ID")
	}
	if os.Getenv("ISSUER_URL") != "" {
		conf.IssuerURL = os.Getenv("ISSUER_URL")
	}
	if os.Getenv("REDIRECT_URL") != "" {
		conf.RedirectURL = os.Getenv("REDIRECT_URL")
	}

	if scopes, ok := m["scopes"].([]interface{}); ok {
		conf.Scopes = make([]string, len(scopes))
		for i, scope := range scopes {
			if s, ok := scope.(string); ok {
				conf.Scopes[i] = s
			}
		}
	}

	// Parse session configuration
	if cookieName, ok := m["session_cookie_name"].(string); ok {
		conf.SessionCookieName = cookieName
	}
	if maxAge, ok := m["session_max_age"].(float64); ok {
		conf.SessionMaxAge = time.Duration(maxAge) * time.Second
	}
	if path, ok := m["session_path"].(string); ok {
		conf.SessionPath = path
	}
	if domain, ok := m["session_domain"].(string); ok {
		conf.SessionDomain = domain
	}
	if secure, ok := m["session_secure"].(bool); ok {
		conf.SessionSecure = secure
	}
	if httpOnly, ok := m["session_http_only"].(bool); ok {
		conf.SessionHttpOnly = httpOnly
	}
	if sameSite, ok := m["session_same_site"].(string); ok {
		conf.SessionSameSite = sameSite
	}

	// Parse exclude paths
	if excludes, ok := m["exclude_paths"].([]interface{}); ok {
		conf.ExcludePaths = make([]string, len(excludes))
		for i, exclude := range excludes {
			if path, ok := exclude.(string); ok {
				conf.ExcludePaths[i] = path
			}
		}
	}

	// Parse WebSocket exclude paths
	if wsExcludes, ok := m["websocket_exclude_paths"].([]interface{}); ok {
		conf.WebSocketExcludePaths = make([]string, len(wsExcludes))
		for i, exclude := range wsExcludes {
			if path, ok := exclude.(string); ok {
				conf.WebSocketExcludePaths[i] = path
			}
		}
	}

	// Parse header configuration
	if userIDHeaderName, ok := m["user_id_header_name"].(string); ok {
		conf.UserIDHeaderName = userIDHeaderName
	}
	if userEmailHeaderName, ok := m["user_email_header_name"].(string); ok {
		conf.UserEmailHeaderName = userEmailHeaderName
	}
	if userUsernameHeaderName, ok := m["user_username_header_name"].(string); ok {
		conf.UserUsernameHeaderName = userUsernameHeaderName
	}
	if authProviderHeaderName, ok := m["auth_provider_header_name"].(string); ok {
		conf.AuthProviderHeaderName = authProviderHeaderName
	}
	if skipAuthHeaderName, ok := m["skip_auth_header_name"].(string); ok {
		conf.SkipAuthHeaderName = skipAuthHeaderName
	}

	if removeHeaders, ok := m["remove_headers"].([]interface{}); ok {
		conf.RemoveHeaders = make([]string, len(removeHeaders))
		for i, header := range removeHeaders {
			if h, ok := header.(string); ok {
				conf.RemoveHeaders[i] = h
			}
		}
	}

	// Parse API key generation setting
	if enableAPIKey, ok := m["enable_api_key"].(bool); ok {
		conf.EnableAPIKey = enableAPIKey
	}

	// Parse bearer token authentication setting
	if enableBearerToken, ok := m["enable_bearer_token"].(bool); ok {
		conf.EnableBearerToken = enableBearerToken
		log.Printf("Parsed enable_bearer_token from config: %v", enableBearerToken)
	} else {
		log.Printf("enable_bearer_token not found in config, using default: %v", conf.EnableBearerToken)
	}

	// Parse /oauth/llms.txt endpoint setting
	if enableLLMsTxt, ok := m["enable_llms_txt"].(bool); ok {
		conf.EnableLLMsTxt = enableLLMsTxt
	}

	// Parse providers map
	if providers, ok := m["providers"].(map[string]interface{}); ok {
		conf.Providers = make(map[string]ProviderConfig)
		for name, raw := range providers {
			if p, ok := raw.(map[string]interface{}); ok {
				pc := ProviderConfig{}
				if v, ok := p["issuer_url"].(string); ok {
					pc.IssuerURL = v
				}
				if v, ok := p["client_id"].(string); ok {
					pc.ClientID = v
				}
				if v, ok := p["client_secret"].(string); ok {
					pc.ClientSecret = v
				}
				if v, ok := p["redirect_url"].(string); ok {
					pc.RedirectURL = v
				}
				if scopes, ok := p["scopes"].([]interface{}); ok {
					pc.Scopes = make([]string, 0, len(scopes))
					for _, s := range scopes {
						if str, ok := s.(string); ok {
							pc.Scopes = append(pc.Scopes, str)
						}
					}
				}
				if allowedUsers, ok := p["allowed_users"].([]interface{}); ok {
					for _, user := range allowedUsers {
						if u, ok := user.(string); ok {
							normalized := strings.TrimSpace(strings.ToLower(u))
							if normalized != "" {
								pc.AllowedUsers = append(pc.AllowedUsers, normalized)
							}
						}
					}
				}
				conf.Providers[name] = pc
			}
		}
	}
	if dp, ok := m["default_provider"].(string); ok {
		conf.DefaultProvider = dp
	}

	// Parse cluster-specific configurations
	if clusters, ok := m["clusters"].(map[string]interface{}); ok {
		for clusterName, clusterConfig := range clusters {
			if config, ok := clusterConfig.(map[string]interface{}); ok {
				clusterConf := ClusterConfig{
					ExcludePaths: []string{},
					SsoInjection: false,
				}
				if exclude, ok := config["exclude"].(bool); ok {
					clusterConf.Exclude = exclude
				}
				if excludes, ok := config["exclude_paths"].([]interface{}); ok {
					clusterConf.ExcludePaths = make([]string, len(excludes))
					for i, exclude := range excludes {
						if path, ok := exclude.(string); ok {
							clusterConf.ExcludePaths[i] = path
						}
					}
				}
				if ssoInjection, ok := config["sso_injection"].(bool); ok {
					clusterConf.SsoInjection = ssoInjection
				}
				if ssoAppURL, ok := config["sso_appurl"].(string); ok {
					clusterConf.SsoAppURL = ssoAppURL
				}
				if ssoAppName, ok := config["sso_appname"].(string); ok {
					clusterConf.SsoAppName = ssoAppName
				}
				if tokenInclude, ok := config["add_token"].(bool); ok {
					clusterConf.TokenInclude = tokenInclude
				}
				if wsExcludes, ok := config["websocket_exclude_paths"].([]interface{}); ok {
					clusterConf.WebSocketExcludePaths = make([]string, len(wsExcludes))
					for i, exclude := range wsExcludes {
						if path, ok := exclude.(string); ok {
							clusterConf.WebSocketExcludePaths[i] = path
						}
					}
				}
				// Parse allowed_users for per-client authorization
				if allowedUsers, ok := config["allowed_users"].([]interface{}); ok {
					clusterConf.AllowedUsers = make([]string, 0, len(allowedUsers))
					for _, user := range allowedUsers {
						if u, ok := user.(string); ok {
							clusterConf.AllowedUsers = append(clusterConf.AllowedUsers, strings.ToLower(u))
						}
					}
				}
				// Parse provider name for this cluster
				if providerName, ok := config["provider"].(string); ok {
					clusterConf.ProviderName = providerName
				}
				conf.Clusters[clusterName] = clusterConf
			}
		}
	}

	// Validate required fields — skip top-level OIDC fields when providers map is present
	if len(conf.Providers) == 0 {
		if conf.IssuerURL == "" {
			return fmt.Errorf("issuer_url is required")
		}
		if conf.ClientID == "" {
			return fmt.Errorf("client_id is required")
		}
		if conf.ClientSecret == "" {
			return fmt.Errorf("client_secret is required")
		}
		if conf.RedirectURL == "" {
			return fmt.Errorf("redirect_url is required")
		}
	}

	return nil
}

// Parse parses the filter configuration from Envoy
func (p *Parser) Parse(any *anypb.Any, callbacks api.ConfigCallbackHandler) (interface{}, error) {
	conf, err := p.parseRawConfig(any)
	if err != nil {
		return nil, err
	}

	log.Printf("Parsed OAuth config: issuer_url=%s, client_id=%s, redirect_url=%s, scopes=%v, enable_api_key=%v, enable_bearer_token=%v",
		conf.IssuerURL, conf.ClientID, conf.RedirectURL, conf.Scopes, conf.EnableAPIKey, conf.EnableBearerToken)

	// Build the base CookieConfig template. InitAll and the legacy path will
	// clone this and derive per-provider cookie names (D-01, D-10).
	cookieConfig := &session.CookieConfig{
		Name:     conf.SessionCookieName,
		Path:     conf.SessionPath,
		Domain:   conf.SessionDomain,
		MaxAge:   int(conf.SessionMaxAge.Seconds()),
		Secure:   conf.SessionSecure,
		HTTPOnly: conf.SessionHttpOnly,
		SameSite: convertSameSite(conf.SessionSameSite),
	}

	// Initialize ProviderRegistry eagerly (D-07)
	logger := GetLogger()
	registry := NewProviderRegistry(logger)
	if len(conf.Providers) > 0 {
		// Inherit global defaults for provider fields that are empty
		for name, pc := range conf.Providers {
			if pc.RedirectURL == "" && conf.RedirectURL != "" {
				pc.RedirectURL = conf.RedirectURL
			}
			if len(pc.Scopes) == 0 && len(conf.Scopes) > 0 {
				pc.Scopes = conf.Scopes
			}
			conf.Providers[name] = pc
		}
		if err := registry.InitAll(conf.Providers, conf.SessionStore, cookieConfig); err != nil {
			return nil, fmt.Errorf("failed to initialize provider registry: %w", err)
		}
	} else {
		// Legacy single-provider path: create a "default" handler with its own
		// provider-namespaced CookieManager named "<base>_default" (D-02 from
		// Phase 3). Phase 5 D-04 extends partial-startup tolerance to this
		// branch — a failed discovery registers *oauth.DownHandler so requests
		// get 503 (via Plan 03) instead of the filter failing to load.
		defaultCookieConfig := cookieConfig.Clone()
		defaultCookieConfig.Name = cookieConfig.Name + "_default"
		defaultCM, err := session.NewCookieManager(nil, nil, defaultCookieConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to create cookie manager for default provider: %v", err)
		}
		cfg := &oauth.OIDCConfig{
			IssuerURL:    conf.IssuerURL,
			ClientID:     conf.ClientID,
			ClientSecret: conf.ClientSecret,
			RedirectURL:  conf.RedirectURL,
			Scopes:       conf.Scopes,
			ProviderName: "default",
		}
		handler, err := oauth.NewOAuthHandler(cfg, conf.SessionStore, defaultCM, logger)
		if err != nil {
			logger.Warn("default provider init failed, registering as down (Phase 5 D-04)",
				zap.String("provider", "default"),
				zap.Error(err))
			registry.Register("default", &oauth.DownHandler{ProviderName: "default"})
			metrics.UpdateIDPState("default", "down")
			registry.startDownHandlerRecovery("default", cfg, conf.SessionStore, defaultCM)
		} else {
			registry.Register("default", handler)
			if impl, ok := handler.(*oauth.OAuthHandlerImpl); ok {
				impl.StartRefresher(registry.ShutdownContext())
			}
		}
		if conf.DefaultProvider == "" {
			conf.DefaultProvider = "default"
		}
	}
	conf.ProviderRegistry = registry

	// Validate DefaultProvider: required when any cluster lacks an explicit provider
	needsDefault := false
	for _, cc := range conf.Clusters {
		if cc.ProviderName == "" && !cc.Exclude {
			needsDefault = true
			break
		}
	}
	if needsDefault && conf.DefaultProvider == "" {
		return nil, fmt.Errorf("default_provider is required when clusters exist without explicit provider")
	}
	if conf.DefaultProvider != "" {
		if _, err := registry.GetHandler(conf.DefaultProvider); err != nil {
			return nil, fmt.Errorf("default_provider %q not found in provider registry", conf.DefaultProvider)
		}
	}
	// Validate each cluster's explicit provider reference so misconfiguration
	// fails at startup rather than at request time with a 503.
	for clusterName, cc := range conf.Clusters {
		if cc.ProviderName != "" {
			if _, err := registry.GetHandler(cc.ProviderName); err != nil {
				return nil, fmt.Errorf("cluster %q: provider %q not found in provider registry", clusterName, cc.ProviderName)
			}
		}
	}

	return conf, nil
}


// Merge merges parent and child configurations
func (p *Parser) Merge(parent interface{}, child interface{}) interface{} {
	parentConfig := parent.(*OAuthConfig)
	childConfig := child.(*OAuthConfig)

	// Create a new config to avoid modifying the parent
	newConfig := &OAuthConfig{
		IssuerURL:         parentConfig.IssuerURL,
		ClientID:          parentConfig.ClientID,
		ClientSecret:      parentConfig.ClientSecret,
		RedirectURL:       parentConfig.RedirectURL,
		Scopes:            slices.Clone(parentConfig.Scopes),
		SessionCookieName: parentConfig.SessionCookieName,
		SessionMaxAge:     parentConfig.SessionMaxAge,
		SessionPath:       parentConfig.SessionPath,
		SessionDomain:     parentConfig.SessionDomain,
		SessionSecure:     parentConfig.SessionSecure,
		SessionHttpOnly:   parentConfig.SessionHttpOnly,
		SessionSameSite:   parentConfig.SessionSameSite,
		ExcludePaths:      slices.Clone(parentConfig.ExcludePaths),
		Clusters:          make(map[string]ClusterConfig),
		SessionStore:      parentConfig.SessionStore,
		EnableAPIKey:           parentConfig.EnableAPIKey,
		EnableBearerToken:      parentConfig.EnableBearerToken,
		EnableLLMsTxt:          parentConfig.EnableLLMsTxt,
		DefaultProvider:        parentConfig.DefaultProvider,
		Providers:              make(map[string]ProviderConfig),
		WebSocketExcludePaths:  slices.Clone(parentConfig.WebSocketExcludePaths),
		UserIDHeaderName:       parentConfig.UserIDHeaderName,
		UserEmailHeaderName:    parentConfig.UserEmailHeaderName,
		UserUsernameHeaderName: parentConfig.UserUsernameHeaderName,
		AuthProviderHeaderName: parentConfig.AuthProviderHeaderName,
		SkipAuthHeaderName:     parentConfig.SkipAuthHeaderName,
		RemoveHeaders:          slices.Clone(parentConfig.RemoveHeaders),
		ProviderRegistry:       parentConfig.ProviderRegistry,
	}

	// Copy parent providers map
	for name, pc := range parentConfig.Providers {
		copied := ProviderConfig{
			IssuerURL:    pc.IssuerURL,
			ClientID:     pc.ClientID,
			ClientSecret: pc.ClientSecret,
			RedirectURL:  pc.RedirectURL,
			Scopes:       slices.Clone(pc.Scopes),
			AllowedUsers: slices.Clone(pc.AllowedUsers),
		}
		newConfig.Providers[name] = copied
	}

	// Override with child values if specified
	if childConfig.IssuerURL != "" {
		newConfig.IssuerURL = childConfig.IssuerURL
	}
	if childConfig.ClientID != "" {
		newConfig.ClientID = childConfig.ClientID
	}
	if childConfig.ClientSecret != "" {
		newConfig.ClientSecret = childConfig.ClientSecret
	}
	if childConfig.RedirectURL != "" {
		newConfig.RedirectURL = childConfig.RedirectURL
	}
	if len(childConfig.Scopes) > 0 {
		newConfig.Scopes = slices.Clone(childConfig.Scopes)
	}

	// Override session settings if specified
	if childConfig.SessionCookieName != "" {
		newConfig.SessionCookieName = childConfig.SessionCookieName
	}
	if childConfig.SessionMaxAge != 0 {
		newConfig.SessionMaxAge = childConfig.SessionMaxAge
	}
	if childConfig.SessionPath != "" {
		newConfig.SessionPath = childConfig.SessionPath
	}
	if childConfig.SessionDomain != "" {
		newConfig.SessionDomain = childConfig.SessionDomain
	}
	if childConfig.SessionSecure != parentConfig.SessionSecure {
		newConfig.SessionSecure = childConfig.SessionSecure
	}
	if childConfig.SessionHttpOnly != parentConfig.SessionHttpOnly {
		newConfig.SessionHttpOnly = childConfig.SessionHttpOnly
	}
	if childConfig.SessionSameSite != "" {
		newConfig.SessionSameSite = childConfig.SessionSameSite
	}

	// Merge exclude paths
	if len(childConfig.ExcludePaths) > 0 {
		newConfig.ExcludePaths = append(newConfig.ExcludePaths, childConfig.ExcludePaths...)
	}

	// Override EnableAPIKey if child config explicitly sets it
	if childConfig.EnableAPIKey != parentConfig.EnableAPIKey {
		newConfig.EnableAPIKey = childConfig.EnableAPIKey
	}

	// Override EnableBearerToken if child config explicitly sets it
	if childConfig.EnableBearerToken != parentConfig.EnableBearerToken {
		newConfig.EnableBearerToken = childConfig.EnableBearerToken
	}

	// Override EnableLLMsTxt if child config explicitly sets it
	if childConfig.EnableLLMsTxt != parentConfig.EnableLLMsTxt {
		newConfig.EnableLLMsTxt = childConfig.EnableLLMsTxt
	}

	// Carry parent providers (read-only — providers must be declared at root level).
	// The ProviderRegistry is already initialized from the parent's Parse() and cannot
	// be rebuilt during Merge(). Child configs that declare new providers would have
	// uninitialized handlers, so we only preserve parent providers here.
	if childConfig.DefaultProvider != "" {
		newConfig.DefaultProvider = childConfig.DefaultProvider
	}
	// Override AuthProviderHeaderName if child specifies it (REQ-01).
	if childConfig.AuthProviderHeaderName != "" {
		newConfig.AuthProviderHeaderName = childConfig.AuthProviderHeaderName
	}

	// Copy parent cluster configs first
	for clusterName, parentClusterConfig := range parentConfig.Clusters {
		newClusterConfig := ClusterConfig{
			ExcludePaths:          slices.Clone(parentClusterConfig.ExcludePaths),
			Exclude:               parentClusterConfig.Exclude,
			AllowedUsers:          slices.Clone(parentClusterConfig.AllowedUsers),
			SsoInjection:          parentClusterConfig.SsoInjection,
			SsoAppURL:             parentClusterConfig.SsoAppURL,
			SsoAppName:            parentClusterConfig.SsoAppName,
			TokenInclude:          parentClusterConfig.TokenInclude,
			WebSocketExcludePaths: slices.Clone(parentClusterConfig.WebSocketExcludePaths),
			ProviderName:          parentClusterConfig.ProviderName,
		}
		newConfig.Clusters[clusterName] = newClusterConfig
	}

	// Merge child cluster configs
	for clusterName, childClusterConfig := range childConfig.Clusters {
		if parentClusterConfig, exists := newConfig.Clusters[clusterName]; exists {
			// Merge with existing cluster config — parent fields preserved unless child overrides
			parentClusterConfig.ExcludePaths = append(parentClusterConfig.ExcludePaths, childClusterConfig.ExcludePaths...)
			if childClusterConfig.Exclude != parentClusterConfig.Exclude {
				parentClusterConfig.Exclude = childClusterConfig.Exclude
			}
			if len(childClusterConfig.AllowedUsers) > 0 {
				parentClusterConfig.AllowedUsers = slices.Clone(childClusterConfig.AllowedUsers)
			}
			if childClusterConfig.SsoInjection {
				parentClusterConfig.SsoInjection = childClusterConfig.SsoInjection
			}
			if childClusterConfig.SsoAppURL != "" {
				parentClusterConfig.SsoAppURL = childClusterConfig.SsoAppURL
			}
			if childClusterConfig.SsoAppName != "" {
				parentClusterConfig.SsoAppName = childClusterConfig.SsoAppName
			}
			if childClusterConfig.TokenInclude {
				parentClusterConfig.TokenInclude = childClusterConfig.TokenInclude
			}
			if len(childClusterConfig.WebSocketExcludePaths) > 0 {
				parentClusterConfig.WebSocketExcludePaths = append(parentClusterConfig.WebSocketExcludePaths, childClusterConfig.WebSocketExcludePaths...)
			}
			if childClusterConfig.ProviderName != "" {
				parentClusterConfig.ProviderName = childClusterConfig.ProviderName
			}
			newConfig.Clusters[clusterName] = parentClusterConfig
		} else {
			// Add new cluster config
			newClusterConfig := ClusterConfig{
				ExcludePaths:          slices.Clone(childClusterConfig.ExcludePaths),
				Exclude:               childClusterConfig.Exclude,
				AllowedUsers:          slices.Clone(childClusterConfig.AllowedUsers),
				SsoInjection:          childClusterConfig.SsoInjection,
				SsoAppURL:             childClusterConfig.SsoAppURL,
				SsoAppName:            childClusterConfig.SsoAppName,
				TokenInclude:          childClusterConfig.TokenInclude,
				WebSocketExcludePaths: slices.Clone(childClusterConfig.WebSocketExcludePaths),
				ProviderName:          childClusterConfig.ProviderName,
			}
			newConfig.Clusters[clusterName] = newClusterConfig
		}
	}

	ensureIdentityHeadersStripped(newConfig)
	return newConfig
}
