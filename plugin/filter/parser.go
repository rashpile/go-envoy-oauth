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
	"github.com/rashpile/go-envoy-oauth/plugin/oauth"
	"github.com/rashpile/go-envoy-oauth/plugin/session"

	"google.golang.org/protobuf/types/known/anypb"
)

// ClusterConfig represents the configuration for a specific cluster
type ClusterConfig struct {
	Exclude      bool
	ExcludePaths []string
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
	CookieConfig      string        `json:"cookie_config"`

	// Header configuration
	UserIDHeaderName       string   `json:"user_id_header_name"`
	UserEmailHeaderName    string   `json:"user_email_header_name"`
	UserUsernameHeaderName string   `json:"user_username_header_name"`
	SkipAuthHeaderName     string   `json:"skip_auth_header_name"`
	RemoveHeaders          []string `json:"remove_headers"`

	// Paths that should be excluded from authentication
	ExcludePaths []string `json:"exclude_paths"`

	// Cluster-specific configurations
	Clusters map[string]ClusterConfig `json:"clusters"`

	// API Key generation feature (offline token)
	EnableAPIKey bool `json:"enable_api_key"`

	// Bearer token authentication
	EnableBearerToken bool `json:"enable_bearer_token"`

	// Session store
	SessionStore session.SessionStore

	OAuthHandler oauth.OAuthHandler
}

// Parser parses the filter configuration
type Parser struct {
}

// Parse parses the filter configuration from Envoy
func (p *Parser) Parse(any *anypb.Any, callbacks api.ConfigCallbackHandler) (interface{}, error) {
	configStruct := &xds.TypedStruct{}
	if err := any.UnmarshalTo(configStruct); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %v", err)
	}

	v := configStruct.Value
	conf := &OAuthConfig{
		Scopes:             []string{"openid", "profile", "email"},
		SessionCookieName:  "session",
		SessionMaxAge:      24 * time.Hour,
		SessionPath:        "/",
		SessionSecure:      true,
		SessionHttpOnly:    true,
		SessionSameSite:    "Lax",
		CookieConfig:       "",
		ExcludePaths:       []string{"/health"},
		Clusters:           make(map[string]ClusterConfig),
		SessionStore:       session.NewInMemorySessionStore(),
		SkipAuthHeaderName: "",
		RemoveHeaders:      []string{"X-User-ID", "X-User-Email", "X-User-Username"},
		EnableAPIKey:       false, // API key generation disabled by default
		EnableBearerToken:  true,  // Bearer token authentication enabled by default
	}

	// Parse OpenID Connect configuration
	if issuerURL, ok := v.AsMap()["issuer_url"].(string); ok {
		conf.IssuerURL = issuerURL
	}
	if clientID, ok := v.AsMap()["client_id"].(string); ok {
		conf.ClientID = clientID
	}
	if clientSecret, ok := v.AsMap()["client_secret"].(string); ok {
		conf.ClientSecret = clientSecret
	}
	if redirectURL, ok := v.AsMap()["redirect_url"].(string); ok {
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

	if scopes, ok := v.AsMap()["scopes"].([]interface{}); ok {
		conf.Scopes = make([]string, len(scopes))
		for i, scope := range scopes {
			if s, ok := scope.(string); ok {
				conf.Scopes[i] = s
			}
		}
	}

	// Parse session configuration
	if cookieName, ok := v.AsMap()["session_cookie_name"].(string); ok {
		conf.SessionCookieName = cookieName
	}
	if maxAge, ok := v.AsMap()["session_max_age"].(float64); ok {
		conf.SessionMaxAge = time.Duration(maxAge) * time.Second
	}
	if path, ok := v.AsMap()["session_path"].(string); ok {
		conf.SessionPath = path
	}
	if domain, ok := v.AsMap()["session_domain"].(string); ok {
		conf.SessionDomain = domain
	}
	if secure, ok := v.AsMap()["session_secure"].(bool); ok {
		conf.SessionSecure = secure
	}
	if httpOnly, ok := v.AsMap()["session_http_only"].(bool); ok {
		conf.SessionHttpOnly = httpOnly
	}
	if sameSite, ok := v.AsMap()["session_same_site"].(string); ok {
		conf.SessionSameSite = sameSite
	}

	// Parse exclude paths
	if excludes, ok := v.AsMap()["exclude_paths"].([]interface{}); ok {
		conf.ExcludePaths = make([]string, len(excludes))
		for i, exclude := range excludes {
			if path, ok := exclude.(string); ok {
				conf.ExcludePaths[i] = path
			}
		}
	}

	// Parse cookie configuration
	if cookieConfig, ok := v.AsMap()["cookie_config"].(string); ok {
		conf.CookieConfig = cookieConfig
	}

	// Parse header configuration
	if userIDHeaderName, ok := v.AsMap()["user_id_header_name"].(string); ok {
		conf.UserIDHeaderName = userIDHeaderName
	}
	if userEmailHeaderName, ok := v.AsMap()["user_email_header_name"].(string); ok {
		conf.UserEmailHeaderName = userEmailHeaderName
	}
	if userUsernameHeaderName, ok := v.AsMap()["user_username_header_name"].(string); ok {
		conf.UserUsernameHeaderName = userUsernameHeaderName
	}
	if skipAuthHeaderName, ok := v.AsMap()["skip_auth_header_name"].(string); ok {
		conf.SkipAuthHeaderName = skipAuthHeaderName
	}

	if removeHeaders, ok := v.AsMap()["remove_headers"].([]interface{}); ok {
		conf.RemoveHeaders = make([]string, len(removeHeaders))
		for i, header := range removeHeaders {
			if h, ok := header.(string); ok {
				conf.RemoveHeaders[i] = h
			}
		}
	}

	// Parse API key generation setting
	if enableAPIKey, ok := v.AsMap()["enable_api_key"].(bool); ok {
		conf.EnableAPIKey = enableAPIKey
	}

	// Parse bearer token authentication setting
	if enableBearerToken, ok := v.AsMap()["enable_bearer_token"].(bool); ok {
		conf.EnableBearerToken = enableBearerToken
		log.Printf("Parsed enable_bearer_token from config: %v", enableBearerToken)
	} else {
		log.Printf("enable_bearer_token not found in config, using default: %v", conf.EnableBearerToken)
	}

	// Parse cluster-specific configurations
	if clusters, ok := v.AsMap()["clusters"].(map[string]interface{}); ok {
		for clusterName, clusterConfig := range clusters {
			if config, ok := clusterConfig.(map[string]interface{}); ok {
				clusterConf := ClusterConfig{
					ExcludePaths: []string{},
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
				conf.Clusters[clusterName] = clusterConf
			}
		}
	}

	// Validate required fields
	if conf.IssuerURL == "" {
		return nil, fmt.Errorf("issuer_url is required")
	}
	if conf.ClientID == "" {
		return nil, fmt.Errorf("client_id is required")
	}
	if conf.ClientSecret == "" {
		return nil, fmt.Errorf("client_secret is required")
	}
	if conf.RedirectURL == "" {
		return nil, fmt.Errorf("redirect_url is required")
	}

	log.Printf("Parsed OAuth config: issuer_url=%s, client_id=%s, redirect_url=%s, scopes=%v, enable_api_key=%v, enable_bearer_token=%v",
		conf.IssuerURL, conf.ClientID, conf.RedirectURL, conf.Scopes, conf.EnableAPIKey, conf.EnableBearerToken)

	return conf, nil
}

// parseAuthPriority converts a comma-separated priority string into a slice
func parseAuthPriority(priority string) []string {
	if priority == "" {
		return []string{"header", "cookie", "query"}
	}

	// Split by comma and trim whitespace
	priorities := strings.Split(priority, ",")
	for i, p := range priorities {
		priorities[i] = strings.TrimSpace(p)
	}
	return priorities
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
		EnableAPIKey:      parentConfig.EnableAPIKey,
		EnableBearerToken: parentConfig.EnableBearerToken,
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

	// Copy parent cluster configs first
	for clusterName, parentClusterConfig := range parentConfig.Clusters {
		newClusterConfig := ClusterConfig{
			ExcludePaths: slices.Clone(parentClusterConfig.ExcludePaths),
			Exclude:      parentClusterConfig.Exclude,
		}
		newConfig.Clusters[clusterName] = newClusterConfig
	}

	// Merge child cluster configs
	for clusterName, childClusterConfig := range childConfig.Clusters {
		if parentClusterConfig, exists := newConfig.Clusters[clusterName]; exists {
			// Merge with existing cluster config
			parentClusterConfig.ExcludePaths = append(parentClusterConfig.ExcludePaths, childClusterConfig.ExcludePaths...)
			// Override exclude flag if different from parent
			if childClusterConfig.Exclude != parentClusterConfig.Exclude {
				parentClusterConfig.Exclude = childClusterConfig.Exclude
			}
		} else {
			// Add new cluster config
			newClusterConfig := ClusterConfig{
				ExcludePaths: slices.Clone(childClusterConfig.ExcludePaths),
				Exclude:      childClusterConfig.Exclude,
			}
			newConfig.Clusters[clusterName] = newClusterConfig
		}
	}

	return newConfig
}
