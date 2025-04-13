package filter

import (
	"fmt"
	"log"
	"strings"
	"time"

	"slices"

	xds "github.com/cncf/xds/go/xds/type/v3"
	"github.com/envoyproxy/envoy/contrib/golang/common/go/api"

	"github.com/rashpile/go-envoy-oauth/auth"
	"github.com/rashpile/go-envoy-oauth/store"
	"google.golang.org/protobuf/types/known/anypb"
)

// Default configuration values
const (
	DefaultAPIKeyHeader     = "X-API-Key"
	DefaultAPIKeyQueryParam = "x-api-key"
	DefaultAPIKeyCookie     = "api-key"
	DefaultUsernameHeader   = "X-User-ID"
	DefaultKeysFile         = "/etc/envoy/api-keys.txt"
	DefaultCheckInterval    = 60                    // seconds
	DefaultAuthPriority     = "header,query,cookie" // Priority order for auth methods
)

// Config holds the filter configuration
type Config struct {
	APIKeyHeader     string
	APIKeyQueryParam string
	APIKeyCookie     string
	UsernameHeader   string
	ExcludePaths     []string
	KeySource        store.KeySource
	ClusterConfigs   map[string]*auth.ClusterConfig
	AuthPriority     []string // Priority order: e.g. ["header", "cookie", "query"]
	CookieSettings   CookieSettings
}

// ClusterConfig holds configuration specific to a cluster
// type ClusterConfig struct {
// 	Exclude      bool
// 	ExcludePaths []string
// }

// Parser parses the filter configuration
type Parser struct {
}

// FilterFactory creates a new Filter instance
// func FilterFactory(c interface{}, callbacks api.FilterCallbackHandler) api.StreamFilter {
// 	conf, ok := c.(*Config)
// 	if !ok {
// 		panic("unexpected config type")
// 	}
// 	return &Filter{
// 		Callbacks: callbacks,
// 		Config:    conf,
// 	}
// }

// Parse parses the filter configuration from Envoy
func (p *Parser) Parse(any *anypb.Any, callbacks api.ConfigCallbackHandler) (interface{}, error) {
	configStruct := &xds.TypedStruct{}
	if err := any.UnmarshalTo(configStruct); err != nil {
		return nil, err
	}

	v := configStruct.Value
	conf := &Config{
		APIKeyHeader:     DefaultAPIKeyHeader,
		APIKeyQueryParam: DefaultAPIKeyQueryParam,
		APIKeyCookie:     DefaultAPIKeyCookie,
		UsernameHeader:   DefaultUsernameHeader,
		ExcludePaths:     []string{},
		ClusterConfigs:   make(map[string]*auth.ClusterConfig),
		AuthPriority:     parseAuthPriority(DefaultAuthPriority),
		CookieSettings:   DefaultCookieSettings(),
	}

	// Parse API key header name
	if header, ok := v.AsMap()["api_key_header"].(string); ok {
		conf.APIKeyHeader = header
	}

	// Parse API key query parameter name
	if queryParam, ok := v.AsMap()["api_key_query_param"].(string); ok {
		// Empty string is valid to disable query param authentication
		conf.APIKeyQueryParam = queryParam
	}

	// Parse API key cookie name
	if cookie, ok := v.AsMap()["api_key_cookie"].(string); ok {
		// Empty string is valid to disable cookie authentication
		conf.APIKeyCookie = cookie
	}

	// Parse authentication priority
	if priority, ok := v.AsMap()["auth_priority"].(string); ok && priority != "" {
		conf.AuthPriority = parseAuthPriority(priority)
	}

	// Parse username header name
	if header, ok := v.AsMap()["username_header"].(string); ok && header != "" {
		conf.UsernameHeader = header
	}

	// Parse exclude paths
	if excludes, ok := v.AsMap()["exclude_paths"].([]interface{}); ok {
		for _, exclude := range excludes {
			if path, ok := exclude.(string); ok {
				conf.ExcludePaths = append(conf.ExcludePaths, path)
			}
		}
	}

	// Parse cluster-specific configurations
	if clusters, ok := v.AsMap()["clusters"].(map[string]interface{}); ok {
		for clusterName, clusterConfig := range clusters {
			if config, ok := clusterConfig.(map[string]interface{}); ok {
				clusterConf := &auth.ClusterConfig{
					ExcludePaths: []string{},
					Exclude:      false,
				}
				if exclude, ok := config["exclude"].(bool); ok {
					clusterConf.Exclude = exclude
				}
				// Parse cluster-specific exclude paths
				if excludes, ok := config["exclude_paths"].([]interface{}); ok {
					for _, exclude := range excludes {
						if path, ok := exclude.(string); ok {
							clusterConf.ExcludePaths = append(clusterConf.ExcludePaths, path)
						}
					}
				}

				conf.ClusterConfigs[clusterName] = clusterConf
			}
		}
	}

	// Parse keys file path
	keysFile := DefaultKeysFile
	if file, ok := v.AsMap()["keys_file"].(string); ok && file != "" {
		keysFile = file
	}

	// Parse check interval
	checkInterval := DefaultCheckInterval
	if interval, ok := v.AsMap()["check_interval"].(float64); ok && interval >= 0 {
		checkInterval = int(interval)
	}

	// Create the key source
	keySource, err := store.NewFileKeySource(keysFile, time.Duration(checkInterval)*time.Second)
	if err != nil {
		return nil, fmt.Errorf("failed to create key source: %w", err)
	}
	conf.KeySource = keySource

	log.Printf("Parsed config: API key header=%s, API key query param=%s, API key cookie=%s, Username header=%s, Keys file=%s, Excluded paths=%v, Auth priority=%v",
		conf.APIKeyHeader, conf.APIKeyQueryParam, conf.APIKeyCookie, conf.UsernameHeader, keysFile, conf.ExcludePaths, conf.AuthPriority)

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
	parentConfig := parent.(*Config)
	childConfig := child.(*Config)

	// Create a new config to avoid modifying the parent
	newConfig := &Config{
		APIKeyHeader:     parentConfig.APIKeyHeader,
		APIKeyQueryParam: parentConfig.APIKeyQueryParam,
		APIKeyCookie:     parentConfig.APIKeyCookie,
		UsernameHeader:   parentConfig.UsernameHeader,
		AuthPriority:     slices.Clone(parentConfig.AuthPriority),
		KeySource:        parentConfig.KeySource,
		ExcludePaths:     slices.Clone(parentConfig.ExcludePaths),
		ClusterConfigs:   make(map[string]*auth.ClusterConfig),
	}

	// Override with child values if specified
	if childConfig.APIKeyHeader != "" {
		newConfig.APIKeyHeader = childConfig.APIKeyHeader
	}

	if childConfig.APIKeyQueryParam != parentConfig.APIKeyQueryParam {
		// Use child query param even if it's empty (to disable query param auth)
		newConfig.APIKeyQueryParam = childConfig.APIKeyQueryParam
	}

	if childConfig.APIKeyCookie != parentConfig.APIKeyCookie {
		// Use child cookie even if it's empty (to disable cookie auth)
		newConfig.APIKeyCookie = childConfig.APIKeyCookie
	}

	if childConfig.UsernameHeader != "" {
		newConfig.UsernameHeader = childConfig.UsernameHeader
	}

	// Override auth priority if it's different
	if len(childConfig.AuthPriority) > 0 && !slices.Equal(childConfig.AuthPriority, parentConfig.AuthPriority) {
		newConfig.AuthPriority = slices.Clone(childConfig.AuthPriority)
	}

	if childConfig.KeySource != nil {
		newConfig.KeySource = childConfig.KeySource
	}

	if len(childConfig.ExcludePaths) > 0 {
		newConfig.ExcludePaths = append(newConfig.ExcludePaths, childConfig.ExcludePaths...)
	}

	// Copy parent cluster configs first
	for clusterName, parentClusterConfig := range parentConfig.ClusterConfigs {
		newClusterConfig := &auth.ClusterConfig{
			ExcludePaths: slices.Clone(parentClusterConfig.ExcludePaths),
			Exclude:      parentClusterConfig.Exclude,
		}
		newConfig.ClusterConfigs[clusterName] = newClusterConfig
	}

	// Merge child cluster configs
	for clusterName, childClusterConfig := range childConfig.ClusterConfigs {
		if parentClusterConfig, exists := newConfig.ClusterConfigs[clusterName]; exists {
			// Merge with existing cluster config
			parentClusterConfig.ExcludePaths = append(parentClusterConfig.ExcludePaths, childClusterConfig.ExcludePaths...)
			// Override exclude flag if different from parent
			if childClusterConfig.Exclude != parentClusterConfig.Exclude {
				parentClusterConfig.Exclude = childClusterConfig.Exclude
			}
		} else {
			// Add new cluster config
			newClusterConfig := &auth.ClusterConfig{
				ExcludePaths: slices.Clone(childClusterConfig.ExcludePaths),
				Exclude:      childClusterConfig.Exclude,
			}
			newConfig.ClusterConfigs[clusterName] = newClusterConfig
		}
	}
	return newConfig
}
