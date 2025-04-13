package auth

import (
	"strings"

	"github.com/rashpile/go-envoy-oauth/store"
)

type ClusterConfig struct {
	Exclude      bool
	ExcludePaths []string
}

type AuthConfig struct {
	ClusterConfigs map[string]*ClusterConfig
	AuthPriority   []string // Priority order: e.g. ["header", "cookie", "query"]
	ExcludePaths   []string
}
type RequestFactory interface {
	HeaderApiKey() (string, bool)
	CookieApiKey() (string, bool)
	QueryApiKey() (string, bool)
}

// AuthResult represents the result of an authentication attempt
type AuthResult struct {
	Success      bool
	Username     string
	AuthKey      string
	ErrorMessage string
	StatusCode   int
}

// AuthService defines the interface for authentication operations
type AuthService interface {
	// Authenticate extracts and validates an API key from various sources
	// Returns the authentication result with username or error details
	Authenticate(requestFactory RequestFactory) AuthResult

	// ShouldSkipAuth determines if authentication should be bypassed
	// based on request path and target cluster
	ShouldSkipAuth(path string, clusterName string) bool
}

// AuthServiceImpl implements the AuthService interface
type AuthServiceImpl struct {
	keySource store.KeySource
	config    *AuthConfig
}

// NewAuthService creates a new authentication service
func NewAuthService(config *AuthConfig, keySource store.KeySource) AuthService {
	return &AuthServiceImpl{
		keySource: keySource,
		config:    config,
	}
}

// Authenticate implements the AuthService.Authenticate method
func (s *AuthServiceImpl) Authenticate(requestFactory RequestFactory) AuthResult {
	// Extract API key using priority order
	apiKey, exists := s.extractAPIKeyByPriority(requestFactory)
	if !exists || apiKey == "" {
		return AuthResult{
			Success:      false,
			ErrorMessage: "Forbidden",
			StatusCode:   401,
		}
	}

	// Validate API key
	username, err := s.keySource.GetUsername(apiKey)
	if err != nil {
		return AuthResult{
			Success:      false,
			ErrorMessage: "Invalid API key",
			StatusCode:   401,
		}
	}

	// Authentication successful
	return AuthResult{
		Success:  true,
		Username: username,
		AuthKey:  apiKey,
	}
}

// ShouldSkipAuth implements the AuthService.ShouldSkipAuth method
func (s *AuthServiceImpl) ShouldSkipAuth(path string, clusterName string) bool {
	// Extract path without query parameters
	pathOnly := getPathWithoutQuery(path)

	// Check if path is in global exclude list
	if isPathExcludedGlobally(s.config, pathOnly) {
		return true
	}

	if isClusterExcluded(s.config, clusterName) {
		return true
	}

	// Check if path is excluded for the specific cluster
	if isPathExcludedForCluster(s.config, pathOnly, clusterName) {
		return true
	}

	return false
}

// extractAPIKeyByPriority extracts the API key according to the configured priority order
func (s *AuthServiceImpl) extractAPIKeyByPriority(requestFactory RequestFactory) (string, bool) {
	for _, source := range s.config.AuthPriority {
		switch source {
		case "header":
			if apiKey, exists := requestFactory.HeaderApiKey(); exists {
				return apiKey, true
			}
		case "query":
			if apiKey, exists := requestFactory.QueryApiKey(); exists {
				return apiKey, true
			}
		case "cookie":
			if apiKey, exists := requestFactory.CookieApiKey(); exists {
				return apiKey, true
			}
		}
	}

	return "", false
}

// getPathWithoutQuery removes query parameters from a path
func getPathWithoutQuery(path string) string {
	pathOnly := path
	if queryPos := strings.Index(path, "?"); queryPos != -1 {
		pathOnly = path[:queryPos]
	}
	return pathOnly
}

// isPathExcludedGlobally checks if a path is in the global exclude list
func isPathExcludedGlobally(config *AuthConfig, pathOnly string) bool {
	return isPathInExcludeList(pathOnly, config.ExcludePaths)
}

// isPathExcludedForCluster checks if a path is excluded for a specific cluster
func isPathExcludedForCluster(config *AuthConfig, pathOnly string, clusterName string) bool {
	if clusterName == "" {
		return false
	}

	clusterConfig, exists := config.ClusterConfigs[clusterName]
	if !exists {
		return false
	}

	return isPathInExcludeList(pathOnly, clusterConfig.ExcludePaths)
}

// isPathInExcludeList is a helper function to check if a path is in an exclude list
func isPathInExcludeList(path string, excludePaths []string) bool {
	for _, excludePath := range excludePaths {
		if strings.HasPrefix(path, excludePath) {
			return true
		}
	}
	return false
}

func isClusterExcluded(config *AuthConfig, clusterName string) bool {
	clusterConfig, exists := config.ClusterConfigs[clusterName]
	if !exists {
		return false
	}
	return clusterConfig.Exclude
}
