package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestOverrideFromEnv(t *testing.T) {
	tests := []struct {
		name     string
		envVars  map[string]string
		initial  *GatewayConfig
		expected *GatewayConfig
	}{
		{
			name: "override plugin library path",
			envVars: map[string]string{
				"PLUGIN_LIBRARYPATH": "/env/override/path.so",
			},
			initial: &GatewayConfig{
				Plugin: PluginConfig{
					LibraryPath: "/default/path.so",
				},
			},
			expected: &GatewayConfig{
				Plugin: PluginConfig{
					LibraryPath: "/env/override/path.so",
				},
			},
		},
		{
			name: "override oauth issuer url",
			envVars: map[string]string{
				"OAUTH_ISSUERURL": "https://env.issuer.com",
			},
			initial: &GatewayConfig{
				OAuth: OAuthConfig{
					IssuerURL: "https://default.issuer.com",
				},
			},
			expected: &GatewayConfig{
				OAuth: OAuthConfig{
					IssuerURL: "https://env.issuer.com",
				},
			},
		},
		{
			name: "override oauth client id and secret",
			envVars: map[string]string{
				"OAUTH_CLIENTID":     "env_client_id",
				"OAUTH_CLIENTSECRET": "env_secret",
			},
			initial: &GatewayConfig{
				OAuth: OAuthConfig{
					ClientID:     "default_client_id",
					ClientSecret: "default_secret",
				},
			},
			expected: &GatewayConfig{
				OAuth: OAuthConfig{
					ClientID:     "env_client_id",
					ClientSecret: "env_secret",
				},
			},
		},
		{
			name: "override oauth redirect url",
			envVars: map[string]string{
				"OAUTH_REDIRECTURL": "/env/callback",
			},
			initial: &GatewayConfig{
				OAuth: OAuthConfig{
					RedirectURL: "/default/callback",
				},
			},
			expected: &GatewayConfig{
				OAuth: OAuthConfig{
					RedirectURL: "/env/callback",
				},
			},
		},
		{
			name: "override oauth scopes",
			envVars: map[string]string{
				"OAUTH_SCOPES": "scope1,scope2,scope3",
			},
			initial: &GatewayConfig{
				OAuth: OAuthConfig{
					Scopes: []string{"default_scope"},
				},
			},
			expected: &GatewayConfig{
				OAuth: OAuthConfig{
					Scopes: []string{"scope1", "scope2", "scope3"},
				},
			},
		},
		{
			name: "override multiple values",
			envVars: map[string]string{
				"PLUGIN_LIBRARYPATH":  "/env/path.so",
				"OAUTH_ISSUERURL":     "https://env.issuer.com",
				"OAUTH_CLIENTID":      "env_client",
				"OAUTH_CLIENTSECRET":  "env_secret",
				"OAUTH_REDIRECTURL":   "/env/callback",
				"OAUTH_SCOPES":        "openid,profile",
			},
			initial: &GatewayConfig{
				Plugin: PluginConfig{
					LibraryPath: "/default/path.so",
				},
				OAuth: OAuthConfig{
					IssuerURL:    "https://default.issuer.com",
					ClientID:     "default_client",
					ClientSecret: "default_secret",
					RedirectURL:  "/default/callback",
					Scopes:       []string{"default"},
				},
			},
			expected: &GatewayConfig{
				Plugin: PluginConfig{
					LibraryPath: "/env/path.so",
				},
				OAuth: OAuthConfig{
					IssuerURL:    "https://env.issuer.com",
					ClientID:     "env_client",
					ClientSecret: "env_secret",
					RedirectURL:  "/env/callback",
					Scopes:       []string{"openid", "profile"},
				},
			},
		},
		{
			name:    "no overrides when env vars not set",
			envVars: map[string]string{},
			initial: &GatewayConfig{
				Plugin: PluginConfig{
					LibraryPath: "/default/path.so",
				},
				OAuth: OAuthConfig{
					IssuerURL:    "https://default.issuer.com",
					ClientID:     "default_client",
					ClientSecret: "default_secret",
					RedirectURL:  "/default/callback",
					Scopes:       []string{"default"},
				},
			},
			expected: &GatewayConfig{
				Plugin: PluginConfig{
					LibraryPath: "/default/path.so",
				},
				OAuth: OAuthConfig{
					IssuerURL:    "https://default.issuer.com",
					ClientID:     "default_client",
					ClientSecret: "default_secret",
					RedirectURL:  "/default/callback",
					Scopes:       []string{"default"},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear environment
			os.Clearenv()

			// Set test environment variables
			for key, value := range tt.envVars {
				os.Setenv(key, value)
			}

			// Apply overrides
			overrideFromEnv(tt.initial)

			// Check results
			if !reflect.DeepEqual(tt.initial, tt.expected) {
				t.Errorf("overrideFromEnv() result mismatch\ngot:  %+v\nwant: %+v", tt.initial, tt.expected)
			}

			// Clean up environment
			for key := range tt.envVars {
				os.Unsetenv(key)
			}
		})
	}
}

func TestLoadConfigWithEnvOverrides(t *testing.T) {
	// Create a temporary config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "test-config.yaml")

	configContent := `plugin:
  library_path: /default/path.so
oauth:
  issuer_url: "https://default.issuer.com"
  client_id: "default_client_id"
  client_secret: "default_secret"
clients:
  - id: test_cluster
    address: test.example.com
    port: 8080
`

	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to create test config file: %v", err)
	}

	// Create config without plugin library path to test default
	configPathNoPlugin := filepath.Join(tmpDir, "test-config-no-plugin.yaml")
	configContentNoPlugin := `oauth:
  issuer_url: "https://default.issuer.com"
  client_id: "default_client_id"
  client_secret: "default_secret"
clients:
  - id: test_cluster
    address: test.example.com
    port: 8080
`
	if err := os.WriteFile(configPathNoPlugin, []byte(configContentNoPlugin), 0644); err != nil {
		t.Fatalf("Failed to create test config file without plugin: %v", err)
	}

	tests := []struct {
		name       string
		configFile string
		envVars    map[string]string
		check      func(*testing.T, *GatewayConfig)
	}{
		{
			name:       "env overrides are applied",
			configFile: configPath,
			envVars: map[string]string{
				"PLUGIN_LIBRARYPATH":  "/env/override.so",
				"OAUTH_ISSUERURL":     "https://env.issuer.com",
				"OAUTH_CLIENTID":      "env_client",
				"OAUTH_CLIENTSECRET":  "env_secret",
				"OAUTH_REDIRECTURL":   "/env/callback",
				"OAUTH_SCOPES":        "openid,profile,email",
			},
			check: func(t *testing.T, config *GatewayConfig) {
				if config.Plugin.LibraryPath != "/env/override.so" {
					t.Errorf("Plugin.LibraryPath = %v, want /env/override.so", config.Plugin.LibraryPath)
				}
				if config.OAuth.IssuerURL != "https://env.issuer.com" {
					t.Errorf("OAuth.IssuerURL = %v, want https://env.issuer.com", config.OAuth.IssuerURL)
				}
				if config.OAuth.ClientID != "env_client" {
					t.Errorf("OAuth.ClientID = %v, want env_client", config.OAuth.ClientID)
				}
				if config.OAuth.ClientSecret != "env_secret" {
					t.Errorf("OAuth.ClientSecret = %v, want env_secret", config.OAuth.ClientSecret)
				}
				if config.OAuth.RedirectURL != "/env/callback" {
					t.Errorf("OAuth.RedirectURL = %v, want /env/callback", config.OAuth.RedirectURL)
				}
				expectedScopes := []string{"openid", "profile", "email"}
				if !reflect.DeepEqual(config.OAuth.Scopes, expectedScopes) {
					t.Errorf("OAuth.Scopes = %v, want %v", config.OAuth.Scopes, expectedScopes)
				}
			},
		},
		{
			name:       "defaults are applied when no env vars set",
			configFile: configPathNoPlugin,
			envVars:    map[string]string{},
			check: func(t *testing.T, config *GatewayConfig) {
				if config.Plugin.LibraryPath != "/app/go-envoy-oauth.so" {
					t.Errorf("Plugin.LibraryPath = %v, want /app/go-envoy-oauth.so (default)", config.Plugin.LibraryPath)
				}
				if config.OAuth.RedirectURL != "/oauth/callback" {
					t.Errorf("OAuth.RedirectURL = %v, want /oauth/callback (default)", config.OAuth.RedirectURL)
				}
				expectedScopes := []string{"openid", "profile", "email"}
				if !reflect.DeepEqual(config.OAuth.Scopes, expectedScopes) {
					t.Errorf("OAuth.Scopes = %v, want %v (default)", config.OAuth.Scopes, expectedScopes)
				}
			},
		},
		{
			name:       "env override takes precedence over defaults",
			configFile: configPath,
			envVars: map[string]string{
				"OAUTH_REDIRECTURL": "/env/override",
			},
			check: func(t *testing.T, config *GatewayConfig) {
				if config.OAuth.RedirectURL != "/env/override" {
					t.Errorf("OAuth.RedirectURL = %v, want /env/override", config.OAuth.RedirectURL)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear environment
			os.Clearenv()

			// Set test environment variables
			for key, value := range tt.envVars {
				os.Setenv(key, value)
			}

			// Load config
			config, err := LoadConfig(tt.configFile)
			if err != nil {
				t.Fatalf("LoadConfig() error = %v", err)
			}

			// Run checks
			tt.check(t, config)

			// Clean up environment
			for key := range tt.envVars {
				os.Unsetenv(key)
			}
		})
	}
}