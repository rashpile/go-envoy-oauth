package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	xdstype "github.com/cncf/xds/go/xds/type/v3"
	golang "github.com/envoyproxy/go-control-plane/contrib/envoy/extensions/filters/http/golang/v3alpha"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	"gopkg.in/yaml.v3"
)

func boolPtr(b bool) *bool { return &b }

func TestClientConfigIsEnabled(t *testing.T) {
	tests := []struct {
		name    string
		enabled *bool
		want    bool
	}{
		{name: "nil pointer treated as enabled", enabled: nil, want: true},
		{name: "explicit true is enabled", enabled: boolPtr(true), want: true},
		{name: "explicit false is disabled", enabled: boolPtr(false), want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := ClientConfig{Enabled: tt.enabled}
			if got := c.IsEnabled(); got != tt.want {
				t.Errorf("IsEnabled() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestClientConfigEnabledYAMLUnmarshal(t *testing.T) {
	tests := []struct {
		name        string
		yamlContent string
		wantNil     bool
		wantValue   bool
	}{
		{
			name: "field absent gives nil pointer",
			yamlContent: `id: app1
address: app1.internal
`,
			wantNil: true,
		},
		{
			name: "enabled: true gives non-nil true",
			yamlContent: `id: app1
address: app1.internal
enabled: true
`,
			wantNil:   false,
			wantValue: true,
		},
		{
			name: "enabled: false gives non-nil false",
			yamlContent: `id: app1
address: app1.internal
enabled: false
`,
			wantNil:   false,
			wantValue: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var c ClientConfig
			if err := yaml.Unmarshal([]byte(tt.yamlContent), &c); err != nil {
				t.Fatalf("yaml.Unmarshal() error = %v", err)
			}
			if tt.wantNil {
				if c.Enabled != nil {
					t.Errorf("Enabled = %v (non-nil), want nil", *c.Enabled)
				}
			} else {
				if c.Enabled == nil {
					t.Fatalf("Enabled = nil, want non-nil pointer to %v", tt.wantValue)
				}
				if *c.Enabled != tt.wantValue {
					t.Errorf("*Enabled = %v, want %v", *c.Enabled, tt.wantValue)
				}
			}
		})
	}
}

// TestClientConfigEnabledYAMLMarshal verifies that explicit *bool pointer values
// (both true and false) survive yaml.Marshal — i.e. `omitempty` strips only nil
// pointers, not pointer-to-false. This guarantees round-trip preservation when
// operators explicitly declare `enabled: false` in YAML.
func TestClientConfigEnabledYAMLMarshal(t *testing.T) {
	t.Run("nil Enabled is omitted by omitempty", func(t *testing.T) {
		c := ClientConfig{ID: "app1", Address: "app1.internal"}
		out, err := yaml.Marshal(&c)
		if err != nil {
			t.Fatalf("yaml.Marshal() error = %v", err)
		}
		if strings.Contains(string(out), "enabled:") {
			t.Errorf("nil Enabled must be omitted by omitempty; got:\n%s", string(out))
		}
	})

	t.Run("explicit Enabled=true survives marshal", func(t *testing.T) {
		c := ClientConfig{ID: "app1", Address: "app1.internal", Enabled: boolPtr(true)}
		out, err := yaml.Marshal(&c)
		if err != nil {
			t.Fatalf("yaml.Marshal() error = %v", err)
		}
		if !strings.Contains(string(out), "enabled: true") {
			t.Errorf("explicit Enabled=true must survive marshal; got:\n%s", string(out))
		}
	})

	t.Run("explicit Enabled=false survives marshal", func(t *testing.T) {
		c := ClientConfig{ID: "app1", Address: "app1.internal", Enabled: boolPtr(false)}
		out, err := yaml.Marshal(&c)
		if err != nil {
			t.Fatalf("yaml.Marshal() error = %v", err)
		}
		if !strings.Contains(string(out), "enabled: false") {
			t.Errorf("explicit Enabled=false must survive marshal (omitempty must not strip pointer-to-false); got:\n%s", string(out))
		}
	})
}

func TestClientConfigDescription(t *testing.T) {
	t.Run("YAML round-trip preserves description value", func(t *testing.T) {
		yamlContent := `id: app1
address: app1.internal
description: "legacy auth, kept for rollback"
`
		var c ClientConfig
		if err := yaml.Unmarshal([]byte(yamlContent), &c); err != nil {
			t.Fatalf("yaml.Unmarshal() error = %v", err)
		}
		if c.Description != "legacy auth, kept for rollback" {
			t.Errorf("Description = %q, want %q", c.Description, "legacy auth, kept for rollback")
		}

		// Re-marshal and assert description is preserved
		out, err := yaml.Marshal(&c)
		if err != nil {
			t.Fatalf("yaml.Marshal() error = %v", err)
		}
		if !strings.Contains(string(out), "description: legacy auth, kept for rollback") {
			t.Errorf("marshalled YAML missing description line; got:\n%s", string(out))
		}
	})

	t.Run("absent description gives empty string", func(t *testing.T) {
		yamlContent := `id: app1
address: app1.internal
`
		var c ClientConfig
		if err := yaml.Unmarshal([]byte(yamlContent), &c); err != nil {
			t.Fatalf("yaml.Unmarshal() error = %v", err)
		}
		if c.Description != "" {
			t.Errorf("Description = %q, want empty string", c.Description)
		}

		// omitempty should keep the marshalled YAML free of a description line
		out, err := yaml.Marshal(&c)
		if err != nil {
			t.Fatalf("yaml.Marshal() error = %v", err)
		}
		if strings.Contains(string(out), "description:") {
			t.Errorf("marshalled YAML should omit description when empty; got:\n%s", string(out))
		}
	})

	t.Run("LoadConfig accepts description without error", func(t *testing.T) {
		os.Clearenv()
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "with-description.yaml")
		content := `plugin:
  library_path: /app/filter.so
oauth:
  issuer_url: https://issuer.example.com
  client_id: cid
  client_secret: secret
clients:
  - id: app1
    description: "v1 of the auth API; kept for rollback during the v2 migration"
    address: app1.internal
    port: 8080
    prefix: /
`
		if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
			t.Fatalf("write config: %v", err)
		}
		cfg, err := LoadConfig(configPath)
		if err != nil {
			t.Fatalf("LoadConfig() error = %v", err)
		}
		if len(cfg.Clients) != 1 {
			t.Fatalf("expected 1 client, got %d", len(cfg.Clients))
		}
		if cfg.Clients[0].Description != "v1 of the auth API; kept for rollback during the v2 migration" {
			t.Errorf("Description = %q, unexpected", cfg.Clients[0].Description)
		}
	})

	// Canonical operator pattern from the README "Disabling Clients" example:
	// a disabled client annotated with a description for rollback context.
	t.Run("LoadConfig accepts description and enabled:false on same client", func(t *testing.T) {
		os.Clearenv()
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "description-and-disabled.yaml")
		content := `plugin:
  library_path: /app/filter.so
oauth:
  issuer_url: https://issuer.example.com
  client_id: cid
  client_secret: secret
clients:
  - id: legacy_api
    description: "v1 of the auth API; kept for rollback during the v2 migration"
    address: legacy-backend
    port: 8080
    prefix: /
    enabled: false
  - id: app1
    address: app1.internal
`
		if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
			t.Fatalf("write config: %v", err)
		}
		cfg, err := LoadConfig(configPath)
		if err != nil {
			t.Fatalf("LoadConfig() error = %v", err)
		}
		var legacy *ClientConfig
		for i := range cfg.Clients {
			if cfg.Clients[i].ID == "legacy_api" {
				legacy = &cfg.Clients[i]
				break
			}
		}
		if legacy == nil {
			t.Fatal("legacy_api client missing from loaded config")
		}
		if legacy.Description != "v1 of the auth API; kept for rollback during the v2 migration" {
			t.Errorf("Description = %q, unexpected", legacy.Description)
		}
		if legacy.IsEnabled() {
			t.Errorf("legacy_api IsEnabled() = true, want false")
		}
	})
}

// TestClientConfigDescriptionDoesNotLeakIntoFilterConfig builds a listener
// from a config containing a `description` value and walks the produced
// plugin config struct to assert the field is not propagated into the per-
// client filter config map.
func TestClientConfigDescriptionDoesNotLeakIntoFilterConfig(t *testing.T) {
	cfg := &GatewayConfig{
		Plugin: PluginConfig{LibraryPath: "/app/filter.so"},
		Providers: map[string]ProviderConfig{
			"default": {
				IssuerURL:    "https://issuer.example.com",
				ClientID:     "cid",
				ClientSecret: "secret",
			},
		},
		DefaultProvider: "default",
		Listener:        ListenerConfig{Address: "0.0.0.0", Port: 8080},
		Clients: []ClientConfig{
			{
				ID:          "app1",
				Description: "operator-only metadata; should not appear in filter config",
				Address:     "app1.internal",
				Port:        8080,
				Prefix:      "/",
			},
		},
	}

	listeners, err := MakeListener(cfg)
	if err != nil {
		t.Fatalf("MakeListener() error = %v", err)
	}
	if len(listeners) == 0 {
		t.Fatal("expected at least one listener")
	}

	lst, ok := listeners[0].(*listener.Listener)
	if !ok {
		t.Fatalf("listeners[0] is %T, want *listener.Listener", listeners[0])
	}

	// Walk the listener -> filter chain -> HCM -> golang filter -> typed struct.
	if len(lst.FilterChains) == 0 || len(lst.FilterChains[0].Filters) == 0 {
		t.Fatal("listener has no HTTP connection manager filter")
	}
	hcmAny := lst.FilterChains[0].Filters[0].GetTypedConfig()
	if hcmAny == nil {
		t.Fatal("HCM filter has no typed config")
	}
	var manager hcm.HttpConnectionManager
	if err := hcmAny.UnmarshalTo(&manager); err != nil {
		t.Fatalf("unmarshal HCM: %v", err)
	}

	// Locate the golang filter.
	var golangFilterCfg golang.Config
	found := false
	for _, hf := range manager.HttpFilters {
		if hf.Name != "envoy.filters.http.golang" {
			continue
		}
		if err := hf.GetTypedConfig().UnmarshalTo(&golangFilterCfg); err != nil {
			t.Fatalf("unmarshal golang filter: %v", err)
		}
		found = true
		break
	}
	if !found {
		t.Fatal("envoy.filters.http.golang filter not found in HCM filters")
	}

	// PluginConfig is the inner Any holding our TypedStruct.
	var typed xdstype.TypedStruct
	if err := golangFilterCfg.PluginConfig.UnmarshalTo(&typed); err != nil {
		t.Fatalf("unmarshal TypedStruct: %v", err)
	}

	clustersField, ok := typed.Value.Fields["clusters"]
	if !ok {
		t.Fatal("plugin config missing 'clusters' field")
	}
	clustersStruct := clustersField.GetStructValue()
	if clustersStruct == nil {
		t.Fatal("'clusters' field is not a struct")
	}
	app1Field, ok := clustersStruct.Fields["app1"]
	if !ok {
		t.Fatalf("clusters map missing entry for client 'app1'; have keys: %v", clustersStruct.Fields)
	}
	app1Struct := app1Field.GetStructValue()
	if app1Struct == nil {
		t.Fatal("clusters['app1'] is not a struct")
	}
	if _, leaked := app1Struct.Fields["description"]; leaked {
		t.Errorf("description leaked into filter config; clusters['app1'] = %v", app1Struct.Fields)
	}
}

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

func TestLoadConfigMultiProvider(t *testing.T) {
	tmpDir := t.TempDir()

	writeConfig := func(name, content string) string {
		path := filepath.Join(tmpDir, name)
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			t.Fatalf("failed to write config %s: %v", name, err)
		}
		return path
	}

	t.Run("multi-provider config loads successfully", func(t *testing.T) {
		os.Clearenv()
		path := writeConfig("multi-provider.yaml", `
plugin:
  library_path: /app/filter.so
providers:
  keycloak:
    issuer_url: https://keycloak.example.com/realms/myrealm
    client_id: my-client
    client_secret: my-secret
  google:
    issuer_url: https://accounts.google.com
    client_id: google-client-id
    client_secret: google-secret
default_provider: keycloak
clients:
  - id: app1
    address: app1.internal
    port: 8080
    prefix: /
`)
		config, err := LoadConfig(path)
		if err != nil {
			t.Fatalf("LoadConfig() error = %v", err)
		}
		if config.Providers["keycloak"].IssuerURL != "https://keycloak.example.com/realms/myrealm" {
			t.Errorf("keycloak IssuerURL = %v, want https://keycloak.example.com/realms/myrealm", config.Providers["keycloak"].IssuerURL)
		}
		if config.Providers["google"].IssuerURL != "https://accounts.google.com" {
			t.Errorf("google IssuerURL = %v, want https://accounts.google.com", config.Providers["google"].IssuerURL)
		}
		if config.DefaultProvider != "keycloak" {
			t.Errorf("DefaultProvider = %v, want keycloak", config.DefaultProvider)
		}
	})

	t.Run("client with provider field set", func(t *testing.T) {
		os.Clearenv()
		path := writeConfig("client-provider.yaml", `
plugin:
  library_path: /app/filter.so
providers:
  keycloak:
    issuer_url: https://keycloak.example.com/realms/myrealm
    client_id: my-client
    client_secret: my-secret
  google:
    issuer_url: https://accounts.google.com
    client_id: google-client-id
    client_secret: google-secret
default_provider: keycloak
clients:
  - id: app1
    address: app1.internal
    port: 8080
    prefix: /
    provider: google
`)
		config, err := LoadConfig(path)
		if err != nil {
			t.Fatalf("LoadConfig() error = %v", err)
		}
		if config.Clients[0].Provider != "google" {
			t.Errorf("client Provider = %v, want google", config.Clients[0].Provider)
		}
	})

	t.Run("client without provider field has empty Provider", func(t *testing.T) {
		os.Clearenv()
		path := writeConfig("client-no-provider.yaml", `
plugin:
  library_path: /app/filter.so
providers:
  keycloak:
    issuer_url: https://keycloak.example.com/realms/myrealm
    client_id: my-client
    client_secret: my-secret
default_provider: keycloak
clients:
  - id: app1
    address: app1.internal
    port: 8080
    prefix: /
`)
		config, err := LoadConfig(path)
		if err != nil {
			t.Fatalf("LoadConfig() error = %v", err)
		}
		if config.Clients[0].Provider != "" {
			t.Errorf("client Provider = %v, want empty string", config.Clients[0].Provider)
		}
	})

	t.Run("legacy config normalizes to default provider", func(t *testing.T) {
		os.Clearenv()
		path := writeConfig("legacy.yaml", `
plugin:
  library_path: /app/filter.so
oauth:
  issuer_url: https://legacy.issuer.com/realms/myrealm
  client_id: legacy-client
  client_secret: legacy-secret
clients:
  - id: app1
    address: app1.internal
    port: 8080
    prefix: /
`)
		config, err := LoadConfig(path)
		if err != nil {
			t.Fatalf("LoadConfig() error = %v", err)
		}
		if config.Providers == nil {
			t.Fatal("Providers map is nil after normalization")
		}
		p, ok := config.Providers["default"]
		if !ok {
			t.Fatalf("expected 'default' provider after normalization, got %v", config.Providers)
		}
		if p.IssuerURL != "https://legacy.issuer.com/realms/myrealm" {
			t.Errorf("default provider IssuerURL = %v, want https://legacy.issuer.com/realms/myrealm", p.IssuerURL)
		}
		if p.ClientID != "legacy-client" {
			t.Errorf("default provider ClientID = %v, want legacy-client", p.ClientID)
		}
		if config.DefaultProvider != "default" {
			t.Errorf("DefaultProvider = %v, want default", config.DefaultProvider)
		}
	})

	t.Run("legacy config with env var overrides normalizes correctly", func(t *testing.T) {
		os.Clearenv()
		os.Setenv("OAUTH_ISSUERURL", "https://env.issuer.com/realms/env")
		os.Setenv("OAUTH_CLIENTID", "env-client")
		os.Setenv("OAUTH_CLIENTSECRET", "env-secret")
		defer os.Clearenv()

		path := writeConfig("legacy-env.yaml", `
plugin:
  library_path: /app/filter.so
oauth:
  issuer_url: https://yaml.issuer.com/realms/yaml
  client_id: yaml-client
  client_secret: yaml-secret
clients:
  - id: app1
    address: app1.internal
    port: 8080
    prefix: /
`)
		config, err := LoadConfig(path)
		if err != nil {
			t.Fatalf("LoadConfig() error = %v", err)
		}
		p := config.Providers["default"]
		if p.IssuerURL != "https://env.issuer.com/realms/env" {
			t.Errorf("default provider IssuerURL = %v, want env override", p.IssuerURL)
		}
		if p.ClientID != "env-client" {
			t.Errorf("default provider ClientID = %v, want env-client", p.ClientID)
		}
	})

	t.Run("default_provider referencing undefined provider returns error", func(t *testing.T) {
		os.Clearenv()
		path := writeConfig("bad-default.yaml", `
plugin:
  library_path: /app/filter.so
providers:
  keycloak:
    issuer_url: https://keycloak.example.com/realms/myrealm
    client_id: my-client
    client_secret: my-secret
default_provider: nonexistent
clients:
  - id: app1
    address: app1.internal
    port: 8080
    prefix: /
`)
		_, err := LoadConfig(path)
		if err == nil {
			t.Fatal("expected error for undefined default_provider, got nil")
		}
		if !strings.Contains(err.Error(), "default_provider") {
			t.Errorf("error %q does not contain 'default_provider'", err.Error())
		}
	})

	t.Run("client referencing undefined provider returns error", func(t *testing.T) {
		os.Clearenv()
		path := writeConfig("bad-client-provider.yaml", `
plugin:
  library_path: /app/filter.so
providers:
  keycloak:
    issuer_url: https://keycloak.example.com/realms/myrealm
    client_id: my-client
    client_secret: my-secret
default_provider: keycloak
clients:
  - id: app1
    address: app1.internal
    port: 8080
    prefix: /
    provider: nonexistent
`)
		_, err := LoadConfig(path)
		if err == nil {
			t.Fatal("expected error for undefined client provider, got nil")
		}
		if !strings.Contains(err.Error(), "app1") {
			t.Errorf("error %q does not contain client ID 'app1'", err.Error())
		}
		if !strings.Contains(err.Error(), "nonexistent") {
			t.Errorf("error %q does not contain provider name 'nonexistent'", err.Error())
		}
	})

	t.Run("client with empty provider field passes validation", func(t *testing.T) {
		os.Clearenv()
		path := writeConfig("empty-client-provider.yaml", `
plugin:
  library_path: /app/filter.so
providers:
  keycloak:
    issuer_url: https://keycloak.example.com/realms/myrealm
    client_id: my-client
    client_secret: my-secret
default_provider: keycloak
clients:
  - id: app1
    address: app1.internal
    port: 8080
    prefix: /
    provider: ""
`)
		_, err := LoadConfig(path)
		if err != nil {
			t.Fatalf("expected no error for empty client provider, got: %v", err)
		}
	})

	t.Run("provider missing issuer_url returns error", func(t *testing.T) {
		os.Clearenv()
		path := writeConfig("missing-issuer.yaml", `
plugin:
  library_path: /app/filter.so
providers:
  keycloak:
    client_id: my-client
    client_secret: my-secret
default_provider: keycloak
clients:
  - id: app1
    address: app1.internal
    port: 8080
    prefix: /
`)
		_, err := LoadConfig(path)
		if err == nil {
			t.Fatal("expected error for missing issuer_url, got nil")
		}
		if !strings.Contains(err.Error(), "issuer_url is required") {
			t.Errorf("error %q does not contain 'issuer_url is required'", err.Error())
		}
	})

	t.Run("provider missing client_id returns error", func(t *testing.T) {
		os.Clearenv()
		path := writeConfig("missing-client-id.yaml", `
plugin:
  library_path: /app/filter.so
providers:
  keycloak:
    issuer_url: https://keycloak.example.com/realms/myrealm
    client_secret: my-secret
default_provider: keycloak
clients:
  - id: app1
    address: app1.internal
    port: 8080
    prefix: /
`)
		_, err := LoadConfig(path)
		if err == nil {
			t.Fatal("expected error for missing client_id, got nil")
		}
		if !strings.Contains(err.Error(), "client_id is required") {
			t.Errorf("error %q does not contain 'client_id is required'", err.Error())
		}
	})

	t.Run("provider missing client_secret returns error", func(t *testing.T) {
		os.Clearenv()
		path := writeConfig("missing-secret.yaml", `
plugin:
  library_path: /app/filter.so
providers:
  keycloak:
    issuer_url: https://keycloak.example.com/realms/myrealm
    client_id: my-client
default_provider: keycloak
clients:
  - id: app1
    address: app1.internal
    port: 8080
    prefix: /
`)
		_, err := LoadConfig(path)
		if err == nil {
			t.Fatal("expected error for missing client_secret, got nil")
		}
		if !strings.Contains(err.Error(), "client_secret is required") {
			t.Errorf("error %q does not contain 'client_secret is required'", err.Error())
		}
	})

	t.Run("invalid provider name returns error", func(t *testing.T) {
		os.Clearenv()
		path := writeConfig("invalid-name.yaml", `
plugin:
  library_path: /app/filter.so
providers:
  "invalid name!":
    issuer_url: https://keycloak.example.com/realms/myrealm
    client_id: my-client
    client_secret: my-secret
default_provider: "invalid name!"
clients:
  - id: app1
    address: app1.internal
    port: 8080
    prefix: /
`)
		_, err := LoadConfig(path)
		if err == nil {
			t.Fatal("expected error for invalid provider name, got nil")
		}
		if !strings.Contains(err.Error(), "invalid") {
			t.Errorf("error %q does not contain 'invalid'", err.Error())
		}
	})

	t.Run("valid provider name good-name passes", func(t *testing.T) {
		os.Clearenv()
		path := writeConfig("valid-name-hyphen.yaml", `
plugin:
  library_path: /app/filter.so
providers:
  good-name:
    issuer_url: https://keycloak.example.com/realms/myrealm
    client_id: my-client
    client_secret: my-secret
default_provider: good-name
clients:
  - id: app1
    address: app1.internal
    port: 8080
    prefix: /
`)
		_, err := LoadConfig(path)
		if err != nil {
			t.Fatalf("expected no error for valid name 'good-name', got: %v", err)
		}
	})

	t.Run("valid provider name 123start passes", func(t *testing.T) {
		os.Clearenv()
		path := writeConfig("valid-name-numeric.yaml", `
plugin:
  library_path: /app/filter.so
providers:
  123start:
    issuer_url: https://keycloak.example.com/realms/myrealm
    client_id: my-client
    client_secret: my-secret
default_provider: 123start
clients:
  - id: app1
    address: app1.internal
    port: 8080
    prefix: /
`)
		_, err := LoadConfig(path)
		if err != nil {
			t.Fatalf("expected no error for valid name '123start', got: %v", err)
		}
	})

	t.Run("leading hyphen provider name returns error", func(t *testing.T) {
		os.Clearenv()
		path := writeConfig("leading-hyphen.yaml", `
plugin:
  library_path: /app/filter.so
providers:
  "-leading-hyphen":
    issuer_url: https://keycloak.example.com/realms/myrealm
    client_id: my-client
    client_secret: my-secret
default_provider: "-leading-hyphen"
clients:
  - id: app1
    address: app1.internal
    port: 8080
    prefix: /
`)
		_, err := LoadConfig(path)
		if err == nil {
			t.Fatal("expected error for leading-hyphen provider name, got nil")
		}
	})

	t.Run("duplicate issuer+client_id returns error", func(t *testing.T) {
		os.Clearenv()
		path := writeConfig("duplicate.yaml", `
plugin:
  library_path: /app/filter.so
providers:
  provider1:
    issuer_url: https://keycloak.example.com/realms/myrealm
    client_id: same-client
    client_secret: secret1
  provider2:
    issuer_url: https://keycloak.example.com/realms/myrealm
    client_id: same-client
    client_secret: secret2
default_provider: provider1
clients:
  - id: app1
    address: app1.internal
    port: 8080
    prefix: /
`)
		_, err := LoadConfig(path)
		if err == nil {
			t.Fatal("expected error for duplicate issuer+client_id, got nil")
		}
		if !strings.Contains(err.Error(), "duplicate") {
			t.Errorf("error %q does not contain 'duplicate'", err.Error())
		}
	})

	t.Run("same issuer_url different client_id passes", func(t *testing.T) {
		os.Clearenv()
		path := writeConfig("same-issuer-diff-client.yaml", `
plugin:
  library_path: /app/filter.so
providers:
  provider1:
    issuer_url: https://keycloak.example.com/realms/myrealm
    client_id: client1
    client_secret: secret1
  provider2:
    issuer_url: https://keycloak.example.com/realms/myrealm
    client_id: client2
    client_secret: secret2
default_provider: provider1
clients:
  - id: app1
    address: app1.internal
    port: 8080
    prefix: /
`)
		_, err := LoadConfig(path)
		if err != nil {
			t.Fatalf("expected no error for same issuer different client_id, got: %v", err)
		}
	})

	t.Run("existing legacy config without providers map loads without errors", func(t *testing.T) {
		os.Clearenv()
		path := writeConfig("legacy-compat.yaml", `
plugin:
  library_path: /app/filter.so
oauth:
  issuer_url: https://legacy.issuer.com/realms/myrealm
  client_id: legacy-client
  client_secret: legacy-secret
clients:
  - id: app1
    address: app1.internal
    port: 8080
    prefix: /
`)
		_, err := LoadConfig(path)
		if err != nil {
			t.Fatalf("legacy config without providers map should load fine, got: %v", err)
		}
	})
}

func TestNormalizeProviders(t *testing.T) {
	t.Run("empty providers and oauth fields set normalizes to default", func(t *testing.T) {
		config := &GatewayConfig{
			OAuth: OAuthConfig{
				IssuerURL:    "https://issuer.com",
				ClientID:     "client-id",
				ClientSecret: "client-secret",
				RedirectURL:  "/oauth/callback",
				Scopes:       []string{"openid"},
			},
		}
		if err := normalizeProviders(config); err != nil {
			t.Fatalf("normalizeProviders() error = %v", err)
		}
		if len(config.Providers) != 1 {
			t.Fatalf("expected 1 provider, got %d", len(config.Providers))
		}
		p := config.Providers["default"]
		if p.IssuerURL != "https://issuer.com" {
			t.Errorf("IssuerURL = %v, want https://issuer.com", p.IssuerURL)
		}
		if p.ClientID != "client-id" {
			t.Errorf("ClientID = %v, want client-id", p.ClientID)
		}
		if p.ClientSecret != "client-secret" {
			t.Errorf("ClientSecret = %v, want client-secret", p.ClientSecret)
		}
		if config.DefaultProvider != "default" {
			t.Errorf("DefaultProvider = %v, want default", config.DefaultProvider)
		}
	})

	t.Run("empty providers and empty oauth returns error", func(t *testing.T) {
		config := &GatewayConfig{}
		err := normalizeProviders(config)
		if err == nil {
			t.Fatal("expected error when both providers and oauth fields are empty, got nil")
		}
		if !strings.Contains(err.Error(), "requires") {
			t.Errorf("unexpected error message: %v", err)
		}
	})

	t.Run("partial oauth fields returns error", func(t *testing.T) {
		config := &GatewayConfig{
			OAuth: OAuthConfig{
				IssuerURL: "https://example.com",
			},
		}
		err := normalizeProviders(config)
		if err == nil {
			t.Fatal("expected error when oauth fields are partial, got nil")
		}
	})

	t.Run("providers already set skips normalization", func(t *testing.T) {
		config := &GatewayConfig{
			Providers: map[string]ProviderConfig{
				"keycloak": {
					IssuerURL:    "https://keycloak.example.com",
					ClientID:     "client",
					ClientSecret: "secret",
				},
			},
			DefaultProvider: "keycloak",
		}
		if err := normalizeProviders(config); err != nil {
			t.Fatalf("normalizeProviders() error = %v", err)
		}
		if len(config.Providers) != 1 {
			t.Errorf("expected 1 provider unchanged, got %d", len(config.Providers))
		}
	})
}

func TestValidateProviders(t *testing.T) {
	validProvider := ProviderConfig{
		IssuerURL:    "https://issuer.com",
		ClientID:     "client-id",
		ClientSecret: "secret",
	}

	t.Run("valid config passes", func(t *testing.T) {
		config := &GatewayConfig{
			Providers:       map[string]ProviderConfig{"keycloak": validProvider},
			DefaultProvider: "keycloak",
		}
		if err := validateProviders(config); err != nil {
			t.Fatalf("validateProviders() error = %v", err)
		}
	})

	t.Run("invalid provider name returns error", func(t *testing.T) {
		config := &GatewayConfig{
			Providers:       map[string]ProviderConfig{"invalid name!": validProvider},
			DefaultProvider: "invalid name!",
		}
		err := validateProviders(config)
		if err == nil {
			t.Fatal("expected error for invalid provider name")
		}
		if !strings.Contains(err.Error(), "invalid") {
			t.Errorf("error %q does not contain 'invalid'", err.Error())
		}
	})

	t.Run("missing issuer_url returns error", func(t *testing.T) {
		p := validProvider
		p.IssuerURL = ""
		config := &GatewayConfig{
			Providers:       map[string]ProviderConfig{"keycloak": p},
			DefaultProvider: "keycloak",
		}
		err := validateProviders(config)
		if err == nil {
			t.Fatal("expected error for missing issuer_url")
		}
		if !strings.Contains(err.Error(), "issuer_url is required") {
			t.Errorf("error %q does not contain 'issuer_url is required'", err.Error())
		}
	})

	t.Run("missing client_id returns error", func(t *testing.T) {
		p := validProvider
		p.ClientID = ""
		config := &GatewayConfig{
			Providers:       map[string]ProviderConfig{"keycloak": p},
			DefaultProvider: "keycloak",
		}
		err := validateProviders(config)
		if err == nil {
			t.Fatal("expected error for missing client_id")
		}
		if !strings.Contains(err.Error(), "client_id is required") {
			t.Errorf("error %q does not contain 'client_id is required'", err.Error())
		}
	})

	t.Run("missing client_secret returns error", func(t *testing.T) {
		p := validProvider
		p.ClientSecret = ""
		config := &GatewayConfig{
			Providers:       map[string]ProviderConfig{"keycloak": p},
			DefaultProvider: "keycloak",
		}
		err := validateProviders(config)
		if err == nil {
			t.Fatal("expected error for missing client_secret")
		}
		if !strings.Contains(err.Error(), "client_secret is required") {
			t.Errorf("error %q does not contain 'client_secret is required'", err.Error())
		}
	})

	t.Run("undefined default_provider returns error", func(t *testing.T) {
		config := &GatewayConfig{
			Providers:       map[string]ProviderConfig{"keycloak": validProvider},
			DefaultProvider: "nonexistent",
		}
		err := validateProviders(config)
		if err == nil {
			t.Fatal("expected error for undefined default_provider")
		}
		if !strings.Contains(err.Error(), "default_provider") {
			t.Errorf("error %q does not contain 'default_provider'", err.Error())
		}
	})

	t.Run("client referencing undefined provider returns error", func(t *testing.T) {
		config := &GatewayConfig{
			Providers:       map[string]ProviderConfig{"keycloak": validProvider},
			DefaultProvider: "keycloak",
			Clients: []ClientConfig{
				{ID: "app1", Address: "app1.internal", Provider: "nonexistent"},
			},
		}
		err := validateProviders(config)
		if err == nil {
			t.Fatal("expected error for client referencing undefined provider")
		}
		if !strings.Contains(err.Error(), "app1") {
			t.Errorf("error %q does not contain 'app1'", err.Error())
		}
		if !strings.Contains(err.Error(), "nonexistent") {
			t.Errorf("error %q does not contain 'nonexistent'", err.Error())
		}
	})

	t.Run("client with empty provider passes", func(t *testing.T) {
		config := &GatewayConfig{
			Providers:       map[string]ProviderConfig{"keycloak": validProvider},
			DefaultProvider: "keycloak",
			Clients: []ClientConfig{
				{ID: "app1", Address: "app1.internal", Provider: ""},
			},
		}
		if err := validateProviders(config); err != nil {
			t.Fatalf("expected no error for client with empty provider, got: %v", err)
		}
	})

	t.Run("client with empty provider and no default_provider returns error", func(t *testing.T) {
		config := &GatewayConfig{
			Providers: map[string]ProviderConfig{"keycloak": validProvider},
			Clients: []ClientConfig{
				{ID: "app1", Address: "app1.internal", Provider: ""},
			},
		}
		err := validateProviders(config)
		if err == nil {
			t.Fatal("expected error when client has no provider and no default_provider")
		}
		if !strings.Contains(err.Error(), "no default_provider") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("duplicate issuer+client_id returns error", func(t *testing.T) {
		config := &GatewayConfig{
			Providers: map[string]ProviderConfig{
				"p1": {IssuerURL: "https://issuer.com", ClientID: "same", ClientSecret: "s1"},
				"p2": {IssuerURL: "https://issuer.com", ClientID: "same", ClientSecret: "s2"},
			},
			DefaultProvider: "p1",
		}
		err := validateProviders(config)
		if err == nil {
			t.Fatal("expected error for duplicate issuer+client_id")
		}
		if !strings.Contains(err.Error(), "duplicate") {
			t.Errorf("error %q does not contain 'duplicate'", err.Error())
		}
	})

	t.Run("same issuer different client_id passes", func(t *testing.T) {
		config := &GatewayConfig{
			Providers: map[string]ProviderConfig{
				"p1": {IssuerURL: "https://issuer.com", ClientID: "client1", ClientSecret: "s1"},
				"p2": {IssuerURL: "https://issuer.com", ClientID: "client2", ClientSecret: "s2"},
			},
			DefaultProvider: "p1",
		}
		if err := validateProviders(config); err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
	})

	t.Run("disabled client referencing undefined provider is skipped", func(t *testing.T) {
		config := &GatewayConfig{
			Providers:       map[string]ProviderConfig{"keycloak": validProvider},
			DefaultProvider: "keycloak",
			Clients: []ClientConfig{
				{ID: "legacy", Address: "legacy.internal", Provider: "nonexistent", Enabled: boolPtr(false)},
			},
		}
		if err := validateProviders(config); err != nil {
			t.Fatalf("expected no error for disabled client with undefined provider, got: %v", err)
		}
	})

	t.Run("disabled client without default_provider passes", func(t *testing.T) {
		config := &GatewayConfig{
			Providers: map[string]ProviderConfig{"keycloak": validProvider},
			Clients: []ClientConfig{
				{ID: "legacy", Address: "legacy.internal", Enabled: boolPtr(false)},
			},
		}
		if err := validateProviders(config); err != nil {
			t.Fatalf("expected no error for disabled client without default_provider, got: %v", err)
		}
	})
}

// TestLoadConfigSkipsDisabledClientValidation exercises the per-client required-field
// validation in LoadConfig: disabled clients may omit `address` (and even `id`), but
// enabled clients must still pass validation. The mixed-case test ensures that the
// disabled-client skip does not short-circuit iteration before validating the enabled
// client.
func TestLoadConfigSkipsDisabledClientValidation(t *testing.T) {
	tmpDir := t.TempDir()
	writeConfig := func(name, content string) string {
		path := filepath.Join(tmpDir, name)
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			t.Fatalf("failed to write config %s: %v", name, err)
		}
		return path
	}

	t.Run("disabled client missing address loads without error", func(t *testing.T) {
		os.Clearenv()
		path := writeConfig("disabled-no-address.yaml", `
plugin:
  library_path: /app/filter.so
oauth:
  issuer_url: https://issuer.example.com
  client_id: cid
  client_secret: secret
clients:
  - id: legacy
    enabled: false
  - id: app1
    address: app1.internal
`)
		cfg, err := LoadConfig(path)
		if err != nil {
			t.Fatalf("LoadConfig() error = %v", err)
		}
		if len(cfg.Clients) != 2 {
			t.Fatalf("expected 2 clients, got %d", len(cfg.Clients))
		}
	})

	t.Run("disabled client missing both id AND address loads without error", func(t *testing.T) {
		os.Clearenv()
		// Both `id` and `address` are absent on the disabled entry. The validation
		// loop must skip the disabled client entirely so neither required-field
		// check fires.
		path := writeConfig("disabled-no-id-no-address.yaml", `
plugin:
  library_path: /app/filter.so
oauth:
  issuer_url: https://issuer.example.com
  client_id: cid
  client_secret: secret
clients:
  - enabled: false
  - id: app1
    address: app1.internal
`)
		cfg, err := LoadConfig(path)
		if err != nil {
			t.Fatalf("LoadConfig() error = %v", err)
		}
		if len(cfg.Clients) != 2 {
			t.Fatalf("expected 2 clients, got %d", len(cfg.Clients))
		}
	})

	t.Run("disabled client referencing undefined provider loads without error", func(t *testing.T) {
		os.Clearenv()
		path := writeConfig("disabled-bad-provider.yaml", `
plugin:
  library_path: /app/filter.so
providers:
  keycloak:
    issuer_url: https://keycloak.example.com/realms/myrealm
    client_id: my-client
    client_secret: my-secret
default_provider: keycloak
clients:
  - id: legacy
    address: legacy.internal
    provider: nonexistent
    enabled: false
  - id: app1
    address: app1.internal
`)
		if _, err := LoadConfig(path); err != nil {
			t.Fatalf("expected no error for disabled client with undefined provider, got: %v", err)
		}
	})

	t.Run("enabled client missing address still errors", func(t *testing.T) {
		os.Clearenv()
		path := writeConfig("enabled-no-address.yaml", `
plugin:
  library_path: /app/filter.so
oauth:
  issuer_url: https://issuer.example.com
  client_id: cid
  client_secret: secret
clients:
  - id: app1
`)
		_, err := LoadConfig(path)
		if err == nil {
			t.Fatal("expected error for enabled client missing address, got nil")
		}
		if !strings.Contains(err.Error(), "app1") {
			t.Errorf("error %q does not contain 'app1'", err.Error())
		}
		if !strings.Contains(err.Error(), "address is required") {
			t.Errorf("error %q does not contain 'address is required'", err.Error())
		}
	})

	t.Run("mixed disabled+enabled both missing address surfaces enabled client error", func(t *testing.T) {
		os.Clearenv()
		// The disabled client is listed first to prove the validation loop continues
		// past it and still catches the enabled client's missing address.
		path := writeConfig("mixed-missing-address.yaml", `
plugin:
  library_path: /app/filter.so
oauth:
  issuer_url: https://issuer.example.com
  client_id: cid
  client_secret: secret
clients:
  - id: legacy
    enabled: false
  - id: required-app
`)
		_, err := LoadConfig(path)
		if err == nil {
			t.Fatal("expected error for mixed config with enabled client missing address, got nil")
		}
		if !strings.Contains(err.Error(), "required-app") {
			t.Errorf("error %q must mention the enabled client ID 'required-app'", err.Error())
		}
		if strings.Contains(err.Error(), "legacy") {
			t.Errorf("error %q should not mention the disabled client 'legacy'", err.Error())
		}
	})

	t.Run("disabled client preserves Port and Prefix defaults", func(t *testing.T) {
		os.Clearenv()
		// Defaults loop deliberately runs for disabled clients so flipping
		// `enabled: true` produces a sane runtime config without further edits.
		path := writeConfig("disabled-defaults.yaml", `
plugin:
  library_path: /app/filter.so
oauth:
  issuer_url: https://issuer.example.com
  client_id: cid
  client_secret: secret
clients:
  - id: legacy
    address: legacy.internal
    enabled: false
  - id: app1
    address: app1.internal
`)
		cfg, err := LoadConfig(path)
		if err != nil {
			t.Fatalf("LoadConfig() error = %v", err)
		}
		var legacy *ClientConfig
		for i := range cfg.Clients {
			if cfg.Clients[i].ID == "legacy" {
				legacy = &cfg.Clients[i]
				break
			}
		}
		if legacy == nil {
			t.Fatal("legacy client missing from loaded config")
		}
		if legacy.Port != 8080 {
			t.Errorf("disabled client Port = %d, want 8080 (default)", legacy.Port)
		}
		if legacy.Prefix != "/" {
			t.Errorf("disabled client Prefix = %q, want %q (default)", legacy.Prefix, "/")
		}
	})
}