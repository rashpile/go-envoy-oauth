package main

import (
	"os"
	"testing"

	listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
)

func TestListenerConfigDefaults(t *testing.T) {
	configData := `
plugin:
  library_path: /test/plugin.so
oauth:
  issuer_url: https://auth.example.com
  client_id: test-client
  client_secret: test-secret
clients:
  - id: test_service
    address: test.example.com
    port: 8080
`
	// Create temp config file
	configFile, err := os.CreateTemp("", "config-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(configFile.Name())

	if _, err := configFile.Write([]byte(configData)); err != nil {
		t.Fatal(err)
	}
	configFile.Close()

	config, err := LoadConfig(configFile.Name())
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	// Check defaults
	if config.Listener.Address != "0.0.0.0" {
		t.Errorf("expected default listener address '0.0.0.0', got %s", config.Listener.Address)
	}
	if config.Listener.Port != 8080 {
		t.Errorf("expected default listener port 8080, got %d", config.Listener.Port)
	}
}

func TestListenerConfigEnvironmentOverrides(t *testing.T) {
	// Set environment variables
	os.Setenv("LISTENER_ADDRESS", "127.0.0.1")
	os.Setenv("LISTENER_PORT", "9090")
	defer os.Unsetenv("LISTENER_ADDRESS")
	defer os.Unsetenv("LISTENER_PORT")

	configData := `
plugin:
  library_path: /test/plugin.so
oauth:
  issuer_url: https://auth.example.com
  client_id: test-client
  client_secret: test-secret
clients:
  - id: test_service
    address: test.example.com
    port: 8080
`
	// Create temp config file
	configFile, err := os.CreateTemp("", "config-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(configFile.Name())

	if _, err := configFile.Write([]byte(configData)); err != nil {
		t.Fatal(err)
	}
	configFile.Close()

	config, err := LoadConfig(configFile.Name())
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	// Check environment overrides
	if config.Listener.Address != "127.0.0.1" {
		t.Errorf("expected listener address '127.0.0.1' from env, got %s", config.Listener.Address)
	}
	if config.Listener.Port != 9090 {
		t.Errorf("expected listener port 9090 from env, got %d", config.Listener.Port)
	}
}

func TestListenerConfigYamlOverrides(t *testing.T) {
	configData := `
listener:
  address: 192.168.1.1
  port: 8888
plugin:
  library_path: /test/plugin.so
oauth:
  issuer_url: https://auth.example.com
  client_id: test-client
  client_secret: test-secret
clients:
  - id: test_service
    address: test.example.com
    port: 8080
`
	// Create temp config file
	configFile, err := os.CreateTemp("", "config-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(configFile.Name())

	if _, err := configFile.Write([]byte(configData)); err != nil {
		t.Fatal(err)
	}
	configFile.Close()

	config, err := LoadConfig(configFile.Name())
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	// Check YAML overrides
	if config.Listener.Address != "192.168.1.1" {
		t.Errorf("expected listener address '192.168.1.1' from yaml, got %s", config.Listener.Address)
	}
	if config.Listener.Port != 8888 {
		t.Errorf("expected listener port 8888 from yaml, got %d", config.Listener.Port)
	}
}

func TestMakeListenerUsesConfig(t *testing.T) {
	config := &GatewayConfig{
		Plugin: PluginConfig{
			LibraryPath: "/test/plugin.so",
		},
		OAuth: OAuthConfig{
			IssuerURL:    "https://auth.example.com",
			ClientID:     "test-client",
			ClientSecret: "test-secret",
		},
		Listener: ListenerConfig{
			Address: "10.0.0.1",
			Port:    9999,
		},
		Clients: []ClientConfig{
			{
				ID:      "test_service",
				Address: "test.example.com",
				Port:    8080,
			},
		},
	}

	listeners, err := MakeListener(config)
	if err != nil {
		t.Fatalf("MakeListener failed: %v", err)
	}

	if len(listeners) != 1 {
		t.Fatalf("expected 1 listener, got %d", len(listeners))
	}

	l := listeners[0].(*listener.Listener)
	socketAddr := l.GetAddress().GetSocketAddress()

	if socketAddr.GetAddress() != "10.0.0.1" {
		t.Errorf("expected listener address '10.0.0.1', got %s", socketAddr.GetAddress())
	}
	if socketAddr.GetPortValue() != 9999 {
		t.Errorf("expected listener port 9999, got %d", socketAddr.GetPortValue())
	}
}