package main

import (
	"os"
	"testing"

	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	"github.com/envoyproxy/go-control-plane/pkg/cache/types"
)

func TestLoadTemplate(t *testing.T) {
	tests := []struct {
		name        string
		path        string
		expectNil   bool
		expectError bool
	}{
		{
			name:        "empty path returns nil",
			path:        "",
			expectNil:   true,
			expectError: false,
		},
		{
			name:        "non-existent file returns nil",
			path:        "/non/existent/file.yaml",
			expectNil:   true,
			expectError: false,
		},
		{
			name:        "valid template loads successfully",
			path:        "../example-template.yaml",
			expectNil:   false,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			template, err := LoadTemplate(tt.path)

			if tt.expectError && err == nil {
				t.Errorf("expected error but got nil")
			}
			if !tt.expectError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if tt.expectNil && template != nil {
				t.Errorf("expected nil template but got %v", template)
			}
			if !tt.expectNil && template == nil {
				t.Errorf("expected template but got nil")
			}
		})
	}
}

func TestMergeTemplateListeners(t *testing.T) {
	// Create a test template
	template := &EnvoyTemplate{
		Listeners: []map[string]interface{}{
			{
				"name": "test_listener",
				"address": map[string]interface{}{
					"socket_address": map[string]interface{}{
						"address":    "0.0.0.0",
						"port_value": 9999,
					},
				},
			},
		},
	}

	// Create auth listeners
	authListener := &listener.Listener{
		Name: HTTPListenerName,
	}
	authListeners := []types.Resource{authListener}

	// Merge
	result, err := MergeTemplateListeners(template, authListeners)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Check result contains both listeners
	if len(result) != 2 {
		t.Errorf("expected 2 listeners, got %d", len(result))
	}
}

func TestMergeTemplateClusters(t *testing.T) {
	// Create a test template
	template := &EnvoyTemplate{
		Clusters: []map[string]interface{}{
			{
				"name": "test_cluster",
				"type": "STATIC",
			},
		},
	}

	// Create auth clusters
	authCluster := &cluster.Cluster{
		Name: "auth_cluster",
	}
	authClusters := []types.Resource{authCluster}

	// Merge
	result, err := MergeTemplateClusters(template, authClusters)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Check result contains both clusters
	if len(result) != 2 {
		t.Errorf("expected 2 clusters, got %d", len(result))
	}
}

func TestTemplateIntegration(t *testing.T) {
	// Create a test config file
	configContent := `
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
	configFile, err := os.CreateTemp("", "config-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(configFile.Name())

	if _, err := configFile.Write([]byte(configContent)); err != nil {
		t.Fatal(err)
	}
	configFile.Close()

	// Create a test template file
	templateContent := `
clusters:
  - name: extra_cluster
    connect_timeout: 0.25s
    type: STATIC
    lb_policy: ROUND_ROBIN
    load_assignment:
      cluster_name: extra_cluster
      endpoints:
        - lb_endpoints:
            - endpoint:
                address:
                  socket_address:
                    address: 127.0.0.1
                    port_value: 1234
`
	templateFile, err := os.CreateTemp("", "template-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(templateFile.Name())

	if _, err := templateFile.Write([]byte(templateContent)); err != nil {
		t.Fatal(err)
	}
	templateFile.Close()

	// Create server with template
	server, err := NewXDSServer(configFile.Name(), templateFile.Name())
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	// Check that template was loaded
	if server.template == nil {
		t.Error("expected template to be loaded")
	}

	// Check snapshot creation
	if err := server.updateSnapshot(); err != nil {
		t.Fatalf("failed to update snapshot: %v", err)
	}
}