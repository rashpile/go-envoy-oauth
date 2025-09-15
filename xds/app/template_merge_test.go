package main

import (
	"testing"

	listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	router "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/router/v3"
	golang "github.com/envoyproxy/go-control-plane/contrib/envoy/extensions/filters/http/golang/v3alpha"
	"github.com/envoyproxy/go-control-plane/pkg/cache/types"
	"google.golang.org/protobuf/types/known/anypb"
)

func TestMergeListenersWithSameName(t *testing.T) {
	// Create a template with listener_0
	template := &EnvoyTemplate{
		Listeners: []map[string]interface{}{
			{
				"name": ListenerName,
				"address": map[string]interface{}{
					"socket_address": map[string]interface{}{
						"address":    "0.0.0.0",
						"port_value": 8080,
					},
				},
				"filter_chains": []interface{}{
					map[string]interface{}{
						"filters": []interface{}{
							map[string]interface{}{
								"name": "envoy.filters.network.http_connection_manager",
								"typed_config": map[string]interface{}{
									"@type":       "type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager",
									"stat_prefix": "ingress_http",
									"http_filters": []interface{}{
										map[string]interface{}{
											"name": "envoy.filters.http.router",
											"typed_config": map[string]interface{}{
												"@type": "type.googleapis.com/envoy.extensions.filters.http.router.v3.Router",
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	// Create OAuth listener
	golangFilter := &golang.Config{
		LibraryId:  "gateway-auth",
		PluginName: "gateway-auth",
	}
	golangFilterAny, _ := anypb.New(golangFilter)
	routerFilter, _ := anypb.New(&router.Router{})

	manager := &hcm.HttpConnectionManager{
		StatPrefix: "ingress_http",
		HttpFilters: []*hcm.HttpFilter{
			{
				Name: "envoy.filters.http.golang",
				ConfigType: &hcm.HttpFilter_TypedConfig{
					TypedConfig: golangFilterAny,
				},
			},
			{
				Name: "envoy.filters.http.router",
				ConfigType: &hcm.HttpFilter_TypedConfig{
					TypedConfig: routerFilter,
				},
			},
		},
	}
	managerAny, _ := anypb.New(manager)

	authListener := &listener.Listener{
		Name: ListenerName,
		FilterChains: []*listener.FilterChain{
			{
				Filters: []*listener.Filter{
					{
						Name: "envoy.filters.network.http_connection_manager",
						ConfigType: &listener.Filter_TypedConfig{
							TypedConfig: managerAny,
						},
					},
				},
			},
		},
	}

	authListeners := []types.Resource{authListener}

	// Merge
	result, err := MergeTemplateListeners(template, authListeners)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should have only one listener (merged)
	if len(result) != 1 {
		t.Errorf("expected 1 listener, got %d", len(result))
	}

	// Check the merged listener has OAuth filter
	mergedListener := result[0].(*listener.Listener)
	if len(mergedListener.FilterChains) == 0 {
		t.Fatal("no filter chains in merged listener")
	}

	filter := mergedListener.FilterChains[0].Filters[0]
	if filter.Name != "envoy.filters.network.http_connection_manager" {
		t.Errorf("expected http_connection_manager, got %s", filter.Name)
	}

	// Unmarshal and check HTTP filters
	var mergedHcm hcm.HttpConnectionManager
	if err := filter.GetTypedConfig().UnmarshalTo(&mergedHcm); err != nil {
		t.Fatalf("failed to unmarshal HCM: %v", err)
	}

	// Should have 2 filters: golang (OAuth) inserted before router
	if len(mergedHcm.HttpFilters) != 2 {
		t.Errorf("expected 2 HTTP filters, got %d", len(mergedHcm.HttpFilters))
	}

	// Check filter order - OAuth should be inserted before router
	expectedOrder := []string{
		"envoy.filters.http.golang",
		"envoy.filters.http.router",
	}

	for i, expectedName := range expectedOrder {
		if i >= len(mergedHcm.HttpFilters) {
			t.Errorf("missing filter at index %d: %s", i, expectedName)
			continue
		}
		if mergedHcm.HttpFilters[i].Name != expectedName {
			t.Errorf("filter %d: expected %s, got %s", i, expectedName, mergedHcm.HttpFilters[i].Name)
		}
	}
}

func TestMergeListenersWithDifferentNames(t *testing.T) {
	// Template with a different listener name
	template := &EnvoyTemplate{
		Listeners: []map[string]interface{}{
			{
				"name": "admin_listener",
				"address": map[string]interface{}{
					"socket_address": map[string]interface{}{
						"address":    "0.0.0.0",
						"port_value": 9901,
					},
				},
			},
		},
	}

	authListener := &listener.Listener{
		Name: ListenerName,
	}
	authListeners := []types.Resource{authListener}

	// Merge
	result, err := MergeTemplateListeners(template, authListeners)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should have two listeners
	if len(result) != 2 {
		t.Errorf("expected 2 listeners, got %d", len(result))
	}

	// Check listener names
	foundAdmin := false
	foundAuth := false
	for _, res := range result {
		l := res.(*listener.Listener)
		if l.Name == "admin_listener" {
			foundAdmin = true
		}
		if l.Name == ListenerName {
			foundAuth = true
		}
	}

	if !foundAdmin {
		t.Error("admin_listener not found in result")
	}
	if !foundAuth {
		t.Error("auth listener not found in result")
	}
}