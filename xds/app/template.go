package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/envoyproxy/go-control-plane/pkg/cache/types"
	"github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	endpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"gopkg.in/yaml.v3"

	// Import all common Envoy types to register them with protojson
	// HTTP Filters
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/adaptive_concurrency/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/admission_control/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/aws_lambda/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/aws_request_signing/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/bandwidth_limit/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/buffer/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/cache/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/cdn_loop/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/composite/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/compressor/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/cors/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/csrf/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/decompressor/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/dynamic_forward_proxy/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_authz/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/fault/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/file_system_buffer/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/gcp_authn/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/grpc_http1_bridge/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/grpc_http1_reverse_bridge/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/grpc_json_transcoder/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/grpc_stats/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/grpc_web/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/gzip/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/header_mutation/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/header_to_metadata/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/health_check/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ip_tagging/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/json_to_metadata/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/jwt_authn/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/kill_request/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/local_ratelimit/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/lua/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/oauth2/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/on_demand/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/original_src/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/rate_limit_quota/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ratelimit/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/rbac/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/router/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/set_metadata/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/stateful_session/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/tap/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/wasm/v3"

	// Network Filters
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/connection_limit/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/direct_response/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/echo/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/ext_authz/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/local_ratelimit/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/mongo_proxy/v3"
	// mysql_proxy and postgres_proxy not available in current version
	// _ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/mysql_proxy/v3"
	// _ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/postgres_proxy/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/ratelimit/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/rbac/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/redis_proxy/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/sni_cluster/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/sni_dynamic_forward_proxy/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/tcp_proxy/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/thrift_proxy/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/wasm/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/zookeeper_proxy/v3"

	// Access Loggers
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/access_loggers/file/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/access_loggers/grpc/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/access_loggers/open_telemetry/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/access_loggers/stream/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/access_loggers/wasm/v3"

	// Transport Sockets
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/alts/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/http_11_proxy/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/proxy_protocol/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/quic/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/raw_buffer/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/starttls/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tap/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tcp_stats/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"

	// Upstreams
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/upstreams/http/generic/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/upstreams/http/http/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/upstreams/http/tcp/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/upstreams/tcp/generic/v3"

	// Compression
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/compression/brotli/compressor/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/compression/brotli/decompressor/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/compression/gzip/compressor/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/compression/gzip/decompressor/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/compression/zstd/compressor/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/compression/zstd/decompressor/v3"
)

type EnvoyTemplate struct {
	Listeners []map[string]interface{} `yaml:"listeners,omitempty"`
	Clusters  []map[string]interface{} `yaml:"clusters,omitempty"`
	Routes    []map[string]interface{} `yaml:"routes,omitempty"`
	Endpoints []map[string]interface{} `yaml:"endpoints,omitempty"`
}

func LoadTemplate(path string) (*EnvoyTemplate, error) {
	if path == "" {
		return nil, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read template file: %w", err)
	}

	var template EnvoyTemplate
	if err := yaml.Unmarshal(data, &template); err != nil {
		return nil, fmt.Errorf("failed to parse template: %w", err)
	}

	return &template, nil
}

func convertToProto(data map[string]interface{}, msg proto.Message) error {
	// Convert YAML data to JSON for protobuf unmarshaling
	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal to JSON: %w", err)
	}

	if err := protojson.Unmarshal(jsonData, msg); err != nil {
		return fmt.Errorf("failed to unmarshal to proto: %w", err)
	}

	return nil
}

func MergeTemplateListeners(template *EnvoyTemplate, authListeners []types.Resource) ([]types.Resource, error) {
	if template == nil || len(template.Listeners) == 0 {
		return authListeners, nil
	}

	result := make([]types.Resource, 0, len(template.Listeners)+len(authListeners))

	// Map to store template listeners by name for merging
	templateListeners := make(map[string]*listener.Listener)
	var otherTemplateListeners []*listener.Listener

	// First pass: parse and categorize template listeners
	for _, listenerData := range template.Listeners {
		l := &listener.Listener{}
		if err := convertToProto(listenerData, l); err != nil {
			return nil, fmt.Errorf("failed to parse template listener: %w", err)
		}

		// Check if this is a mergeable listener (http_listener or https_listener)
		if l.Name == HTTPListenerName || l.Name == HTTPSListenerName {
			templateListeners[l.Name] = l
		} else {
			otherTemplateListeners = append(otherTemplateListeners, l)
		}
	}

	// Second pass: merge or add auth listeners
	for _, authRes := range authListeners {
		authListener, ok := authRes.(*listener.Listener)
		if !ok {
			result = append(result, authRes)
			continue
		}

		// Try to find matching template listener for merging
		var templateListener *listener.Listener

		// Direct name match (http_listener or https_listener)
		if tmpl, exists := templateListeners[authListener.Name]; exists {
			templateListener = tmpl
			delete(templateListeners, authListener.Name) // Mark as used
		}

		// If we found a template to merge with, do the merge
		if templateListener != nil {
			merged, err := mergeListeners(templateListener, authListener)
			if err != nil {
				return nil, fmt.Errorf("failed to merge listeners: %w", err)
			}
			result = append(result, merged)
		} else {
			// No template to merge, add auth listener as-is
			result = append(result, authListener)
		}
	}

	// Add any remaining template listeners that weren't merged
	for _, tmpl := range templateListeners {
		result = append(result, tmpl)
	}

	// Add other template listeners (non-mergeable names)
	for _, tmpl := range otherTemplateListeners {
		result = append(result, tmpl)
	}

	return result, nil
}

func MergeTemplateClusters(template *EnvoyTemplate, authClusters []types.Resource) ([]types.Resource, error) {
	if template == nil || len(template.Clusters) == 0 {
		return authClusters, nil
	}

	authClusterNames := make(map[string]bool)
	for _, res := range authClusters {
		if c, ok := res.(*cluster.Cluster); ok {
			authClusterNames[c.Name] = true
		}
	}

	result := make([]types.Resource, 0, len(template.Clusters)+len(authClusters))

	for _, clusterData := range template.Clusters {
		c := &cluster.Cluster{}
		if err := convertToProto(clusterData, c); err != nil {
			return nil, fmt.Errorf("failed to parse template cluster: %w", err)
		}

		if !authClusterNames[c.Name] {
			result = append(result, c)
		}
	}

	result = append(result, authClusters...)

	return result, nil
}

func MergeTemplateRoutes(template *EnvoyTemplate, authRoutes []types.Resource) ([]types.Resource, error) {
	if template == nil || len(template.Routes) == 0 {
		return authRoutes, nil
	}

	if len(authRoutes) > 0 {
		if authRoute, ok := authRoutes[0].(*route.RouteConfiguration); ok {
			for _, routeData := range template.Routes {
				r := &route.RouteConfiguration{}
				if err := convertToProto(routeData, r); err != nil {
					return nil, fmt.Errorf("failed to parse template route: %w", err)
				}

				if r.Name == RouteConfig && len(r.VirtualHosts) > 0 {
					for _, vh := range r.VirtualHosts {
						if vh.Name != "local_service" {
							authRoute.VirtualHosts = append(authRoute.VirtualHosts, vh)
						}
					}
				} else if r.Name != RouteConfig {
					authRoutes = append(authRoutes, r)
				}
			}
		}
	}

	return authRoutes, nil
}

func MergeTemplateEndpoints(template *EnvoyTemplate, authEndpoints []types.Resource) ([]types.Resource, error) {
	if template == nil || len(template.Endpoints) == 0 {
		return authEndpoints, nil
	}

	result := make([]types.Resource, 0, len(template.Endpoints)+len(authEndpoints))

	for _, endpointData := range template.Endpoints {
		e := &endpoint.ClusterLoadAssignment{}
		if err := convertToProto(endpointData, e); err != nil {
			return nil, fmt.Errorf("failed to parse template endpoint: %w", err)
		}
		result = append(result, e)
	}

	result = append(result, authEndpoints...)

	return result, nil
}

func mergeListeners(templateListener, authListener *listener.Listener) (*listener.Listener, error) {
	// Start with the template listener as base
	merged := proto.Clone(templateListener).(*listener.Listener)

	// If template has no filter chains, use auth listener's filter chains
	if len(merged.FilterChains) == 0 {
		merged.FilterChains = authListener.FilterChains
		return merged, nil
	}

	// Find and merge HTTP connection manager filters
	for i, fc := range merged.FilterChains {
		for j, filter := range fc.Filters {
			if filter.Name == "envoy.filters.network.http_connection_manager" {
				// Get the auth listener's HTTP connection manager
				if len(authListener.FilterChains) > 0 && len(authListener.FilterChains[0].Filters) > 0 {
					authFilter := authListener.FilterChains[0].Filters[0]
					if authFilter.Name == "envoy.filters.network.http_connection_manager" {
						// Merge HTTP filters
						mergedFilter, err := mergeHttpConnectionManagers(filter, authFilter)
						if err != nil {
							return nil, err
						}
						merged.FilterChains[i].Filters[j] = mergedFilter
					}
				}
			}
		}
	}

	// Add any additional filter chains from auth listener that don't exist in template
	if len(authListener.FilterChains) > 1 {
		merged.FilterChains = append(merged.FilterChains, authListener.FilterChains[1:]...)
	}

	return merged, nil
}

func mergeHttpConnectionManagers(templateFilter, authFilter *listener.Filter) (*listener.Filter, error) {
	// Extract HTTP connection managers from both filters
	var templateHcm, authHcm hcm.HttpConnectionManager

	if templateFilter.GetTypedConfig() != nil {
		if err := templateFilter.GetTypedConfig().UnmarshalTo(&templateHcm); err != nil {
			return nil, fmt.Errorf("failed to unmarshal template HCM: %w", err)
		}
	}

	if authFilter.GetTypedConfig() != nil {
		if err := authFilter.GetTypedConfig().UnmarshalTo(&authHcm); err != nil {
			return nil, fmt.Errorf("failed to unmarshal auth HCM: %w", err)
		}
	}

	// Find the OAuth filter in auth HCM
	var oauthFilter *hcm.HttpFilter
	for _, filter := range authHcm.HttpFilters {
		if filter.Name == "envoy.filters.http.golang" {
			oauthFilter = filter
			break
		}
	}

	if oauthFilter == nil {
		// No OAuth filter found, return template as-is
		return templateFilter, nil
	}

	// Find the router filter from auth HCM (it should always have one)
	var routerFilter *hcm.HttpFilter
	for _, filter := range authHcm.HttpFilters {
		if filter.Name == "envoy.filters.http.router" || filter.Name == "envoy.router" {
			routerFilter = filter
			break
		}
	}

	// Build new filter chain
	var newFilters []*hcm.HttpFilter
	hasRouter := false

	// Add all non-router filters from template
	for _, filter := range templateHcm.HttpFilters {
		if filter.Name == "envoy.filters.http.router" || filter.Name == "envoy.router" {
			hasRouter = true
			continue // Skip router for now, we'll add it at the end
		}
		newFilters = append(newFilters, filter)
	}

	// Add OAuth filter
	newFilters = append(newFilters, oauthFilter)

	// Always add router filter at the end
	if hasRouter && routerFilter != nil {
		// Use the router from template if it had one
		for _, filter := range templateHcm.HttpFilters {
			if filter.Name == "envoy.filters.http.router" || filter.Name == "envoy.router" {
				newFilters = append(newFilters, filter)
				break
			}
		}
	} else if routerFilter != nil {
		// Use router from auth config
		newFilters = append(newFilters, routerFilter)
	}

	templateHcm.HttpFilters = newFilters

	// Use auth HCM's route config if template doesn't have one
	if templateHcm.GetRds() == nil && authHcm.GetRds() != nil {
		templateHcm.RouteSpecifier = authHcm.RouteSpecifier
	}

	// Marshal back to Any
	mergedAny, err := anypb.New(&templateHcm)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal merged HCM: %w", err)
	}

	return &listener.Filter{
		Name: templateFilter.Name,
		ConfigType: &listener.Filter_TypedConfig{
			TypedConfig: mergedAny,
		},
	}, nil
}

func ApplyTemplate(template *EnvoyTemplate, listeners, routes, clusters, endpoints []types.Resource) (map[resource.Type][]types.Resource, error) {
	mergedListeners, err := MergeTemplateListeners(template, listeners)
	if err != nil {
		return nil, fmt.Errorf("failed to merge listeners: %w", err)
	}

	mergedRoutes, err := MergeTemplateRoutes(template, routes)
	if err != nil {
		return nil, fmt.Errorf("failed to merge routes: %w", err)
	}

	mergedClusters, err := MergeTemplateClusters(template, clusters)
	if err != nil {
		return nil, fmt.Errorf("failed to merge clusters: %w", err)
	}

	mergedEndpoints, err := MergeTemplateEndpoints(template, endpoints)
	if err != nil {
		return nil, fmt.Errorf("failed to merge endpoints: %w", err)
	}

	return map[resource.Type][]types.Resource{
		resource.ListenerType: mergedListeners,
		resource.RouteType:    mergedRoutes,
		resource.ClusterType:  mergedClusters,
		resource.EndpointType: mergedEndpoints,
	}, nil
}