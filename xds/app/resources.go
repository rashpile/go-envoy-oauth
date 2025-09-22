package main

import (
	"fmt"

	xdstype "github.com/cncf/xds/go/xds/type/v3"
	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	endpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	golang "github.com/envoyproxy/go-control-plane/contrib/envoy/extensions/filters/http/golang/v3alpha"
	router "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/router/v3"
	tls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	"github.com/envoyproxy/go-control-plane/pkg/cache/types"
	"github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"github.com/envoyproxy/go-control-plane/pkg/wellknown"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	ListenerName = "listener_0"
	RouteConfig  = "local_route"
)

func MakeListener(config *GatewayConfig) ([]types.Resource, error) {
	// Create golang filter configuration
	pluginConfig := map[string]interface{}{
		"issuer_url":                config.OAuth.IssuerURL,
		"client_id":                 config.OAuth.ClientID,
		"client_secret":             config.OAuth.ClientSecret,
		"redirect_url":              config.OAuth.RedirectURL,
		"enable_api_key":            config.OAuth.EnableAPIKey,
		"enable_bearer_token":       config.OAuth.EnableBearerToken,
		"session_cookie_name":       "session",
		"session_max_age":           86400,
		"session_path":              "/",
		"session_domain":            "localhost",
		"session_secure":            false,
		"session_http_only":         true,
		"session_same_site":         "Lax",
		"cookie_config":             "HttpOnly; SameSite=Lax",
		"user_id_header_name":       "X-User-ID",
		"user_email_header_name":    "X-User-Email",
		"user_username_header_name": "X-User",
		"skip_auth_header_name":     "X-Skip-Auth",
	}

	// Add scopes if provided (convert []string to []interface{} for structpb)
	if len(config.OAuth.Scopes) > 0 {
		scopesInterface := make([]interface{}, len(config.OAuth.Scopes))
		for i, scope := range config.OAuth.Scopes {
			scopesInterface[i] = scope
		}
		pluginConfig["scopes"] = scopesInterface
	}

	// Add cluster-specific configurations
	clusters := make(map[string]interface{})
	for _, client := range config.Clients {
		clientConfig := make(map[string]interface{})
		if client.Exclude {
			clientConfig["exclude"] = true
		}
		if len(client.ExcludePaths) > 0 {
			// Convert []string to []interface{} for structpb
			excludePathsInterface := make([]interface{}, len(client.ExcludePaths))
			for i, path := range client.ExcludePaths {
				excludePathsInterface[i] = path
			}
			clientConfig["exclude_paths"] = excludePathsInterface
		}
		if len(clientConfig) > 0 {
			clusters[client.ID] = clientConfig
		}
	}
	if len(clusters) > 0 {
		pluginConfig["clusters"] = clusters
	}

	pluginConfigStruct, err := structpb.NewStruct(pluginConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create plugin config struct: %w", err)
	}

	// Create a proper TypedStruct with the config
	typedStruct := &xdstype.TypedStruct{
		Value: pluginConfigStruct,
	}

	// Wrap in Any
	pluginConfigAny, err := anypb.New(typedStruct)
	if err != nil {
		return nil, fmt.Errorf("failed to create plugin config any: %w", err)
	}

	golangFilter := &golang.Config{
		LibraryId:    "gateway-auth",
		LibraryPath:  config.Plugin.LibraryPath,
		PluginName:   "gateway-auth",
		PluginConfig: pluginConfigAny,
	}

	golangFilterAny, err := anypb.New(golangFilter)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal golang filter: %w", err)
	}

	// Create router filter
	routerFilter, err := anypb.New(&router.Router{})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal router filter: %w", err)
	}

	// Create HTTP connection manager
	manager := &hcm.HttpConnectionManager{
		StatPrefix: "ingress_http",
		RouteSpecifier: &hcm.HttpConnectionManager_Rds{
			Rds: &hcm.Rds{
				RouteConfigName: RouteConfig,
				ConfigSource: &core.ConfigSource{
					ResourceApiVersion: resource.DefaultAPIVersion,
					ConfigSourceSpecifier: &core.ConfigSource_Ads{
						Ads: &core.AggregatedConfigSource{},
					},
				},
			},
		},
		HttpFilters: []*hcm.HttpFilter{
			{
				Name: "envoy.filters.http.golang",
				ConfigType: &hcm.HttpFilter_TypedConfig{
					TypedConfig: golangFilterAny,
				},
			},
			{
				Name: wellknown.Router,
				ConfigType: &hcm.HttpFilter_TypedConfig{
					TypedConfig: routerFilter,
				},
			},
		},
	}

	managerAny, err := anypb.New(manager)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal HTTP connection manager: %w", err)
	}

	// Create listener
	l := &listener.Listener{
		Name: ListenerName,
		Address: &core.Address{
			Address: &core.Address_SocketAddress{
				SocketAddress: &core.SocketAddress{
					Address: "0.0.0.0",
					PortSpecifier: &core.SocketAddress_PortValue{
						PortValue: 8080,
					},
				},
			},
		},
		FilterChains: []*listener.FilterChain{
			{
				Filters: []*listener.Filter{
					{
						Name: wellknown.HTTPConnectionManager,
						ConfigType: &listener.Filter_TypedConfig{
							TypedConfig: managerAny,
						},
					},
				},
			},
		},
	}

	return []types.Resource{l}, nil
}

func MakeRoutes(config *GatewayConfig) ([]types.Resource, error) {
	var virtualHosts []*route.VirtualHost
	var wildcardRoutes []*route.Route

	for _, client := range config.Clients {
		// Determine host rewrite value
		// If domain is specified, use domain; otherwise use address
		hostRewrite := client.Address
		if client.Domain != "" {
			hostRewrite = client.Domain
		}

		// Create route for this client
		r := &route.Route{
			Match: &route.RouteMatch{
				PathSpecifier: &route.RouteMatch_Prefix{
					Prefix: client.Prefix,
				},
			},
			Action: &route.Route_Route{
				Route: &route.RouteAction{
					ClusterSpecifier: &route.RouteAction_Cluster{
						Cluster: client.ID,
					},
					HostRewriteSpecifier: &route.RouteAction_HostRewriteLiteral{
						HostRewriteLiteral: hostRewrite,
					},
				},
			},
		}

		if client.Domain != "" {
			// Create individual virtual host for clients with specific domains
			vh := &route.VirtualHost{
				Name:    client.ID + "_host",
				Domains: []string{client.Domain},
				Routes:  []*route.Route{r},
			}
			virtualHosts = append(virtualHosts, vh)
		} else {
			// Collect routes for wildcard virtual host
			wildcardRoutes = append(wildcardRoutes, r)
		}
	}

	// Add wildcard virtual host if there are any routes without specific domains
	if len(wildcardRoutes) > 0 {
		// Sort routes by prefix length (longest first) for proper matching
		sortRoutesByPrefix(wildcardRoutes)

		vh := &route.VirtualHost{
			Name:    "default_host",
			Domains: []string{"*"},
			Routes:  wildcardRoutes,
		}
		virtualHosts = append(virtualHosts, vh)
	}

	routeConfig := &route.RouteConfiguration{
		Name:         RouteConfig,
		VirtualHosts: virtualHosts,
	}

	return []types.Resource{routeConfig}, nil
}

func MakeClusters(config *GatewayConfig) ([]types.Resource, error) {
	var clusters []types.Resource

	for _, client := range config.Clients {
		c := &cluster.Cluster{
			Name:                 client.ID,
			ClusterDiscoveryType: &cluster.Cluster_Type{Type: cluster.Cluster_STRICT_DNS},
			DnsLookupFamily:      cluster.Cluster_V4_ONLY,
			LbPolicy:             cluster.Cluster_ROUND_ROBIN,
			LoadAssignment: &endpoint.ClusterLoadAssignment{
				ClusterName: client.ID,
				Endpoints: []*endpoint.LocalityLbEndpoints{
					{
						LbEndpoints: []*endpoint.LbEndpoint{
							{
								HostIdentifier: &endpoint.LbEndpoint_Endpoint{
									Endpoint: &endpoint.Endpoint{
										Address: &core.Address{
											Address: &core.Address_SocketAddress{
												SocketAddress: &core.SocketAddress{
													Address: client.Address,
													PortSpecifier: &core.SocketAddress_PortValue{
														PortValue: client.Port,
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
			},
		}

		// Add TLS if SSL is enabled
		if client.SSL {
			tlsContext := &tls.UpstreamTlsContext{
				Sni: client.Address,
			}
			tlsAny, err := anypb.New(tlsContext)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal TLS context: %w", err)
			}
			c.TransportSocket = &core.TransportSocket{
				Name: "envoy.transport_sockets.tls",
				ConfigType: &core.TransportSocket_TypedConfig{
					TypedConfig: tlsAny,
				},
			}
		}

		clusters = append(clusters, c)
	}

	return clusters, nil
}

// sortRoutesByPrefix sorts routes by prefix length (longest first)
// This ensures more specific routes are matched before general ones
func sortRoutesByPrefix(routes []*route.Route) {
	for i := 0; i < len(routes)-1; i++ {
		for j := i + 1; j < len(routes); j++ {
			prefixI := routes[i].GetMatch().GetPrefix()
			prefixJ := routes[j].GetMatch().GetPrefix()
			if len(prefixJ) > len(prefixI) {
				routes[i], routes[j] = routes[j], routes[i]
			}
		}
	}
}

func MakeEndpoints(config *GatewayConfig) ([]types.Resource, error) {
	// Endpoints are included in the cluster LoadAssignment above
	// Return empty for now as we're using static endpoints
	return []types.Resource{}, nil
}