package main

import (
	"testing"

	xdstype "github.com/cncf/xds/go/xds/type/v3"
	golang "github.com/envoyproxy/go-control-plane/contrib/envoy/extensions/filters/http/golang/v3alpha"
	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	tls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	"github.com/envoyproxy/go-control-plane/pkg/wellknown"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestMakeRoutesWithDomains(t *testing.T) {
	config := &GatewayConfig{
		Clients: []ClientConfig{
			{
				ID:      "keycloak_service",
				Domain:  "idp.example.com",
				Address: "keycloak",
				Port:    8080,
				Prefix:  "/auth",
			},
			{
				ID:      "app_service",
				Domain:  "app.example.com",
				Address: "app",
				Port:    8080,
				Prefix:  "/",
			},
			{
				ID:      "wildcard_service",
				Domain:  "", // No domain specified, should use "*"
				Address: "wildcard",
				Port:    8080,
				Prefix:  "/api",
			},
		},
	}

	routes, err := MakeRoutes(config)
	if err != nil {
		t.Fatalf("MakeRoutes failed: %v", err)
	}

	if len(routes) != 1 {
		t.Fatalf("expected 1 route configuration, got %d", len(routes))
	}

	routeConfig := routes[0].(*route.RouteConfiguration)

	// Should have 3 virtual hosts (2 with domains + 1 wildcard)
	if len(routeConfig.VirtualHosts) != 3 {
		t.Fatalf("expected 3 virtual hosts, got %d", len(routeConfig.VirtualHosts))
	}

	// Check first virtual host (keycloak)
	vh1 := routeConfig.VirtualHosts[0]
	if vh1.Name != "idp_example_com_host" {
		t.Errorf("expected virtual host name 'idp_example_com_host', got %s", vh1.Name)
	}
	if len(vh1.Domains) != 1 || vh1.Domains[0] != "idp.example.com" {
		t.Errorf("expected domain 'idp.example.com', got %v", vh1.Domains)
	}
	if len(vh1.Routes) != 1 {
		t.Errorf("expected 1 route, got %d", len(vh1.Routes))
	}
	if vh1.Routes[0].GetRoute().GetCluster() != "keycloak_service" {
		t.Errorf("expected cluster 'keycloak_service', got %s", vh1.Routes[0].GetRoute().GetCluster())
	}
	// When domain is specified, host_rewrite_literal should use domain
	if vh1.Routes[0].GetRoute().GetHostRewriteLiteral() != "idp.example.com" {
		t.Errorf("expected host rewrite 'idp.example.com', got %s", vh1.Routes[0].GetRoute().GetHostRewriteLiteral())
	}

	// Check second virtual host (app)
	vh2 := routeConfig.VirtualHosts[1]
	if vh2.Name != "app_example_com_host" {
		t.Errorf("expected virtual host name 'app_example_com_host', got %s", vh2.Name)
	}
	if len(vh2.Domains) != 1 || vh2.Domains[0] != "app.example.com" {
		t.Errorf("expected domain 'app.example.com', got %v", vh2.Domains)
	}
	// Should also use domain for host rewrite
	if vh2.Routes[0].GetRoute().GetHostRewriteLiteral() != "app.example.com" {
		t.Errorf("expected host rewrite 'app.example.com', got %s", vh2.Routes[0].GetRoute().GetHostRewriteLiteral())
	}

	// Check third virtual host (wildcard - combined default_host)
	vh3 := routeConfig.VirtualHosts[2]
	if vh3.Name != "default_host" {
		t.Errorf("expected virtual host name 'default_host', got %s", vh3.Name)
	}
	if len(vh3.Domains) != 1 || vh3.Domains[0] != "*" {
		t.Errorf("expected wildcard domain '*', got %v", vh3.Domains)
	}
	// Should have the route from wildcard_service
	if len(vh3.Routes) != 1 {
		t.Errorf("expected 1 route in wildcard host, got %d", len(vh3.Routes))
	}
	// Without domain, host_rewrite_literal should use address
	if vh3.Routes[0].GetRoute().GetHostRewriteLiteral() != "wildcard" {
		t.Errorf("expected host rewrite 'wildcard' (address), got %s", vh3.Routes[0].GetRoute().GetHostRewriteLiteral())
	}
}

func TestMakeRoutesSkipsDisabledClients(t *testing.T) {
	config := &GatewayConfig{
		Clients: []ClientConfig{
			{
				// Default: Enabled is nil → treated as enabled.
				ID:      "enabled_default_service",
				Domain:  "enabled.example.com",
				Address: "enabled-backend",
				Port:    8080,
				Prefix:  "/",
			},
			{
				ID:      "disabled_service",
				Domain:  "disabled.example.com",
				Address: "disabled-backend",
				Port:    8080,
				Prefix:  "/",
				Enabled: boolPtr(false),
			},
			{
				ID:      "explicitly_enabled_service",
				Domain:  "explicit.example.com",
				Address: "explicit-backend",
				Port:    8080,
				Prefix:  "/",
				Enabled: boolPtr(true),
			},
		},
	}

	routes, err := MakeRoutes(config)
	if err != nil {
		t.Fatalf("MakeRoutes failed: %v", err)
	}

	if len(routes) != 1 {
		t.Fatalf("expected 1 route configuration, got %d", len(routes))
	}

	routeConfig := routes[0].(*route.RouteConfiguration)

	// Should have exactly 2 virtual hosts (the disabled client should be omitted).
	if len(routeConfig.VirtualHosts) != 2 {
		t.Fatalf("expected 2 virtual hosts, got %d", len(routeConfig.VirtualHosts))
	}

	for _, vh := range routeConfig.VirtualHosts {
		// No virtual host should be for the disabled domain.
		for _, d := range vh.Domains {
			if d == "disabled.example.com" {
				t.Errorf("disabled client domain %q must not appear in virtual hosts", d)
			}
		}
		// No route should target the disabled cluster.
		for _, r := range vh.Routes {
			if r.GetRoute().GetCluster() == "disabled_service" {
				t.Errorf("disabled cluster 'disabled_service' must not appear in routes")
			}
		}
	}

	// Sanity: ensure the enabled clusters do appear.
	wantClusters := map[string]bool{
		"enabled_default_service":    false,
		"explicitly_enabled_service": false,
	}
	for _, vh := range routeConfig.VirtualHosts {
		for _, r := range vh.Routes {
			cluster := r.GetRoute().GetCluster()
			if _, ok := wantClusters[cluster]; ok {
				wantClusters[cluster] = true
			}
		}
	}
	for cluster, found := range wantClusters {
		if !found {
			t.Errorf("expected cluster %q to be present in routes", cluster)
		}
	}
}

func TestMakeRoutesWithMultipleWildcards(t *testing.T) {
	// Test that multiple clients without domains are combined into one wildcard host
	config := &GatewayConfig{
		Clients: []ClientConfig{
			{
				ID:      "api_service",
				Domain:  "", // No domain
				Address: "api",
				Port:    8080,
				Prefix:  "/api",
			},
			{
				ID:      "web_service",
				Domain:  "", // No domain
				Address: "web",
				Port:    8080,
				Prefix:  "/",
			},
			{
				ID:      "specific_service",
				Domain:  "app.example.com",
				Address: "app",
				Port:    8080,
				Prefix:  "/",
			},
		},
	}

	routes, err := MakeRoutes(config)
	if err != nil {
		t.Fatalf("MakeRoutes failed: %v", err)
	}

	routeConfig := routes[0].(*route.RouteConfiguration)

	// Should have 2 virtual hosts: 1 for specific domain, 1 for wildcard
	if len(routeConfig.VirtualHosts) != 2 {
		t.Fatalf("expected 2 virtual hosts, got %d", len(routeConfig.VirtualHosts))
	}

	// Find the wildcard host
	var wildcardHost *route.VirtualHost
	for _, vh := range routeConfig.VirtualHosts {
		if vh.Name == "default_host" {
			wildcardHost = vh
			break
		}
	}

	if wildcardHost == nil {
		t.Fatal("wildcard host 'default_host' not found")
	}

	// Wildcard host should have both routes from clients without domains
	if len(wildcardHost.Routes) != 2 {
		t.Errorf("expected 2 routes in wildcard host, got %d", len(wildcardHost.Routes))
	}

	// Check route ordering (longer prefix first)
	if wildcardHost.Routes[0].GetMatch().GetPrefix() != "/api" {
		t.Errorf("expected first route prefix '/api', got %s", wildcardHost.Routes[0].GetMatch().GetPrefix())
	}
	if wildcardHost.Routes[1].GetMatch().GetPrefix() != "/" {
		t.Errorf("expected second route prefix '/', got %s", wildcardHost.Routes[1].GetMatch().GetPrefix())
	}
}

func TestMakeClustersSkipsDisabledClients(t *testing.T) {
	config := &GatewayConfig{
		Clients: []ClientConfig{
			{
				// Default: Enabled is nil → treated as enabled.
				ID:      "enabled_default_service",
				Domain:  "enabled.example.com",
				Address: "enabled-backend",
				Port:    8080,
				Prefix:  "/",
			},
			{
				ID:      "disabled_service",
				Domain:  "disabled.example.com",
				Address: "disabled-backend",
				Port:    8080,
				Prefix:  "/",
				Enabled: boolPtr(false),
			},
			{
				ID:      "explicitly_enabled_service",
				Domain:  "explicit.example.com",
				Address: "explicit-backend",
				Port:    8080,
				Prefix:  "/",
				Enabled: boolPtr(true),
			},
		},
	}

	clusters, err := MakeClusters(config)
	if err != nil {
		t.Fatalf("MakeClusters failed: %v", err)
	}

	// Should have exactly 2 cluster resources (the disabled client should be omitted).
	if len(clusters) != 2 {
		t.Fatalf("expected 2 cluster resources, got %d", len(clusters))
	}

	wantClusters := map[string]bool{
		"enabled_default_service":    false,
		"explicitly_enabled_service": false,
	}
	for _, res := range clusters {
		c, ok := res.(*cluster.Cluster)
		if !ok {
			t.Fatalf("expected *cluster.Cluster resource, got %T", res)
		}
		if c.Name == "disabled_service" {
			t.Errorf("disabled cluster 'disabled_service' must not appear in clusters")
		}
		if _, exists := wantClusters[c.Name]; exists {
			wantClusters[c.Name] = true
		}
	}
	for name, found := range wantClusters {
		if !found {
			t.Errorf("expected cluster %q to be present", name)
		}
	}
}

// extractClustersStruct walks the listener -> HCM -> golang filter -> typed
// struct -> "clusters" field and returns the per-client struct map.
func extractClustersStruct(t *testing.T, lst *listener.Listener) map[string]struct{} {
	t.Helper()

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

	keys := make(map[string]struct{}, len(clustersStruct.Fields))
	for k := range clustersStruct.Fields {
		keys[k] = struct{}{}
	}
	return keys
}

// TestMakeListenerSkipsDisabledClientsFromPluginConfig asserts that disabled
// clients do not appear in the per-cluster filter config map sent to the Go
// plugin.
func TestMakeListenerSkipsDisabledClientsFromPluginConfig(t *testing.T) {
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
				// Default Enabled is nil → enabled.
				ID:      "enabled_default_service",
				Address: "enabled-backend",
				Port:    8080,
				Prefix:  "/",
			},
			{
				ID:      "disabled_service",
				Address: "disabled-backend",
				Port:    8080,
				Prefix:  "/",
				Enabled: boolPtr(false),
			},
			{
				ID:      "explicitly_enabled_service",
				Address: "explicit-backend",
				Port:    8080,
				Prefix:  "/",
				Enabled: boolPtr(true),
			},
		},
	}

	listeners, err := MakeListener(cfg)
	if err != nil {
		t.Fatalf("MakeListener failed: %v", err)
	}
	if len(listeners) == 0 {
		t.Fatal("expected at least one listener")
	}
	lst, ok := listeners[0].(*listener.Listener)
	if !ok {
		t.Fatalf("listeners[0] is %T, want *listener.Listener", listeners[0])
	}

	keys := extractClustersStruct(t, lst)
	if _, leaked := keys["disabled_service"]; leaked {
		t.Errorf("disabled client must not appear in plugin clusters map; have keys %v", keys)
	}
	if _, ok := keys["enabled_default_service"]; !ok {
		t.Errorf("enabled_default_service missing from plugin clusters map; have keys %v", keys)
	}
	if _, ok := keys["explicitly_enabled_service"]; !ok {
		t.Errorf("explicitly_enabled_service missing from plugin clusters map; have keys %v", keys)
	}
	if len(keys) != 2 {
		t.Errorf("expected 2 entries in plugin clusters map, got %d (%v)", len(keys), keys)
	}
}

// TestMakeListenerSkipsDisabledClientsFromTLSDomains asserts that a disabled
// client with tls: true does not contribute to SDS certificate provisioning.
func TestMakeListenerSkipsDisabledClientsFromTLSDomains(t *testing.T) {
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
		Listener:        ListenerConfig{Address: "0.0.0.0", Port: 8080, TLSPort: 8443},
		SSL:             SSLConfig{Enabled: true},
		Clients: []ClientConfig{
			{
				ID:      "enabled_tls_service",
				Address: "enabled-backend",
				Port:    8080,
				Prefix:  "/",
				TLS:     true,
				Domain:  "enabled.example.com",
			},
			{
				ID:      "disabled_tls_service",
				Address: "disabled-backend",
				Port:    8080,
				Prefix:  "/",
				TLS:     true,
				Domain:  "disabled.example.com",
				Enabled: boolPtr(false),
			},
		},
	}

	listeners, err := MakeListener(cfg)
	if err != nil {
		t.Fatalf("MakeListener failed: %v", err)
	}

	// Locate the HTTPS listener (the one with TransportSocket configured).
	var httpsListener *listener.Listener
	for _, res := range listeners {
		l, ok := res.(*listener.Listener)
		if !ok {
			continue
		}
		if l.Name == HTTPSListenerName {
			httpsListener = l
			break
		}
	}
	if httpsListener == nil {
		t.Fatalf("HTTPS listener not found; got %d listener resources", len(listeners))
	}

	if len(httpsListener.FilterChains) == 0 {
		t.Fatal("HTTPS listener has no filter chains")
	}
	ts := httpsListener.FilterChains[0].GetTransportSocket()
	if ts == nil {
		t.Fatal("HTTPS filter chain has no TransportSocket configured")
	}

	var dtlsCtx tls.DownstreamTlsContext
	if err := ts.GetTypedConfig().UnmarshalTo(&dtlsCtx); err != nil {
		t.Fatalf("unmarshal DownstreamTlsContext: %v", err)
	}

	common := dtlsCtx.GetCommonTlsContext()
	if common == nil {
		t.Fatal("DownstreamTlsContext.CommonTlsContext is nil")
	}

	// Verify only the enabled client's secret is present.
	wantSecret := GetSecretName("enabled.example.com")
	disabledSecret := GetSecretName("disabled.example.com")

	sdsConfigs := common.GetTlsCertificateSdsSecretConfigs()
	if len(sdsConfigs) != 1 {
		t.Fatalf("expected 1 SDS secret config, got %d (%+v)", len(sdsConfigs), sdsConfigs)
	}
	if sdsConfigs[0].GetName() != wantSecret {
		t.Errorf("expected SDS secret name %q, got %q", wantSecret, sdsConfigs[0].GetName())
	}
	for _, sc := range sdsConfigs {
		if sc.GetName() == disabledSecret {
			t.Errorf("disabled client domain produced SDS secret %q (must be skipped)", disabledSecret)
		}
	}
}

// extractPluginTypedStruct decodes the HCM Any returned by createHTTPConnectionManager
// and returns the TypedStruct value embedded in the golang filter's plugin config.
func extractPluginTypedStruct(t *testing.T, managerAny *anypb.Any) *structpb.Struct {
	t.Helper()
	var manager hcm.HttpConnectionManager
	if err := managerAny.UnmarshalTo(&manager); err != nil {
		t.Fatalf("unmarshal HCM: %v", err)
	}
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
		t.Fatal("envoy.filters.http.golang filter not found")
	}
	var typed xdstype.TypedStruct
	if err := golangFilterCfg.PluginConfig.UnmarshalTo(&typed); err != nil {
		t.Fatalf("unmarshal TypedStruct: %v", err)
	}
	return typed.Value
}

// pluginStructFor builds a minimal GatewayConfig with the given providers ("kc" as
// default), runs createHTTPConnectionManager and returns the decoded plugin config.
func pluginStructFor(t *testing.T, providers map[string]ProviderConfig) *structpb.Struct {
	t.Helper()
	cfg := &GatewayConfig{
		Plugin:          PluginConfig{LibraryPath: "/app/filter.so"},
		DefaultProvider: "kc",
		Providers:       providers,
		Listener:        ListenerConfig{Address: "0.0.0.0", Port: 8080},
	}
	managerAny, err := createHTTPConnectionManager(cfg)
	if err != nil {
		t.Fatalf("createHTTPConnectionManager: %v", err)
	}
	return extractPluginTypedStruct(t, managerAny)
}

// TestProviderAllowedUsersSerialization verifies that ProviderConfig.AllowedUsers is
// lowercased and written into the plugin config under providers.<name>.allowed_users.
func TestProviderAllowedUsersSerialization(t *testing.T) {
	pluginStruct := pluginStructFor(t, map[string]ProviderConfig{
		"kc": {
			IssuerURL:    "https://issuer.example.com",
			ClientID:     "cid",
			ClientSecret: "secret",
			AllowedUsers: []string{"Alice", "BOB"},
		},
	})

	providersField, ok := pluginStruct.Fields["providers"]
	if !ok {
		t.Fatal("plugin config missing 'providers' field")
	}
	kcField, ok := providersField.GetStructValue().Fields["kc"]
	if !ok {
		t.Fatal("providers map missing 'kc' entry")
	}
	allowedField, ok := kcField.GetStructValue().Fields["allowed_users"]
	if !ok {
		t.Fatal("providers.kc missing 'allowed_users' field")
	}
	vals := allowedField.GetListValue().GetValues()
	if len(vals) != 2 {
		t.Fatalf("expected 2 allowed_users entries, got %d", len(vals))
	}
	want := []string{"alice", "bob"}
	for i, v := range vals {
		if v.GetStringValue() != want[i] {
			t.Errorf("allowed_users[%d]: got %q, want %q", i, v.GetStringValue(), want[i])
		}
	}
}

// TestProviderAllowedUsersOmittedWhenEmpty verifies that providers with no AllowedUsers
// do not emit an allowed_users key in the serialized plugin config.
func TestProviderAllowedUsersOmittedWhenEmpty(t *testing.T) {
	pluginStruct := pluginStructFor(t, map[string]ProviderConfig{
		"kc": {
			IssuerURL:    "https://issuer.example.com",
			ClientID:     "cid",
			ClientSecret: "secret",
			// AllowedUsers intentionally absent
		},
	})

	providersField, ok := pluginStruct.Fields["providers"]
	if !ok {
		t.Fatal("plugin config missing 'providers' field")
	}
	kcField, ok := providersField.GetStructValue().Fields["kc"]
	if !ok {
		t.Fatal("providers map missing 'kc' entry")
	}
	if _, present := kcField.GetStructValue().Fields["allowed_users"]; present {
		t.Error("providers.kc must not have 'allowed_users' key when AllowedUsers is empty")
	}
}

// TestPluginConfigOmitsSkipAuthHeaderName verifies that the plugin config no longer
// carries skip_auth_header_name: any client could send that header and bypass auth (issue #3).
func TestPluginConfigOmitsSkipAuthHeaderName(t *testing.T) {
	pluginStruct := pluginStructFor(t, map[string]ProviderConfig{
		"kc": {
			IssuerURL:    "https://issuer.example.com",
			ClientID:     "cid",
			ClientSecret: "secret",
		},
	})

	// Sanity check: the decoded struct is the real plugin config.
	if _, ok := pluginStruct.Fields["user_id_header_name"]; !ok {
		t.Fatal("plugin config missing 'user_id_header_name' field")
	}
	if v, present := pluginStruct.Fields["skip_auth_header_name"]; present {
		t.Errorf("plugin config must not have 'skip_auth_header_name' key, got %q", v.GetStringValue())
	}
}

// assertPathNormalization fails the test unless the HCM normalizes paths before
// the auth filter runs (issue #8).
func assertPathNormalization(t *testing.T, m *hcm.HttpConnectionManager) {
	t.Helper()
	if !m.GetNormalizePath().GetValue() {
		t.Error("normalize_path must be true")
	}
	if !m.GetMergeSlashes() {
		t.Error("merge_slashes must be true")
	}
	if got := m.GetPathWithEscapedSlashesAction(); got != hcm.HttpConnectionManager_UNESCAPE_AND_REDIRECT {
		t.Errorf("path_with_escaped_slashes_action = %v, want UNESCAPE_AND_REDIRECT", got)
	}
}

func TestHTTPConnectionManagerNormalizesPaths(t *testing.T) {
	cfg := &GatewayConfig{
		Plugin:          PluginConfig{LibraryPath: "/app/filter.so"},
		DefaultProvider: "kc",
		Providers:       map[string]ProviderConfig{"kc": {IssuerURL: "https://issuer.example.com", ClientID: "cid"}},
		Listener:        ListenerConfig{Address: "0.0.0.0", Port: 8080},
	}
	managerAny, err := createHTTPConnectionManager(cfg)
	if err != nil {
		t.Fatalf("createHTTPConnectionManager: %v", err)
	}
	var m hcm.HttpConnectionManager
	if err := managerAny.UnmarshalTo(&m); err != nil {
		t.Fatalf("unmarshal HCM: %v", err)
	}
	assertPathNormalization(t, &m)

	// A template HCM without these settings must not switch normalization off.
	templateAny, err := anypb.New(&hcm.HttpConnectionManager{StatPrefix: "template"})
	if err != nil {
		t.Fatalf("marshal template HCM: %v", err)
	}
	merged, err := mergeHttpConnectionManagers(
		&listener.Filter{Name: wellknown.HTTPConnectionManager, ConfigType: &listener.Filter_TypedConfig{TypedConfig: templateAny}},
		&listener.Filter{Name: wellknown.HTTPConnectionManager, ConfigType: &listener.Filter_TypedConfig{TypedConfig: managerAny}},
	)
	if err != nil {
		t.Fatalf("mergeHttpConnectionManagers: %v", err)
	}
	var mm hcm.HttpConnectionManager
	if err := merged.GetTypedConfig().UnmarshalTo(&mm); err != nil {
		t.Fatalf("unmarshal merged HCM: %v", err)
	}
	assertPathNormalization(t, &mm)
}
