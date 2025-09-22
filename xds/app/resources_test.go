package main

import (
	"testing"

	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
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
	if vh1.Name != "keycloak_service_host" {
		t.Errorf("expected virtual host name 'keycloak_service_host', got %s", vh1.Name)
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
	if vh2.Name != "app_service_host" {
		t.Errorf("expected virtual host name 'app_service_host', got %s", vh2.Name)
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