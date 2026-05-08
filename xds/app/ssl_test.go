package main

import (
	"sort"
	"testing"
)

// TestCollectDomainsFromSkipsDisabledClients verifies that disabled clients
// (enabled: false) are excluded from the domain list returned for ACME
// certificate acquisition. Without this skip, a disabled client with
// `tls: true` would still trigger Let's Encrypt challenges on YAML reload.
func TestCollectDomainsFromSkipsDisabledClients(t *testing.T) {
	cfg := &GatewayConfig{
		Clients: []ClientConfig{
			{
				ID:     "enabled_default",
				TLS:    true,
				Domain: "default-enabled.example.com",
				// Enabled left nil → treated as enabled.
			},
			{
				ID:      "enabled_explicit",
				TLS:     true,
				Domain:  "explicit-enabled.example.com",
				Enabled: boolPtr(true),
			},
			{
				ID:      "disabled_tls",
				TLS:     true,
				Domain:  "disabled.example.com",
				Enabled: boolPtr(false),
			},
			{
				ID:     "enabled_no_tls",
				TLS:    false,
				Domain: "no-tls.example.com",
			},
		},
	}

	got := collectDomainsFrom(cfg)
	sort.Strings(got)

	want := []string{
		"default-enabled.example.com",
		"explicit-enabled.example.com",
	}

	if len(got) != len(want) {
		t.Fatalf("collectDomainsFrom returned %d domains, want %d: got=%v want=%v",
			len(got), len(want), got, want)
	}
	for i, d := range want {
		if got[i] != d {
			t.Errorf("collectDomainsFrom[%d] = %q, want %q (full got=%v)", i, got[i], d, got)
		}
	}

	// Explicitly assert the disabled client's domain is absent.
	for _, d := range got {
		if d == "disabled.example.com" {
			t.Errorf("disabled client's domain %q must not be returned for ACME", d)
		}
	}
}

// TestCollectDomainsSkipsDisabledClients provides method-level coverage of the
// same skip behavior. The XDSServer method wraps collectDomainsFrom over
// s.config, which is exhaustively covered by TestCollectDomainsFromSkipsDisabledClients.
func TestCollectDomainsSkipsDisabledClients(t *testing.T) {
	s := &XDSServer{config: &GatewayConfig{Clients: []ClientConfig{
		{ID: "enabled_tls", TLS: true, Domain: "enabled.example.com"},
		{ID: "disabled_tls", TLS: true, Domain: "disabled.example.com", Enabled: boolPtr(false)},
	}}}
	if got := s.collectDomains(); len(got) != 1 || got[0] != "enabled.example.com" {
		t.Errorf("collectDomains() = %v, want [enabled.example.com]", got)
	}
}
