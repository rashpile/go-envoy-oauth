package filter

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"testing"

	xds "github.com/cncf/xds/go/xds/type/v3"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"
)

// buildAny creates an anypb.Any from a map[string]interface{} suitable for Parse().
func buildAny(t *testing.T, m map[string]interface{}) *anypb.Any {
	t.Helper()
	s, err := structpb.NewStruct(m)
	if err != nil {
		t.Fatalf("structpb.NewStruct failed: %v", err)
	}
	ts := &xds.TypedStruct{Value: s}
	a, err := anypb.New(ts)
	if err != nil {
		t.Fatalf("anypb.New failed: %v", err)
	}
	return a
}

// baseConfig returns the minimum valid config map (legacy format).
func baseConfig() map[string]interface{} {
	return map[string]interface{}{
		"issuer_url":    "https://keycloak.example.com/realms/test",
		"client_id":     "my-client",
		"client_secret": "secret",
		"redirect_url":  "/oauth/callback",
	}
}

// TestParseProviders verifies that parseRawConfig() correctly reads a providers map
// containing two named providers and sets conf.Providers and conf.DefaultProvider.
// Uses parseRawConfig (not Parse) to skip OIDC discovery — struct population only.
func TestParseProviders(t *testing.T) {
	cfg := baseConfig()
	cfg["providers"] = map[string]interface{}{
		"keycloak": map[string]interface{}{
			"issuer_url":    "https://keycloak.example.com",
			"client_id":     "kc-client",
			"client_secret": "kc-secret",
			"redirect_url":  "https://app.example.com/callback",
			"scopes":        []interface{}{"openid", "profile"},
		},
		"google": map[string]interface{}{
			"issuer_url":    "https://accounts.google.com",
			"client_id":     "google-client",
			"client_secret": "google-secret",
		},
	}
	cfg["default_provider"] = "keycloak"

	p := &Parser{}
	conf, err := p.parseRawConfig(buildAny(t, cfg))
	if err != nil {
		t.Fatalf("parseRawConfig() error: %v", err)
	}

	if len(conf.Providers) != 2 {
		t.Errorf("expected 2 providers, got %d", len(conf.Providers))
	}

	kc, ok := conf.Providers["keycloak"]
	if !ok {
		t.Fatal("expected keycloak provider in conf.Providers")
	}
	if kc.IssuerURL != "https://keycloak.example.com" {
		t.Errorf("keycloak IssuerURL: got %q, want %q", kc.IssuerURL, "https://keycloak.example.com")
	}
	if kc.ClientID != "kc-client" {
		t.Errorf("keycloak ClientID: got %q, want %q", kc.ClientID, "kc-client")
	}
	if kc.ClientSecret != "kc-secret" {
		t.Errorf("keycloak ClientSecret: got %q, want %q", kc.ClientSecret, "kc-secret")
	}
	if kc.RedirectURL != "https://app.example.com/callback" {
		t.Errorf("keycloak RedirectURL: got %q, want %q", kc.RedirectURL, "https://app.example.com/callback")
	}
	if len(kc.Scopes) != 2 || kc.Scopes[0] != "openid" || kc.Scopes[1] != "profile" {
		t.Errorf("keycloak Scopes: got %v, want [openid profile]", kc.Scopes)
	}

	g, ok := conf.Providers["google"]
	if !ok {
		t.Fatal("expected google provider in conf.Providers")
	}
	if g.IssuerURL != "https://accounts.google.com" {
		t.Errorf("google IssuerURL: got %q, want %q", g.IssuerURL, "https://accounts.google.com")
	}
	if g.ClientID != "google-client" {
		t.Errorf("google ClientID: got %q, want %q", g.ClientID, "google-client")
	}
	if g.ClientSecret != "google-secret" {
		t.Errorf("google ClientSecret: got %q, want %q", g.ClientSecret, "google-secret")
	}

	if conf.DefaultProvider != "keycloak" {
		t.Errorf("DefaultProvider: got %q, want %q", conf.DefaultProvider, "keycloak")
	}
}

// TestParseClusterProviderName verifies that parseRawConfig() reads the provider field
// from a cluster config and stores it in ClusterConfig.ProviderName.
func TestParseClusterProviderName(t *testing.T) {
	cfg := baseConfig()
	cfg["clusters"] = map[string]interface{}{
		"my-cluster": map[string]interface{}{
			"provider": "google",
			"exclude":  false,
		},
	}

	p := &Parser{}
	conf, err := p.parseRawConfig(buildAny(t, cfg))
	if err != nil {
		t.Fatalf("parseRawConfig() error: %v", err)
	}

	cluster, ok := conf.Clusters["my-cluster"]
	if !ok {
		t.Fatal("expected my-cluster in conf.Clusters")
	}
	if cluster.ProviderName != "google" {
		t.Errorf("ProviderName: got %q, want %q", cluster.ProviderName, "google")
	}
}

// TestParseLegacyNoProviders verifies that parseRawConfig() on a legacy config
// (no providers map) still succeeds with empty conf.Providers.
func TestParseLegacyNoProviders(t *testing.T) {
	cfg := baseConfig()
	// Intentionally no "providers" key — legacy path.

	p := &Parser{}
	conf, err := p.parseRawConfig(buildAny(t, cfg))
	if err != nil {
		t.Fatalf("parseRawConfig() error: %v", err)
	}

	if len(conf.Providers) != 0 {
		t.Errorf("expected 0 providers for legacy config, got %d", len(conf.Providers))
	}
	if conf.DefaultProvider != "" {
		t.Errorf("expected empty DefaultProvider for legacy config, got %q", conf.DefaultProvider)
	}
	if conf.IssuerURL != "https://keycloak.example.com/realms/test" {
		t.Errorf("IssuerURL: got %q, want legacy value", conf.IssuerURL)
	}
}

// TestParseClusterMissingProvider verifies that a cluster without a provider
// field gets an empty ProviderName (pre-resolution happens in resources.go).
func TestParseClusterMissingProvider(t *testing.T) {
	cfg := baseConfig()
	cfg["clusters"] = map[string]interface{}{
		"my-cluster": map[string]interface{}{
			"exclude": false,
		},
	}

	p := &Parser{}
	conf, err := p.parseRawConfig(buildAny(t, cfg))
	if err != nil {
		t.Fatalf("parseRawConfig() error: %v", err)
	}

	cluster, ok := conf.Clusters["my-cluster"]
	if !ok {
		t.Fatal("expected my-cluster in conf.Clusters")
	}
	if cluster.ProviderName != "" {
		t.Errorf("ProviderName: got %q, want empty string", cluster.ProviderName)
	}
}

// TestParseClusterExistingFieldsWithProvider verifies existing cluster config
// fields (exclude, exclude_paths, sso_injection, allowed_users) still parse
// correctly alongside the new provider field.
func TestParseClusterExistingFieldsWithProvider(t *testing.T) {
	cfg := baseConfig()
	cfg["clusters"] = map[string]interface{}{
		"app-cluster": map[string]interface{}{
			"provider":      "keycloak",
			"exclude":       true,
			"exclude_paths": []interface{}{"/health", "/metrics"},
			"sso_injection": true,
			"sso_appurl":    "https://app.example.com",
			"sso_appname":   "My App",
			"allowed_users": []interface{}{"alice", "Bob"},
		},
	}

	p := &Parser{}
	conf, err := p.parseRawConfig(buildAny(t, cfg))
	if err != nil {
		t.Fatalf("parseRawConfig() error: %v", err)
	}

	cluster, ok := conf.Clusters["app-cluster"]
	if !ok {
		t.Fatal("expected app-cluster in conf.Clusters")
	}
	if cluster.ProviderName != "keycloak" {
		t.Errorf("ProviderName: got %q, want keycloak", cluster.ProviderName)
	}
	if !cluster.Exclude {
		t.Error("expected Exclude=true")
	}
	if len(cluster.ExcludePaths) != 2 {
		t.Errorf("expected 2 ExcludePaths, got %d", len(cluster.ExcludePaths))
	} else if cluster.ExcludePaths[0] != "/health" || cluster.ExcludePaths[1] != "/metrics" {
		t.Errorf("ExcludePaths: got %v, want [/health /metrics]", cluster.ExcludePaths)
	}
	if !cluster.SsoInjection {
		t.Error("expected SsoInjection=true")
	}
	if cluster.SsoAppURL != "https://app.example.com" {
		t.Errorf("SsoAppURL: got %q", cluster.SsoAppURL)
	}
	if cluster.SsoAppName != "My App" {
		t.Errorf("SsoAppName: got %q", cluster.SsoAppName)
	}
	// AllowedUsers should be normalized to lowercase
	if len(cluster.AllowedUsers) != 2 {
		t.Errorf("expected 2 AllowedUsers, got %d", len(cluster.AllowedUsers))
	}
	if cluster.AllowedUsers[0] != "alice" || cluster.AllowedUsers[1] != "bob" {
		t.Errorf("AllowedUsers: got %v, want [alice bob]", cluster.AllowedUsers)
	}
}

// newLegacyOIDCServer starts a minimal httptest server that serves OIDC discovery
// at /.well-known/openid-configuration, suitable for Parse() legacy path tests.
func newLegacyOIDCServer(t *testing.T) *httptest.Server {
	t.Helper()

	var srv *httptest.Server
	mux := http.NewServeMux()

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		base := srv.URL
		cfg := map[string]interface{}{
			"issuer":                 base,
			"authorization_endpoint": base + "/auth",
			"token_endpoint":         base + "/token",
			"userinfo_endpoint":      base + "/userinfo",
			"jwks_uri":               base + "/jwks",
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(cfg)
	})

	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// parserTestHeaderMap is a minimal api.RequestHeaderMap for parser tests.
type parserTestHeaderMap struct {
	headers map[string]string
}

func newParserTestHeaderMap(cookieValue string) *parserTestHeaderMap {
	return &parserTestHeaderMap{headers: map[string]string{"cookie": cookieValue}}
}

func (m *parserTestHeaderMap) GetRaw(name string) string     { return m.headers[name] }
func (m *parserTestHeaderMap) Get(key string) (string, bool) { v, ok := m.headers[key]; return v, ok }
func (m *parserTestHeaderMap) Values(key string) []string {
	if v, ok := m.headers[key]; ok {
		return []string{v}
	}
	return nil
}
func (m *parserTestHeaderMap) Set(key, value string) { m.headers[key] = value }
func (m *parserTestHeaderMap) Add(key, value string) { m.headers[key] = value }
func (m *parserTestHeaderMap) Del(key string)        { delete(m.headers, key) }
func (m *parserTestHeaderMap) Range(f func(key, value string) bool) {
	for k, v := range m.headers {
		if !f(k, v) {
			break
		}
	}
}
func (m *parserTestHeaderMap) RangeWithCopy(f func(key, value string) bool) { m.Range(f) }
func (m *parserTestHeaderMap) GetAllHeaders() map[string][]string {
	result := make(map[string][]string, len(m.headers))
	for k, v := range m.headers {
		result[k] = []string{v}
	}
	return result
}
func (m *parserTestHeaderMap) Scheme() string          { return "https" }
func (m *parserTestHeaderMap) Method() string          { return "GET" }
func (m *parserTestHeaderMap) Host() string            { return "localhost" }
func (m *parserTestHeaderMap) Path() string            { return "/" }
func (m *parserTestHeaderMap) SetMethod(method string) { m.headers[":method"] = method }
func (m *parserTestHeaderMap) SetHost(host string)     { m.headers[":authority"] = host }
func (m *parserTestHeaderMap) SetPath(path string)     { m.headers[":path"] = path }

// TestParseAuthProviderHeaderName verifies that parseRawConfig() reads the
// auth_provider_header_name field (REQ-01, D-02).
func TestParseAuthProviderHeaderName(t *testing.T) {
	cfg := baseConfig()
	cfg["auth_provider_header_name"] = "X-Custom-Provider"

	p := &Parser{}
	conf, err := p.parseRawConfig(buildAny(t, cfg))
	if err != nil {
		t.Fatalf("parseRawConfig() error: %v", err)
	}
	if conf.AuthProviderHeaderName != "X-Custom-Provider" {
		t.Errorf("AuthProviderHeaderName: got %q, want %q", conf.AuthProviderHeaderName, "X-Custom-Provider")
	}
}

// TestParseAuthProviderHeaderNameDefault verifies that omitting the field
// leaves AuthProviderHeaderName empty (filter applies X-Auth-Provider at write time).
func TestParseAuthProviderHeaderNameDefault(t *testing.T) {
	cfg := baseConfig()
	p := &Parser{}
	conf, err := p.parseRawConfig(buildAny(t, cfg))
	if err != nil {
		t.Fatalf("parseRawConfig() error: %v", err)
	}
	if conf.AuthProviderHeaderName != "" {
		t.Errorf("AuthProviderHeaderName default: got %q, want empty", conf.AuthProviderHeaderName)
	}
}

// TestRemoveHeadersDefaultIncludesAuthProvider verifies that the default
// RemoveHeaders slice includes X-Auth-Provider to prevent client-supplied
// spoofing of the provider identity header (security threat T-04-01).
func TestRemoveHeadersDefaultIncludesAuthProvider(t *testing.T) {
	cfg := baseConfig()
	p := &Parser{}
	conf, err := p.parseRawConfig(buildAny(t, cfg))
	if err != nil {
		t.Fatalf("parseRawConfig() error: %v", err)
	}
	found := false
	for _, h := range conf.RemoveHeaders {
		if h == "X-Auth-Provider" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("default RemoveHeaders missing \"X-Auth-Provider\"; got %v", conf.RemoveHeaders)
	}
}

// TestRemoveHeadersAppendsCustomAuthProviderHeader verifies that when an
// operator sets a custom auth_provider_header_name, the parser auto-appends
// that name to RemoveHeaders so the spoof-protection invariant holds
// (T-04-01 — operators should not need to duplicate the name manually).
func TestRemoveHeadersAppendsCustomAuthProviderHeader(t *testing.T) {
	cfg := baseConfig()
	cfg["auth_provider_header_name"] = "X-Tenant-IDP"
	p := &Parser{}
	conf, err := p.parseRawConfig(buildAny(t, cfg))
	if err != nil {
		t.Fatalf("parseRawConfig() error: %v", err)
	}
	found := false
	for _, h := range conf.RemoveHeaders {
		if h == "X-Tenant-IDP" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("custom AuthProviderHeaderName not auto-added to RemoveHeaders; got %v", conf.RemoveHeaders)
	}
}

// TestRemoveHeadersAppendsCustomUserHeaders verifies that when operators rename
// any identity header (X-User-ID / X-User-Email / X-User-Username), the custom
// name is auto-added to RemoveHeaders so T-04-01 cannot be bypassed by renaming.
func TestRemoveHeadersAppendsCustomUserHeaders(t *testing.T) {
	cfg := baseConfig()
	cfg["user_id_header_name"] = "X-Tenant-UID"
	cfg["user_email_header_name"] = "X-Tenant-Email"
	cfg["user_username_header_name"] = "X-Tenant-User"
	p := &Parser{}
	conf, err := p.parseRawConfig(buildAny(t, cfg))
	if err != nil {
		t.Fatalf("parseRawConfig() error: %v", err)
	}
	for _, name := range []string{"X-Tenant-UID", "X-Tenant-Email", "X-Tenant-User"} {
		if !slices.Contains(conf.RemoveHeaders, name) {
			t.Errorf("custom identity header %q not auto-added to RemoveHeaders; got %v", name, conf.RemoveHeaders)
		}
	}
}

// TestRemoveHeadersEnforcesAuthProviderWhenUserOverrides verifies that even
// when the operator replaces RemoveHeaders wholesale (e.g., to prune unwanted
// entries), the effective auth-provider header is still appended, so
// T-04-01 cannot be bypassed by misconfiguration.
func TestRemoveHeadersEnforcesAuthProviderWhenUserOverrides(t *testing.T) {
	cfg := baseConfig()
	cfg["remove_headers"] = []interface{}{"X-User-ID"} // omits X-Auth-Provider on purpose
	p := &Parser{}
	conf, err := p.parseRawConfig(buildAny(t, cfg))
	if err != nil {
		t.Fatalf("parseRawConfig() error: %v", err)
	}
	found := false
	for _, h := range conf.RemoveHeaders {
		if h == "X-Auth-Provider" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("user-overridden RemoveHeaders did not enforce X-Auth-Provider; got %v", conf.RemoveHeaders)
	}
}

// TestMergePreservesAuthProviderHeaderName verifies that AuthProviderHeaderName
// is copied from parent and correctly overridden by child (REQ-01, Pitfall 1).
func TestMergePreservesAuthProviderHeaderName(t *testing.T) {
	p := &Parser{}

	// Parent-only case: parent value must survive.
	parentCfg := baseConfig()
	parentCfg["auth_provider_header_name"] = "X-Parent-Provider"
	parent, err := p.parseRawConfig(buildAny(t, parentCfg))
	if err != nil {
		t.Fatalf("parent parseRawConfig: %v", err)
	}

	childCfg := baseConfig()
	child, err := p.parseRawConfig(buildAny(t, childCfg))
	if err != nil {
		t.Fatalf("child parseRawConfig: %v", err)
	}

	merged := p.Merge(parent, child).(*OAuthConfig)
	if merged.AuthProviderHeaderName != "X-Parent-Provider" {
		t.Errorf("Merge parent-only: AuthProviderHeaderName lost; got %q, want %q",
			merged.AuthProviderHeaderName, "X-Parent-Provider")
	}

	// Child-override case: child value must win.
	childOverrideCfg := baseConfig()
	childOverrideCfg["auth_provider_header_name"] = "X-Child-Provider"
	childOverride, err := p.parseRawConfig(buildAny(t, childOverrideCfg))
	if err != nil {
		t.Fatalf("childOverride parseRawConfig: %v", err)
	}
	mergedOverride := p.Merge(parent, childOverride).(*OAuthConfig)
	if mergedOverride.AuthProviderHeaderName != "X-Child-Provider" {
		t.Errorf("Merge child-override: got %q, want %q",
			mergedOverride.AuthProviderHeaderName, "X-Child-Provider")
	}
}

// TestMergePreservesProviderAllowedUsers verifies that Merge() copies AllowedUsers
// from parent providers and that the copy is independent (deep clone).
func TestMergePreservesProviderAllowedUsers(t *testing.T) {
	p := &Parser{}

	parentCfg := baseConfig()
	parentCfg["providers"] = map[string]interface{}{
		"keycloak": map[string]interface{}{
			"issuer_url":    "https://keycloak.example.com",
			"client_id":     "kc-client",
			"client_secret": "kc-secret",
			"allowed_users": []interface{}{"alice", "bob"},
		},
	}
	parentCfg["default_provider"] = "keycloak"
	parent, err := p.parseRawConfig(buildAny(t, parentCfg))
	if err != nil {
		t.Fatalf("parent parseRawConfig: %v", err)
	}

	childCfg := baseConfig()
	child, err := p.parseRawConfig(buildAny(t, childCfg))
	if err != nil {
		t.Fatalf("child parseRawConfig: %v", err)
	}

	merged := p.Merge(parent, child).(*OAuthConfig)

	kc, ok := merged.Providers["keycloak"]
	if !ok {
		t.Fatal("keycloak provider lost after Merge")
	}
	if !slices.Equal(kc.AllowedUsers, []string{"alice", "bob"}) {
		t.Errorf("AllowedUsers after Merge: got %v, want [alice bob]", kc.AllowedUsers)
	}

	// Mutate the merged slice to verify it is a clone, not the original.
	kc.AllowedUsers[0] = "mutated"
	merged.Providers["keycloak"] = kc
	orig := parent.Providers["keycloak"]
	if orig.AllowedUsers[0] != "alice" {
		t.Errorf("Merge AllowedUsers is not a deep clone: parent mutated to %v", orig.AllowedUsers)
	}
}

// TestParseLegacyCookieName verifies that Parse() with a legacy single-provider config
// (no providers map) creates a "default" handler whose CookieManager uses the namespaced
// cookie name "<base>_default" (D-02, Pitfall 1 in RESEARCH).
//
// Assertions:
//   - handler.GetSessionCookie with "pkgw_default=my-id" returns "my-id"
//   - handler.GetSessionCookie with old bare "pkgw=my-id" returns error (D-03)
func TestParseLegacyCookieName(t *testing.T) {
	srv := newLegacyOIDCServer(t)

	cfg := map[string]interface{}{
		"issuer_url":          srv.URL,
		"client_id":           "test-client",
		"client_secret":       "test-secret",
		"redirect_url":        "/callback",
		"session_cookie_name": "pkgw",
	}
	any := buildAny(t, cfg)

	p := &Parser{}
	result, err := p.Parse(any, nil)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	conf := result.(*OAuthConfig)

	handler, err := conf.ProviderRegistry.GetHandler("default")
	if err != nil {
		t.Fatalf("default handler not registered: %v", err)
	}

	// New namespaced cookie name must work.
	newCookieHeader := newParserTestHeaderMap("pkgw_default=my-id")
	got, err := handler.GetSessionCookie(newCookieHeader)
	if err != nil || got != "my-id" {
		t.Errorf("GetSessionCookie(pkgw_default=my-id) = (%q, %v), want (\"my-id\", nil)", got, err)
	}

	// Old bare cookie name must be ignored (D-03).
	oldCookieHeader := newParserTestHeaderMap("pkgw=my-id")
	got2, err2 := handler.GetSessionCookie(oldCookieHeader)
	if err2 == nil || got2 != "" {
		t.Errorf("GetSessionCookie(pkgw=my-id) = (%q, %v), want (\"\", error) — old bare name must be ignored", got2, err2)
	}
	if err2 != nil && !strings.Contains(err2.Error(), "not found") && !strings.Contains(err2.Error(), "cookie") {
		t.Logf("GetSessionCookie old name error (acceptable): %v", err2)
	}
}

// TestParseProviderAllowedUsers verifies that allowed_users under a provider entry
// is lowercased, trimmed, and empty strings dropped. Dedup is NOT performed.
func TestParseProviderAllowedUsers(t *testing.T) {
	cfg := map[string]interface{}{
		"providers": map[string]interface{}{
			"kc": map[string]interface{}{
				"issuer_url":    "https://keycloak.example.com",
				"client_id":     "test",
				"client_secret": "secret",
				"allowed_users": []interface{}{"Alice", "  ", "BOB", "alice"},
			},
		},
		"default_provider": "kc",
	}
	p := &Parser{}
	conf, err := p.parseRawConfig(buildAny(t, cfg))
	if err != nil {
		t.Fatalf("parseRawConfig() error: %v", err)
	}
	kc, ok := conf.Providers["kc"]
	if !ok {
		t.Fatal("expected kc provider")
	}
	// "  " trims to "" and is dropped; "Alice" → "alice", "BOB" → "bob", "alice" stays
	want := []string{"alice", "bob", "alice"}
	if len(kc.AllowedUsers) != len(want) {
		t.Fatalf("AllowedUsers len: got %d, want %d; got %v", len(kc.AllowedUsers), len(want), kc.AllowedUsers)
	}
	for i, w := range want {
		if kc.AllowedUsers[i] != w {
			t.Errorf("AllowedUsers[%d]: got %q, want %q", i, kc.AllowedUsers[i], w)
		}
	}
}

// TestParseProviderAllowedUsersEmpty verifies that a provider with no allowed_users
// key results in nil (not an empty slice) and does not panic.
func TestParseProviderAllowedUsersEmpty(t *testing.T) {
	cfg := map[string]interface{}{
		"providers": map[string]interface{}{
			"kc": map[string]interface{}{
				"issuer_url":    "https://keycloak.example.com",
				"client_id":     "test",
				"client_secret": "secret",
				// no allowed_users key
			},
		},
		"default_provider": "kc",
	}
	p := &Parser{}
	conf, err := p.parseRawConfig(buildAny(t, cfg))
	if err != nil {
		t.Fatalf("parseRawConfig() error: %v", err)
	}
	kc, ok := conf.Providers["kc"]
	if !ok {
		t.Fatal("expected kc provider")
	}
	if kc.AllowedUsers != nil {
		t.Errorf("AllowedUsers: got %v, want nil when key absent", kc.AllowedUsers)
	}
}

// TestParseProviderAllowedUsersNonStringEntries verifies that non-string entries in
// allowed_users are silently skipped; only string values survive.
func TestParseProviderAllowedUsersNonStringEntries(t *testing.T) {
	cfg := map[string]interface{}{
		"providers": map[string]interface{}{
			"kc": map[string]interface{}{
				"issuer_url":    "https://keycloak.example.com",
				"client_id":     "test",
				"client_secret": "secret",
				"allowed_users": []interface{}{"alice", 123.0, true, "bob"},
			},
		},
		"default_provider": "kc",
	}
	p := &Parser{}
	conf, err := p.parseRawConfig(buildAny(t, cfg))
	if err != nil {
		t.Fatalf("parseRawConfig() error: %v", err)
	}
	kc, ok := conf.Providers["kc"]
	if !ok {
		t.Fatal("expected kc provider")
	}
	want := []string{"alice", "bob"}
	if len(kc.AllowedUsers) != len(want) {
		t.Fatalf("AllowedUsers: got %v, want %v", kc.AllowedUsers, want)
	}
	for i, w := range want {
		if kc.AllowedUsers[i] != w {
			t.Errorf("AllowedUsers[%d]: got %q, want %q", i, kc.AllowedUsers[i], w)
		}
	}
}

// TestParseEnableLLMsTxtAbsent verifies that when "enable_llms_txt" is absent
// from the config, the resolved value defaults to true.
func TestParseEnableLLMsTxtAbsent(t *testing.T) {
	cfg := baseConfig()
	// note: no "enable_llms_txt" key

	p := &Parser{}
	conf, err := p.parseRawConfig(buildAny(t, cfg))
	if err != nil {
		t.Fatalf("parseRawConfig() error: %v", err)
	}

	if !conf.EnableLLMsTxt {
		t.Errorf("EnableLLMsTxt: got %v, want true (default when key absent)", conf.EnableLLMsTxt)
	}
}

// TestParseEnableLLMsTxtFalse verifies that an explicit false value disables the flag.
func TestParseEnableLLMsTxtFalse(t *testing.T) {
	cfg := baseConfig()
	cfg["enable_llms_txt"] = false

	p := &Parser{}
	conf, err := p.parseRawConfig(buildAny(t, cfg))
	if err != nil {
		t.Fatalf("parseRawConfig() error: %v", err)
	}

	if conf.EnableLLMsTxt {
		t.Errorf("EnableLLMsTxt: got %v, want false (explicit false in config)", conf.EnableLLMsTxt)
	}
}

// TestParseEnableLLMsTxtTrue verifies that an explicit true value keeps the flag on.
func TestParseEnableLLMsTxtTrue(t *testing.T) {
	cfg := baseConfig()
	cfg["enable_llms_txt"] = true

	p := &Parser{}
	conf, err := p.parseRawConfig(buildAny(t, cfg))
	if err != nil {
		t.Fatalf("parseRawConfig() error: %v", err)
	}

	if !conf.EnableLLMsTxt {
		t.Errorf("EnableLLMsTxt: got %v, want true (explicit true in config)", conf.EnableLLMsTxt)
	}
}

// observeWarnLogs swaps the package logger for an observer at Warn level and
// restores it when the test ends. It replaces a package-level global, so tests
// that use it must not call t.Parallel.
func observeWarnLogs(t *testing.T) *observer.ObservedLogs {
	t.Helper()
	core, logs := observer.New(zap.WarnLevel)
	orig := logger
	logger = zap.New(core)
	t.Cleanup(func() { logger = orig })
	return logs
}

// TestParseLegacySkipAuthHeaderNameIgnored verifies that a legacy
// skip_auth_header_name key still parses (old configs keep loading) and logs
// exactly one Warn saying it is ignored (issue #3: the header was a client-controlled bypass).
func TestParseLegacySkipAuthHeaderNameIgnored(t *testing.T) {
	logs := observeWarnLogs(t)

	cfg := baseConfig()
	cfg["skip_auth_header_name"] = "X-Skip-Auth"

	p := &Parser{}
	if _, err := p.parseRawConfig(buildAny(t, cfg)); err != nil {
		t.Fatalf("parseRawConfig() error: %v", err)
	}

	entries := logs.FilterMessageSnippet("skip_auth_header_name").All()
	if len(entries) != 1 {
		t.Fatalf("skip_auth_header_name log entries: got %d, want 1", len(entries))
	}
	e := entries[0]
	if e.Level != zapcore.WarnLevel {
		t.Errorf("log level: got %v, want %v", e.Level, zapcore.WarnLevel)
	}
	if got := e.ContextMap()["header"]; got != "X-Skip-Auth" {
		t.Errorf("header field: got %v, want %q", got, "X-Skip-Auth")
	}
}

// TestParseNoSkipAuthWarnWhenAbsentEmptyOrNonString verifies that no
// skip_auth_header_name warning is logged when the key is absent, empty, or
// not a string, and that parsing still succeeds. Only string values were ever
// honored before the removal, so a non-string value never enabled the bypass
// and there is nothing stale to warn about.
func TestParseNoSkipAuthWarnWhenAbsentEmptyOrNonString(t *testing.T) {
	tests := []struct {
		name  string
		set   bool
		value interface{}
	}{
		{name: "absent"},
		{name: "empty", set: true, value: ""},
		{name: "bool", set: true, value: true},
		{name: "number", set: true, value: 1},
		{name: "list", set: true, value: []interface{}{"X-Skip-Auth"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logs := observeWarnLogs(t)

			cfg := baseConfig()
			if tt.set {
				cfg["skip_auth_header_name"] = tt.value
			}

			p := &Parser{}
			if _, err := p.parseRawConfig(buildAny(t, cfg)); err != nil {
				t.Fatalf("parseRawConfig() error: %v", err)
			}

			if got := logs.FilterMessageSnippet("skip_auth_header_name").Len(); got != 0 {
				t.Errorf("skip_auth_header_name warnings: got %d, want 0", got)
			}
		})
	}
}

// mcpClusterConfig returns a legacy config with one cluster carrying the given mcp block.
func mcpClusterConfig(mcp map[string]interface{}) map[string]interface{} {
	cfg := baseConfig()
	cfg["clusters"] = map[string]interface{}{
		"pack": map[string]interface{}{"mcp": mcp},
	}
	return cfg
}

// TestParseClusterMCP verifies parsing and validation of the cluster mcp block (issue #7).
func TestParseClusterMCP(t *testing.T) {
	p := &Parser{}

	t.Run("valid block derives metadata path and URL", func(t *testing.T) {
		conf, err := p.parseRawConfig(buildAny(t, mcpClusterConfig(map[string]interface{}{
			"path":     "/mcp/",
			"resource": "https://romanian.example/mcp",
		})))
		if err != nil {
			t.Fatalf("parseRawConfig: %v", err)
		}
		got := conf.Clusters["pack"].MCP
		want := &MCPConfig{
			Path:         "/mcp",
			Resource:     "https://romanian.example/mcp",
			MetadataPath: "/.well-known/oauth-protected-resource/mcp",
			MetadataURL:  "https://romanian.example/.well-known/oauth-protected-resource/mcp",
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("MCP = %+v, want %+v", got, want)
		}
	})

	t.Run("cluster without mcp", func(t *testing.T) {
		cfg := baseConfig()
		cfg["clusters"] = map[string]interface{}{"plain": map[string]interface{}{"exclude": false}}
		conf, err := p.parseRawConfig(buildAny(t, cfg))
		if err != nil {
			t.Fatalf("parseRawConfig: %v", err)
		}
		if conf.Clusters["plain"].MCP != nil {
			t.Errorf("MCP = %+v, want nil", conf.Clusters["plain"].MCP)
		}
	})

	invalid := []struct {
		name string
		mcp  map[string]interface{}
	}{
		{"missing path", map[string]interface{}{"resource": "https://romanian.example/mcp"}},
		{"relative path", map[string]interface{}{"path": "mcp", "resource": "https://romanian.example/mcp"}},
		{"root path", map[string]interface{}{"path": "/", "resource": "https://romanian.example/"}},
		{"path differs from resource path", map[string]interface{}{"path": "/api/mcp", "resource": "https://romanian.example/mcp"}},
		{"missing resource", map[string]interface{}{"path": "/mcp"}},
		{"http resource", map[string]interface{}{"path": "/mcp", "resource": "http://romanian.example/mcp"}},
		{"unparsable resource", map[string]interface{}{"path": "/mcp", "resource": "https://%zz/mcp"}},
		{"resource without host", map[string]interface{}{"path": "/mcp", "resource": "https:///mcp"}},
		{"resource without path", map[string]interface{}{"path": "/mcp", "resource": "https://romanian.example"}},
		{"resource with query", map[string]interface{}{"path": "/mcp", "resource": "https://romanian.example/mcp?x=1"}},
		{"resource with fragment", map[string]interface{}{"path": "/mcp", "resource": "https://romanian.example/mcp#x"}},
		// The guard compares raw request paths, so a resource path that needs
		// escaping could never match and would silently fall back to cookie auth.
		// Envoy normalizes these before the filter runs, so the guard could never match them.
		{"resource path with //", map[string]interface{}{"path": "/api//mcp", "resource": "https://romanian.example/api//mcp"}},
		{"resource path with dot-segment", map[string]interface{}{"path": "/a/../mcp", "resource": "https://romanian.example/a/../mcp"}},
		{"resource path with ;", map[string]interface{}{"path": "/mcp;v1", "resource": "https://romanian.example/mcp;v1"}},
		{"percent-encoded resource path", map[string]interface{}{"path": "/a b/mcp", "resource": "https://romanian.example/a%20b/mcp"}},
		{"percent-encoded resource path, escaped config path", map[string]interface{}{"path": "/a%20b/mcp", "resource": "https://romanian.example/a%20b/mcp"}},
	}
	for _, tt := range invalid {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := p.parseRawConfig(buildAny(t, mcpClusterConfig(tt.mcp))); err == nil {
				t.Error("parseRawConfig: expected an error")
			}
		})
	}
}

// TestMergeClusterMCP verifies that all three Merge copy sites carry the mcp block.
func TestMergeClusterMCP(t *testing.T) {
	p := &Parser{}
	parse := func(cfg map[string]interface{}) *OAuthConfig {
		t.Helper()
		conf, err := p.parseRawConfig(buildAny(t, cfg))
		if err != nil {
			t.Fatalf("parseRawConfig: %v", err)
		}
		return conf
	}
	romanian := map[string]interface{}{"path": "/mcp", "resource": "https://romanian.example/mcp", "scopes": []interface{}{"openid", "profile"}}
	english := map[string]interface{}{"path": "/mcp", "resource": "https://english.example/mcp"}

	parent := parse(mcpClusterConfig(romanian))

	merged := p.Merge(parent, parse(baseConfig())).(*OAuthConfig)
	if mcp := merged.Clusters["pack"].MCP; mcp == nil || mcp.Resource != "https://romanian.example/mcp" || !slices.Equal(mcp.Scopes, []string{"openid", "profile"}) {
		t.Errorf("parent only: MCP = %+v, want the parent block with its scopes", mcp)
	}

	merged = p.Merge(parent, parse(mcpClusterConfig(english))).(*OAuthConfig)
	if mcp := merged.Clusters["pack"].MCP; mcp == nil || mcp.Resource != "https://english.example/mcp" {
		t.Errorf("child override: MCP = %+v, want the child block", mcp)
	}

	childOnly := baseConfig()
	childOnly["clusters"] = map[string]interface{}{"other": map[string]interface{}{"mcp": english}}
	merged = p.Merge(parse(baseConfig()), parse(childOnly)).(*OAuthConfig)
	if mcp := merged.Clusters["other"].MCP; mcp == nil || mcp.Resource != "https://english.example/mcp" {
		t.Errorf("child-only cluster: MCP = %+v, want the child block", mcp)
	}
}

// TestParseClusterMCPScopes verifies the optional scopes list of the mcp block.
func TestParseClusterMCPScopes(t *testing.T) {
	p := &Parser{}
	block := func(scopes interface{}) map[string]interface{} {
		m := map[string]interface{}{"path": "/mcp", "resource": "https://romanian.example/mcp"}
		if scopes != nil {
			m["scopes"] = scopes
		}
		return m
	}

	t.Run("scopes kept in config order", func(t *testing.T) {
		conf, err := p.parseRawConfig(buildAny(t, mcpClusterConfig(block([]interface{}{"openid", "profile", "offline_access"}))))
		if err != nil {
			t.Fatalf("parseRawConfig: %v", err)
		}
		got := conf.Clusters["pack"].MCP.Scopes
		if !slices.Equal(got, []string{"openid", "profile", "offline_access"}) {
			t.Errorf("Scopes = %v", got)
		}
	})

	t.Run("absent and empty mean no scopes", func(t *testing.T) {
		for _, scopes := range []interface{}{nil, []interface{}{}} {
			conf, err := p.parseRawConfig(buildAny(t, mcpClusterConfig(block(scopes))))
			if err != nil {
				t.Fatalf("parseRawConfig(%v): %v", scopes, err)
			}
			if got := conf.Clusters["pack"].MCP.Scopes; got != nil {
				t.Errorf("Scopes(%v) = %v, want nil", scopes, got)
			}
		}
	})

	invalid := map[string]interface{}{
		"empty entry":  []interface{}{"openid", ""},
		"space":        []interface{}{"open id"},
		"double quote": []interface{}{`open"id`},
		"backslash":    []interface{}{`open\id`},
		"non-ascii":    []interface{}{"profilé"},
		"control char": []interface{}{"open\tid"},
		"duplicate":    []interface{}{"openid", "profile", "openid"},
		"non-string":   []interface{}{"openid", 7.0},
		"not a list":   "openid profile",
	}
	for name, scopes := range invalid {
		t.Run(name, func(t *testing.T) {
			if _, err := p.parseRawConfig(buildAny(t, mcpClusterConfig(block(scopes)))); err == nil {
				t.Errorf("scopes %#v: expected an error", scopes)
			}
		})
	}
}
