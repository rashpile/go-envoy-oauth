package filter

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/envoyproxy/envoy/contrib/golang/common/go/api"
	"github.com/rashpile/go-envoy-oauth/plugin/oauth"
	"github.com/rashpile/go-envoy-oauth/plugin/session"
	"go.uber.org/zap"
)

// mockOAuthHandler is a minimal OAuthHandler implementation for registry tests.
type mockOAuthHandler struct{}

func (m *mockOAuthHandler) HandleAuthRedirect(_ api.RequestHeaderMap, _ string) error { return nil }
func (m *mockOAuthHandler) HandleCallback(_ api.RequestHeaderMap, _ string) error     { return nil }
func (m *mockOAuthHandler) HandleLogout(_ api.RequestHeaderMap) (string, error)       { return "/", nil }
func (m *mockOAuthHandler) ValidateSession(_ *session.Session) error                  { return nil }
func (m *mockOAuthHandler) IsNeedValidateSession(_ *session.Session) bool             { return false }
func (m *mockOAuthHandler) ValidateBearerToken(_ context.Context, _ string) (*session.Session, error) {
	return nil, nil
}
func (m *mockOAuthHandler) ExchangeRefreshToken(_ context.Context, _ string) (string, error) {
	return "", nil
}
func (m *mockOAuthHandler) GetSessionCookie(_ api.RequestHeaderMap) (string, error) {
	return "", nil
}
func (m *mockOAuthHandler) DeleteSessionCookie(_ api.RequestHeaderMap)              {}
func (m *mockOAuthHandler) SetSessionCookie(_ api.RequestHeaderMap, _ string) error { return nil }
func (m *mockOAuthHandler) FormatSessionCookie(_ string) string                     { return "" }
func (m *mockOAuthHandler) HealthState() oauth.ProviderState                        { return oauth.StateReady }

// Compile-time check: mockOAuthHandler must implement oauth.OAuthHandler.
var _ oauth.OAuthHandler = (*mockOAuthHandler)(nil)

// TestProviderRegistry tests the ProviderRegistry type.
func TestProviderRegistry(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	t.Run("NewProviderRegistry returns non-nil registry with empty handlers", func(t *testing.T) {
		r := NewProviderRegistry(logger)
		if r == nil {
			t.Fatal("expected non-nil registry")
		}
		if r.handlers == nil {
			t.Fatal("expected non-nil handlers map")
		}
		if len(r.handlers) != 0 {
			t.Errorf("expected empty handlers map, got %d entries", len(r.handlers))
		}
	})

	t.Run("GetHandler for non-existent provider returns error containing 'not found'", func(t *testing.T) {
		r := NewProviderRegistry(logger)
		h, err := r.GetHandler("nonexistent")
		if h != nil {
			t.Error("expected nil handler for missing provider")
		}
		if err == nil {
			t.Fatal("expected error for missing provider")
		}
		if !strings.Contains(err.Error(), "not found") {
			t.Errorf("expected error to contain 'not found', got: %v", err)
		}
	})

	t.Run("Register then GetHandler returns the registered handler", func(t *testing.T) {
		r := NewProviderRegistry(logger)
		mock := &mockOAuthHandler{}
		r.Register("keycloak", mock)

		h, err := r.GetHandler("keycloak")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if h != mock {
			t.Error("expected same handler instance back")
		}
	})
}

// TestPendingAuth tests PendingAuth encode/decode via the session store.
func TestPendingAuth(t *testing.T) {
	store := session.NewInMemorySessionStore()

	t.Run("StorePendingAuth stores with 'pending:' prefix; GetPendingAuth retrieves and deletes", func(t *testing.T) {
		nonce := "testnonce123"
		pa := &session.PendingAuth{
			ProviderName: "keycloak",
			OriginalPath: "/app/dashboard",
			CodeVerifier: "verifier-value",
			Expiry:       time.Now().Add(5 * time.Minute),
		}

		if err := session.StorePendingAuth(store, nonce, pa); err != nil {
			t.Fatalf("StorePendingAuth failed: %v", err)
		}

		// Verify it was stored with "pending:" prefix by attempting a direct Get
		rawSess, err := store.Get(session.PendingAuthPrefix + nonce)
		if err != nil {
			t.Fatalf("expected session stored with key %q, got error: %v", session.PendingAuthPrefix+nonce, err)
		}
		if rawSess.UserID != session.PendingAuthUserID {
			t.Errorf("expected UserID %q, got %q", session.PendingAuthUserID, rawSess.UserID)
		}

		retrieved, err := session.GetPendingAuth(store, nonce)
		if err != nil {
			t.Fatalf("GetPendingAuth failed: %v", err)
		}
		if retrieved.ProviderName != pa.ProviderName {
			t.Errorf("ProviderName: got %q, want %q", retrieved.ProviderName, pa.ProviderName)
		}
		if retrieved.OriginalPath != pa.OriginalPath {
			t.Errorf("OriginalPath: got %q, want %q", retrieved.OriginalPath, pa.OriginalPath)
		}
		if retrieved.CodeVerifier != pa.CodeVerifier {
			t.Errorf("CodeVerifier: got %q, want %q", retrieved.CodeVerifier, pa.CodeVerifier)
		}
	})

	t.Run("GetPendingAuth deletes after retrieval (single-use)", func(t *testing.T) {
		nonce := "singleusenonce"
		pa := &session.PendingAuth{
			ProviderName: "provider1",
			OriginalPath: "/",
			CodeVerifier: "cv",
			Expiry:       time.Now().Add(5 * time.Minute),
		}

		if err := session.StorePendingAuth(store, nonce, pa); err != nil {
			t.Fatalf("StorePendingAuth failed: %v", err)
		}

		// First retrieval should succeed
		if _, err := session.GetPendingAuth(store, nonce); err != nil {
			t.Fatalf("first GetPendingAuth failed: %v", err)
		}

		// Second retrieval should fail (entry deleted)
		if _, err := session.GetPendingAuth(store, nonce); err == nil {
			t.Error("expected error on second GetPendingAuth (should be deleted)")
		}
	})

	t.Run("GetPendingAuth returns error for non-existent nonce", func(t *testing.T) {
		_, err := session.GetPendingAuth(store, "doesnotexist")
		if err == nil {
			t.Error("expected error for non-existent nonce")
		}
	})
}

// TestGetProviderHandler verifies that Filter.getProviderHandler resolves handlers
// using the cluster ProviderName and falls back to DefaultProvider.
func TestGetProviderHandler(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	registry := NewProviderRegistry(logger)

	keycloakHandler := &mockOAuthHandler{}
	defaultHandler := &mockOAuthHandler{}
	registry.Register("keycloak", keycloakHandler)
	registry.Register("default", defaultHandler)

	baseConfig := &OAuthConfig{
		Clusters: map[string]ClusterConfig{
			"app-cluster":     {ProviderName: "keycloak"},
			"default-cluster": {ProviderName: ""},
		},
		DefaultProvider: "default",
	}

	t.Run("cluster with ProviderName returns that provider's handler", func(t *testing.T) {
		f := &Filter{
			config:           baseConfig,
			providerRegistry: registry,
			cluster:          "app-cluster",
		}
		h, err := f.getProviderHandler()
		if err != nil {
			t.Fatalf("getProviderHandler() error: %v", err)
		}
		if h != keycloakHandler {
			t.Error("expected keycloak handler")
		}
	})

	t.Run("cluster with empty ProviderName falls back to DefaultProvider", func(t *testing.T) {
		f := &Filter{
			config:           baseConfig,
			providerRegistry: registry,
			cluster:          "default-cluster",
		}
		h, err := f.getProviderHandler()
		if err != nil {
			t.Fatalf("getProviderHandler() error: %v", err)
		}
		if h != defaultHandler {
			t.Error("expected default handler for cluster with empty ProviderName")
		}
	})

	t.Run("unknown cluster falls back to DefaultProvider", func(t *testing.T) {
		f := &Filter{
			config:           baseConfig,
			providerRegistry: registry,
			cluster:          "unknown-cluster",
		}
		h, err := f.getProviderHandler()
		if err != nil {
			t.Fatalf("getProviderHandler() error: %v", err)
		}
		if h != defaultHandler {
			t.Error("expected default handler for unknown cluster")
		}
	})

	t.Run("returns error when provider not in registry", func(t *testing.T) {
		registryMissing := NewProviderRegistry(logger)
		// Only register "default", not "keycloak"
		registryMissing.Register("default", defaultHandler)

		f := &Filter{
			config:           baseConfig,
			providerRegistry: registryMissing,
			cluster:          "app-cluster", // maps to "keycloak" which is not registered
		}
		_, err := f.getProviderHandler()
		if err == nil {
			t.Fatal("expected error when provider not in registry")
		}
	})
}

// TestMergeProviderRegistry verifies that Merge() copies the ProviderRegistry
// pointer from parent to child config.
func TestMergeProviderRegistry(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	registry := NewProviderRegistry(logger)
	registry.Register("default", &mockOAuthHandler{})

	parent := &OAuthConfig{
		IssuerURL:        "https://example.com",
		ClientID:         "parent-client",
		ClientSecret:     "parent-secret",
		RedirectURL:      "/callback",
		ProviderRegistry: registry,
		Clusters:         make(map[string]ClusterConfig),
		Providers:        make(map[string]ProviderConfig),
	}
	child := &OAuthConfig{
		IssuerURL:        "",
		ClientID:         "",
		ClientSecret:     "",
		RedirectURL:      "",
		ProviderRegistry: nil, // child has no registry
		Clusters:         make(map[string]ClusterConfig),
		Providers:        make(map[string]ProviderConfig),
	}

	p := &Parser{}
	result := p.Merge(parent, child).(*OAuthConfig)

	if result.ProviderRegistry != registry {
		t.Error("expected Merge() to copy ProviderRegistry pointer from parent to result")
	}
}

// newTestOIDCDiscoveryServer starts an httptest server that serves OIDC discovery
// documents. Each provider path (e.g. "/p1") gets its own discovery endpoint at
// "/p1/.well-known/openid-configuration" with an issuer matching that path prefix.
// This enables TestInitAllPerProviderCookieNames to point two ProviderConfig entries
// at distinct issuer URLs on the same test server.
func newTestOIDCDiscoveryServer(t *testing.T) *httptest.Server {
	t.Helper()

	var srv *httptest.Server
	mux := http.NewServeMux()

	makeDiscovery := func(issuer string) func(w http.ResponseWriter, r *http.Request) {
		return func(w http.ResponseWriter, r *http.Request) {
			cfg := map[string]interface{}{
				"issuer":                 issuer,
				"authorization_endpoint": issuer + "/auth",
				"token_endpoint":         issuer + "/token",
				"userinfo_endpoint":      issuer + "/userinfo",
				"jwks_uri":               issuer + "/jwks",
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(cfg)
		}
	}

	// We register discovery handlers lazily via a catch-all that derives the
	// provider prefix from the path.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Match "/<prefix>/.well-known/openid-configuration"
		path := r.URL.Path
		const suffix = "/.well-known/openid-configuration"
		if strings.HasSuffix(path, suffix) {
			prefix := strings.TrimSuffix(path, suffix)
			issuer := srv.URL + prefix
			makeDiscovery(issuer)(w, r)
			return
		}
		http.NotFound(w, r)
	})

	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// TestInitAllPerProviderCookieNames verifies that after InitAll with two providers,
// each handler's CookieManager uses the correct per-provider namespaced cookie name,
// and that handlers cannot read each other's cookies (T-03-08).
func TestInitAllPerProviderCookieNames(t *testing.T) {
	srv := newTestOIDCDiscoveryServer(t)
	logger, _ := zap.NewDevelopment()
	store := session.NewInMemorySessionStore()
	registry := NewProviderRegistry(logger)

	providers := map[string]ProviderConfig{
		"p1": {
			IssuerURL:    srv.URL + "/p1",
			ClientID:     "client-p1",
			ClientSecret: "secret-p1",
			RedirectURL:  "http://localhost/callback",
			Scopes:       []string{"openid"},
		},
		"p2": {
			IssuerURL:    srv.URL + "/p2",
			ClientID:     "client-p2",
			ClientSecret: "secret-p2",
			RedirectURL:  "http://localhost/callback",
			Scopes:       []string{"openid"},
		},
	}

	cookieConfig := &session.CookieConfig{Name: "pkgw", Path: "/"}

	// This call must fail to compile while InitAll still takes *session.CookieManager.
	if err := registry.InitAll(providers, store, cookieConfig); err != nil {
		t.Fatalf("InitAll failed: %v", err)
	}

	h1, err := registry.GetHandler("p1")
	if err != nil {
		t.Fatalf("GetHandler(p1): %v", err)
	}
	h2, err := registry.GetHandler("p2")
	if err != nil {
		t.Fatalf("GetHandler(p2): %v", err)
	}

	// Build a header that carries both cookies.
	bothHeader := &mockRegistryHeaderMap{headers: map[string]string{
		"cookie": "pkgw_p1=session-one; pkgw_p2=session-two",
	}}

	// h1 must read pkgw_p1 (its own cookie).
	got1, err := h1.GetSessionCookie(bothHeader)
	if err != nil || got1 != "session-one" {
		t.Errorf("h1.GetSessionCookie = (%q, %v), want (\"session-one\", nil)", got1, err)
	}

	// h2 must read pkgw_p2 (its own cookie).
	got2, err := h2.GetSessionCookie(bothHeader)
	if err != nil || got2 != "session-two" {
		t.Errorf("h2.GetSessionCookie = (%q, %v), want (\"session-two\", nil)", got2, err)
	}

	// h1 must NOT read p2's cookie when only pkgw_p2 is present.
	onlyP2 := &mockRegistryHeaderMap{headers: map[string]string{
		"cookie": "pkgw_p2=only-p2",
	}}
	got1cross, err := h1.GetSessionCookie(onlyP2)
	if err == nil || got1cross != "" {
		t.Errorf("h1.GetSessionCookie with only pkgw_p2 cookie = (%q, %v), want (\"\", error)", got1cross, err)
	}
}

// mockRegistryHeaderMap is a minimal api.RequestHeaderMap for provider_registry tests.
type mockRegistryHeaderMap struct {
	headers map[string]string
}

func (m *mockRegistryHeaderMap) GetRaw(name string) string     { return m.headers[name] }
func (m *mockRegistryHeaderMap) Get(key string) (string, bool) { v, ok := m.headers[key]; return v, ok }
func (m *mockRegistryHeaderMap) Values(key string) []string {
	if v, ok := m.headers[key]; ok {
		return []string{v}
	}
	return nil
}
func (m *mockRegistryHeaderMap) Set(key, value string) { m.headers[key] = value }
func (m *mockRegistryHeaderMap) Add(key, value string) { m.headers[key] = value }
func (m *mockRegistryHeaderMap) Del(key string)        { delete(m.headers, key) }
func (m *mockRegistryHeaderMap) Range(f func(key, value string) bool) {
	for k, v := range m.headers {
		if !f(k, v) {
			break
		}
	}
}
func (m *mockRegistryHeaderMap) RangeWithCopy(f func(key, value string) bool) { m.Range(f) }
func (m *mockRegistryHeaderMap) GetAllHeaders() map[string][]string {
	result := make(map[string][]string, len(m.headers))
	for k, v := range m.headers {
		result[k] = []string{v}
	}
	return result
}
func (m *mockRegistryHeaderMap) Scheme() string          { return "https" }
func (m *mockRegistryHeaderMap) Method() string          { return "GET" }
func (m *mockRegistryHeaderMap) Host() string            { return "localhost" }
func (m *mockRegistryHeaderMap) Path() string            { return "/" }
func (m *mockRegistryHeaderMap) SetMethod(method string) { m.headers[":method"] = method }
func (m *mockRegistryHeaderMap) SetHost(host string)     { m.headers[":authority"] = host }
func (m *mockRegistryHeaderMap) SetPath(path string)     { m.headers[":path"] = path }

// TestPeekPendingAuthProvider tests that PeekPendingAuthProvider reads provider name without deleting.
func TestPeekPendingAuthProvider(t *testing.T) {
	store := session.NewInMemorySessionStore()

	t.Run("PeekPendingAuthProvider returns provider name without deleting", func(t *testing.T) {
		nonce := "peeknonce"
		pa := &session.PendingAuth{
			ProviderName: "google",
			OriginalPath: "/protected",
			CodeVerifier: "cv-peek",
			Expiry:       time.Now().Add(5 * time.Minute),
		}

		if err := session.StorePendingAuth(store, nonce, pa); err != nil {
			t.Fatalf("StorePendingAuth failed: %v", err)
		}

		// Peek should return provider name
		providerName, err := session.PeekPendingAuthProvider(store, nonce)
		if err != nil {
			t.Fatalf("PeekPendingAuthProvider failed: %v", err)
		}
		if providerName != "google" {
			t.Errorf("expected provider %q, got %q", "google", providerName)
		}

		// Entry should still exist (peek doesn't delete)
		retrieved, err := session.GetPendingAuth(store, nonce)
		if err != nil {
			t.Fatalf("GetPendingAuth after peek failed: %v", err)
		}
		if retrieved.ProviderName != "google" {
			t.Errorf("ProviderName after peek: got %q, want %q", retrieved.ProviderName, "google")
		}
	})

	t.Run("PeekPendingAuthProvider returns error for non-existent nonce", func(t *testing.T) {
		_, err := session.PeekPendingAuthProvider(store, "doesnotexist")
		if err == nil {
			t.Error("expected error for non-existent nonce")
		}
	})
}

// newBlockingOIDCServer starts an httptest server whose discovery endpoint
// blocks on `release` before responding. inFlight is incremented per in-flight
// request and decremented on return; the test uses max(peak) to verify the
// concurrency bound.
func newBlockingOIDCServer(t *testing.T, release <-chan struct{}, inFlight *atomic.Int32, peak *atomic.Int32) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		const suffix = "/.well-known/openid-configuration"
		path := r.URL.Path
		if !strings.HasSuffix(path, suffix) {
			http.NotFound(w, r)
			return
		}
		now := inFlight.Add(1)
		for {
			cur := peak.Load()
			if now <= cur || peak.CompareAndSwap(cur, now) {
				break
			}
		}
		defer inFlight.Add(-1)

		<-release // wait until test releases

		prefix := strings.TrimSuffix(path, suffix)
		issuer := srv.URL + prefix
		cfg := map[string]interface{}{
			"issuer":                 issuer,
			"authorization_endpoint": issuer + "/auth",
			"token_endpoint":         issuer + "/token",
			"userinfo_endpoint":      issuer + "/userinfo",
			"jwks_uri":               issuer + "/jwks",
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(cfg)
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// TestInitAllPartialFailure — HLTH-03: a single failed provider does not
// prevent others from registering; failed provider → DownHandler.
func TestInitAllPartialFailure(t *testing.T) {
	goodSrv := newTestOIDCDiscoveryServer(t)
	logger, _ := zap.NewDevelopment()
	store := session.NewInMemorySessionStore()
	registry := NewProviderRegistry(logger)

	providers := map[string]ProviderConfig{
		"p1": {
			IssuerURL:    goodSrv.URL + "/p1",
			ClientID:     "c1",
			ClientSecret: "s1",
			RedirectURL:  "http://localhost/cb",
			Scopes:       []string{"openid"},
		},
		"p2": {
			// Port 1 is reliably unreachable; OIDC discovery fails quickly.
			IssuerURL:    "http://127.0.0.1:1",
			ClientID:     "c2",
			ClientSecret: "s2",
			RedirectURL:  "http://localhost/cb",
			Scopes:       []string{"openid"},
		},
	}

	cookieConfig := &session.CookieConfig{Name: "pkgw", Path: "/"}
	if err := registry.InitAll(providers, store, cookieConfig); err != nil {
		t.Fatalf("InitAll unexpectedly returned error: %v", err)
	}

	h1, err := registry.GetHandler("p1")
	if err != nil {
		t.Fatalf("GetHandler(p1): %v", err)
	}
	if _, ok := h1.(*oauth.DownHandler); ok {
		t.Errorf("expected p1 to be a healthy handler, got *oauth.DownHandler")
	}

	h2, err := registry.GetHandler("p2")
	if err != nil {
		t.Fatalf("GetHandler(p2): %v", err)
	}
	if _, ok := h2.(*oauth.DownHandler); !ok {
		t.Errorf("expected p2 to be *oauth.DownHandler, got %T", h2)
	}
	if got := h2.HealthState(); got != oauth.StateDown {
		t.Errorf("p2 HealthState = %v, want StateDown", got)
	}
}

// TestInitAllAllFailed — every provider's discovery fails; all register as DownHandler.
func TestInitAllAllFailed(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	store := session.NewInMemorySessionStore()
	registry := NewProviderRegistry(logger)

	providers := map[string]ProviderConfig{
		"p1": {IssuerURL: "http://127.0.0.1:1", ClientID: "c1", ClientSecret: "s1", RedirectURL: "http://localhost/cb", Scopes: []string{"openid"}},
		"p2": {IssuerURL: "http://127.0.0.1:2", ClientID: "c2", ClientSecret: "s2", RedirectURL: "http://localhost/cb", Scopes: []string{"openid"}},
	}

	cookieConfig := &session.CookieConfig{Name: "pkgw", Path: "/"}
	if err := registry.InitAll(providers, store, cookieConfig); err != nil {
		t.Fatalf("InitAll unexpectedly returned error: %v", err)
	}

	for _, name := range []string{"p1", "p2"} {
		h, err := registry.GetHandler(name)
		if err != nil {
			t.Fatalf("GetHandler(%s): %v", name, err)
		}
		if _, ok := h.(*oauth.DownHandler); !ok {
			t.Errorf("%s: expected *oauth.DownHandler, got %T", name, h)
		}
	}
}

// TestInitAllBoundedConcurrency — HLTH-01: peak in-flight discovery requests ≤ 5.
func TestInitAllBoundedConcurrency(t *testing.T) {
	release := make(chan struct{})
	var inFlight, peak atomic.Int32
	srv := newBlockingOIDCServer(t, release, &inFlight, &peak)

	logger, _ := zap.NewDevelopment()
	store := session.NewInMemorySessionStore()
	registry := NewProviderRegistry(logger)

	const numProviders = 8
	providers := make(map[string]ProviderConfig, numProviders)
	for i := 0; i < numProviders; i++ {
		name := fmt.Sprintf("p%d", i)
		providers[name] = ProviderConfig{
			IssuerURL:    srv.URL + "/" + name,
			ClientID:     "c" + name,
			ClientSecret: "s" + name,
			RedirectURL:  "http://localhost/cb",
			Scopes:       []string{"openid"},
		}
	}

	cookieConfig := &session.CookieConfig{Name: "pkgw", Path: "/"}
	done := make(chan error, 1)
	go func() { done <- registry.InitAll(providers, store, cookieConfig) }()

	// Give goroutines time to queue; they will block at <-release until we signal.
	// Poll until we see at least 5 in flight or 2 seconds pass, then release.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if inFlight.Load() >= initConcurrencyLimit {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	close(release)

	if err := <-done; err != nil {
		t.Fatalf("InitAll returned error: %v", err)
	}

	gotPeak := peak.Load()
	if gotPeak > int32(initConcurrencyLimit) {
		t.Errorf("peak in-flight = %d, want ≤ %d", gotPeak, initConcurrencyLimit)
	}
	if gotPeak == 0 {
		t.Errorf("peak in-flight = 0 — test did not observe any concurrent requests; timing bug")
	}
}

// TestInitAllShutdownCancelsContext — ShutdownContext().Done() closes on Shutdown().
func TestInitAllShutdownCancelsContext(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	registry := NewProviderRegistry(logger)
	ctx := registry.ShutdownContext()
	select {
	case <-ctx.Done():
		t.Fatal("shutdown context was already cancelled before Shutdown()")
	default:
	}
	registry.Shutdown()
	select {
	case <-ctx.Done():
		// success
	case <-time.After(1 * time.Second):
		t.Fatal("shutdown context not cancelled within 1s of Shutdown()")
	}
}

// downMockHandler is a mockOAuthHandler whose HealthState returns StateDown.
type downMockHandler struct{ mockOAuthHandler }

func (d *downMockHandler) HealthState() oauth.ProviderState { return oauth.StateDown }

// TestGetProviderHandlerGatesOnDown verifies that getProviderHandler returns an
// error when the resolved handler is StateDown (HLTH-02 / D-03).
func TestGetProviderHandlerGatesOnDown(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	registry := NewProviderRegistry(logger)

	downHandler := &downMockHandler{}
	registry.Register("keycloak", downHandler)

	cfg := &OAuthConfig{
		Clusters:        map[string]ClusterConfig{"app": {ProviderName: "keycloak"}},
		DefaultProvider: "keycloak",
	}
	f := &Filter{config: cfg, providerRegistry: registry, cluster: "app"}

	_, err := f.getProviderHandler()
	if err == nil {
		t.Fatal("expected error from getProviderHandler when provider is StateDown, got nil")
	}
}

// TestGetProviderHandlerReadyPasses verifies that getProviderHandler returns the
// handler without error when health state is StateReady.
func TestGetProviderHandlerReadyPasses(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	registry := NewProviderRegistry(logger)

	readyHandler := &mockOAuthHandler{} // HealthState() returns StateReady
	registry.Register("keycloak", readyHandler)

	cfg := &OAuthConfig{
		Clusters:        map[string]ClusterConfig{"app": {ProviderName: "keycloak"}},
		DefaultProvider: "keycloak",
	}
	f := &Filter{config: cfg, providerRegistry: registry, cluster: "app"}

	h, err := f.getProviderHandler()
	if err != nil {
		t.Fatalf("getProviderHandler() returned unexpected error: %v", err)
	}
	if h != readyHandler {
		t.Error("expected readyHandler back from getProviderHandler")
	}
}

type degradedTestMock struct{ mockOAuthHandler }

func (d *degradedTestMock) HealthState() oauth.ProviderState { return oauth.StateDegraded }

// TestGetProviderHandlerDegradedAllowed verifies that StateDegraded does NOT
// trigger the 503 gate — only StateDown does (D-03).
func TestGetProviderHandlerDegradedAllowed(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	registry := NewProviderRegistry(logger)
	registry.Register("p1", &degradedTestMock{})

	cfg := &OAuthConfig{
		Clusters:        map[string]ClusterConfig{"app": {ProviderName: "p1"}},
		DefaultProvider: "p1",
	}
	f := &Filter{config: cfg, providerRegistry: registry, cluster: "app"}

	h, err := f.getProviderHandler()
	if err != nil {
		t.Fatalf("getProviderHandler() with StateDegraded returned unexpected error: %v", err)
	}
	if h == nil {
		t.Fatal("expected non-nil handler for degraded (not down) provider")
	}
}
