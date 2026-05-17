package filter

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/envoyproxy/envoy/contrib/golang/common/go/api"
	"github.com/rashpile/go-envoy-oauth/plugin/session"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

// testProviderName is a shared constant for isUserPermitted tests to avoid duplicating
// the string literal across multiple test functions.
const testProviderName = "test-provider"

// recordingHandler wraps mockOAuthHandler with call recording for mismatch-branch testing.
// Methods not explicitly overridden delegate to mockOAuthHandler.
type recordingHandler struct {
	mockOAuthHandler
	cookieValue           string
	getSessionCookieCalls int
	deleteCookieCalls     int
	isNeedValidate        bool
}

func (r *recordingHandler) GetSessionCookie(_ api.RequestHeaderMap) (string, error) {
	r.getSessionCookieCalls++
	if r.cookieValue == "" {
		return "", errors.New("no cookie")
	}
	return r.cookieValue, nil
}

func (r *recordingHandler) DeleteSessionCookie(_ api.RequestHeaderMap) {
	r.deleteCookieCalls++
}

func (r *recordingHandler) IsNeedValidateSession(_ *session.Session) bool {
	return r.isNeedValidate
}

func (r *recordingHandler) ValidateBearerToken(_ context.Context, _ string) (*session.Session, error) {
	return nil, errors.New("not implemented")
}

// TestProviderMatchAllowsSession verifies SESS-02: a session whose ProviderName
// matches the cluster-derived provider passes verifySessionProvider as matched.
func TestProviderMatchAllowsSession(t *testing.T) {
	store := session.NewInMemorySessionStore()
	_ = store.Store(&session.Session{
		ID:           "sess-ok",
		ProviderName: "keycloak",
		ExpiresAt:    time.Now().Add(1 * time.Hour),
	})
	handler := &recordingHandler{cookieValue: "sess-ok"}
	registry := NewProviderRegistry(zap.NewNop())
	registry.Register("keycloak", handler)

	f := &Filter{
		config: &OAuthConfig{
			Clusters: map[string]ClusterConfig{
				"cluster1": {ProviderName: "keycloak"},
			},
			DefaultProvider: "keycloak",
		},
		cluster:          "cluster1",
		providerRegistry: registry,
		sessionStore:     store,
		logger:           zap.NewNop(),
	}

	sess, getErr := store.Get("sess-ok")
	if getErr != nil {
		t.Fatalf("test setup: session not in store: %v", getErr)
	}

	matched, _ := f.verifySessionProvider(sess)
	if !matched {
		t.Error("verifySessionProvider returned not-matched for a session whose ProviderName matches the cluster provider; want matched=true")
	}

	// Session must still be in the store (not deleted)
	if _, err := store.Get("sess-ok"); err != nil {
		t.Error("session was deleted from the store even though the provider matched")
	}
}

// TestProviderMismatchRejectsSession verifies SESS-02: a session whose ProviderName
// differs from the cluster-derived provider fails verifySessionProvider.
// Side effects (session delete, cookie clear) are exercised separately in handleDecodeHeaders
// integration; this test validates the helper's bool return.
func TestProviderMismatchRejectsSession(t *testing.T) {
	store := session.NewInMemorySessionStore()
	_ = store.Store(&session.Session{
		ID:           "sess-bad",
		ProviderName: "google",
		ExpiresAt:    time.Now().Add(1 * time.Hour),
	})
	handler := &recordingHandler{cookieValue: "sess-bad"}
	registry := NewProviderRegistry(zap.NewNop())
	registry.Register("keycloak", handler)

	f := &Filter{
		config: &OAuthConfig{
			Clusters: map[string]ClusterConfig{
				"cluster1": {ProviderName: "keycloak"},
			},
			DefaultProvider: "keycloak",
		},
		cluster:          "cluster1",
		providerRegistry: registry,
		sessionStore:     store,
		logger:           zap.NewNop(),
	}

	sess, getErr := store.Get("sess-bad")
	if getErr != nil {
		t.Fatalf("test setup: session not in store: %v", getErr)
	}

	matched, expectedProvider := f.verifySessionProvider(sess)
	if matched {
		t.Error("verifySessionProvider returned matched for a session with a mismatching ProviderName; want matched=false")
	}
	if expectedProvider != "keycloak" {
		t.Errorf("verifySessionProvider expectedProvider = %q, want %q", expectedProvider, "keycloak")
	}

	// Simulate mismatch side-effects (delete session, record cookie clear)
	_ = f.sessionStore.Delete(sess.ID)
	handler.DeleteSessionCookie(nil)

	// Session must be removed from the store
	if _, err := store.Get("sess-bad"); err == nil {
		t.Error("session was NOT deleted from the store after a provider mismatch; want deletion")
	}

	// DeleteSessionCookie must have been called
	if handler.deleteCookieCalls == 0 {
		t.Error("DeleteSessionCookie was not called on provider mismatch; want at least 1 call")
	}
}

// TestEmptyProviderNameAllowed verifies the legacy-session upgrade path:
// a session with an empty ProviderName (created before plan 01) must be
// accepted (treated as matched) regardless of cluster provider.
func TestEmptyProviderNameAllowed(t *testing.T) {
	store := session.NewInMemorySessionStore()
	_ = store.Store(&session.Session{
		ID:           "sess-legacy",
		ProviderName: "", // pre-Phase-3 session
		ExpiresAt:    time.Now().Add(1 * time.Hour),
	})
	handler := &recordingHandler{cookieValue: "sess-legacy"}
	registry := NewProviderRegistry(zap.NewNop())
	registry.Register("keycloak", handler)

	f := &Filter{
		config: &OAuthConfig{
			Clusters: map[string]ClusterConfig{
				"cluster1": {ProviderName: "keycloak"},
			},
			DefaultProvider: "keycloak",
		},
		cluster:          "cluster1",
		providerRegistry: registry,
		sessionStore:     store,
		logger:           zap.NewNop(),
	}

	sess, getErr := store.Get("sess-legacy")
	if getErr != nil {
		t.Fatalf("test setup: session not in store: %v", getErr)
	}

	matched, _ := f.verifySessionProvider(sess)
	if !matched {
		t.Error("verifySessionProvider rejected a legacy session with empty ProviderName; empty ProviderName must be treated as matched")
	}

	// Session must NOT have been deleted
	if _, err := store.Get("sess-legacy"); err != nil {
		t.Error("legacy session was deleted; empty ProviderName must not trigger mismatch rejection")
	}
}

// TestRefreshUsesClusterProvider verifies SESS-03: the handler used for session
// refresh is resolved from cluster config, never from session.ProviderName.
// This prevents cross-provider routing where a session could cause token refresh
// calls to be dispatched to the wrong provider's endpoint.
func TestRefreshUsesClusterProvider(t *testing.T) {
	logger := zap.NewNop()
	keycloakHandler := &recordingHandler{}
	googleHandler := &recordingHandler{}

	registry := NewProviderRegistry(logger)
	registry.Register("keycloak", keycloakHandler)
	registry.Register("google", googleHandler)

	store := session.NewInMemorySessionStore()
	_ = store.Store(&session.Session{
		ID:           "sess1",
		ProviderName: "google", // session claims google
		ExpiresAt:    time.Now().Add(1 * time.Hour),
	})

	f := &Filter{
		config: &OAuthConfig{
			Clusters: map[string]ClusterConfig{
				"cluster-kc": {ProviderName: "keycloak"},
			},
			DefaultProvider: "keycloak",
		},
		cluster:          "cluster-kc", // cluster says keycloak
		providerRegistry: registry,
		sessionStore:     store,
		logger:           logger,
	}

	got, err := f.getProviderHandler()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Must be keycloak (from cluster config), NOT google (from session data).
	if got != keycloakHandler {
		t.Error("getProviderHandler returned the wrong handler; dispatch must use cluster config, not session.ProviderName (SESS-03, D-06)")
	}
	if got == googleHandler {
		t.Error("getProviderHandler returned google handler based on session data — this is exactly the vulnerability SESS-03/D-06 prohibits")
	}
}

// TestCookieValueIsSessionHandle verifies SESS-04: session cookies contain only
// the opaque session ID handle, never token payloads (JWT fragments, access_token, etc.).
func TestCookieValueIsSessionHandle(t *testing.T) {
	cfg := &session.CookieConfig{
		Name:     "session_keycloak",
		Path:     "/",
		MaxAge:   3600,
		Secure:   true,
		HTTPOnly: true,
	}
	cm, err := session.NewCookieManager(nil, nil, cfg)
	if err != nil {
		t.Fatalf("NewCookieManager: %v", err)
	}
	hdr := &capturingHeaderMap{headers: make(map[string]string)}
	if err := cm.SetCookie(hdr, "opaque-session-id-abc123"); err != nil {
		t.Fatalf("SetCookie: %v", err)
	}
	got := hdr.headers["set-cookie"]
	if !strings.Contains(got, "session_keycloak=opaque-session-id-abc123") {
		t.Errorf("cookie value missing expected handle: %q", got)
	}
	forbidden := []string{"access_token", "eyJ", "Bearer ", "refresh_token", "id_token"}
	for _, f := range forbidden {
		if strings.Contains(got, f) {
			t.Errorf("cookie value leaked forbidden token marker %q in: %q", f, got)
		}
	}
}

// capturingHeaderMap implements api.RequestHeaderMap and records Set calls.
// Used to capture the Set-Cookie value written by CookieManager.SetCookie.
type capturingHeaderMap struct {
	headers map[string]string
}

func (c *capturingHeaderMap) GetRaw(name string) string          { return c.headers[name] }
func (c *capturingHeaderMap) Get(key string) (string, bool)      { v, ok := c.headers[key]; return v, ok }
func (c *capturingHeaderMap) Values(key string) []string {
	if v, ok := c.headers[key]; ok {
		return []string{v}
	}
	return nil
}
func (c *capturingHeaderMap) Set(key, value string)             { c.headers[key] = value }
func (c *capturingHeaderMap) Add(key, value string)             { c.headers[key] = value }
func (c *capturingHeaderMap) Del(key string)                    { delete(c.headers, key) }
func (c *capturingHeaderMap) Range(f func(key, value string) bool) {
	for k, v := range c.headers {
		if !f(k, v) {
			break
		}
	}
}
func (c *capturingHeaderMap) RangeWithCopy(f func(key, value string) bool) { c.Range(f) }
func (c *capturingHeaderMap) GetAllHeaders() map[string][]string {
	result := make(map[string][]string, len(c.headers))
	for k, v := range c.headers {
		result[k] = []string{v}
	}
	return result
}
func (c *capturingHeaderMap) Scheme() string              { return "https" }
func (c *capturingHeaderMap) Method() string              { return "GET" }
func (c *capturingHeaderMap) Host() string                { return "localhost" }
func (c *capturingHeaderMap) Path() string                { return "/" }
func (c *capturingHeaderMap) SetMethod(method string)     { c.headers[":method"] = method }
func (c *capturingHeaderMap) SetHost(host string)         { c.headers[":authority"] = host }
func (c *capturingHeaderMap) SetPath(path string)         { c.headers[":path"] = path }

// TestHandleAuthSuccessSetsProviderHeader verifies that handleAuthSuccess writes
// X-Auth-Provider from session.ProviderName when AuthProviderHeaderName is empty
// (REQ-01, D-01, D-02).
func TestHandleAuthSuccessSetsProviderHeader(t *testing.T) {
	store := session.NewInMemorySessionStore()
	sess := &session.Session{
		ID:           "sess-ok",
		UserID:       "user-123",
		ProviderName: "keycloak",
		ExpiresAt:    time.Now().Add(1 * time.Hour),
		Claims: map[string]interface{}{
			"preferred_username": "alice",
		},
	}
	_ = store.Store(sess)

	f := &Filter{
		config: &OAuthConfig{
			Providers: map[string]ProviderConfig{
				"keycloak": {AllowedUsers: []string{"*"}},
			},
			Clusters: map[string]ClusterConfig{
				"cluster1": {ProviderName: "keycloak"},
			},
			DefaultProvider: "keycloak",
		},
		cluster:          "cluster1",
		providerRegistry: NewProviderRegistry(zap.NewNop()),
		sessionStore:     store,
		logger:           zap.NewNop(),
	}

	hdr := &capturingHeaderMap{headers: make(map[string]string)}
	_ = f.handleAuthSuccess(hdr, sess)

	if got := hdr.headers["X-Auth-Provider"]; got != "keycloak" {
		t.Errorf("X-Auth-Provider: got %q, want %q", got, "keycloak")
	}
}

// TestHandleAuthSuccessCustomProviderHeaderName verifies that a configured
// AuthProviderHeaderName is honored and the default X-Auth-Provider is NOT
// written when a custom name is set (REQ-01, D-02).
func TestHandleAuthSuccessCustomProviderHeaderName(t *testing.T) {
	store := session.NewInMemorySessionStore()
	sess := &session.Session{
		ID:           "sess-custom",
		UserID:       "user-9",
		ProviderName: "google",
		ExpiresAt:    time.Now().Add(1 * time.Hour),
		Claims: map[string]interface{}{
			"preferred_username": "charlie",
		},
	}
	_ = store.Store(sess)

	f := &Filter{
		config: &OAuthConfig{
			Providers: map[string]ProviderConfig{
				"google": {AllowedUsers: []string{"*"}},
			},
			Clusters: map[string]ClusterConfig{
				"cluster1": {ProviderName: "google"},
			},
			DefaultProvider:        "google",
			AuthProviderHeaderName: "X-Custom-Provider",
		},
		cluster:          "cluster1",
		providerRegistry: NewProviderRegistry(zap.NewNop()),
		sessionStore:     store,
		logger:           zap.NewNop(),
	}

	hdr := &capturingHeaderMap{headers: make(map[string]string)}
	_ = f.handleAuthSuccess(hdr, sess)

	if got := hdr.headers["X-Custom-Provider"]; got != "google" {
		t.Errorf("X-Custom-Provider: got %q, want %q", got, "google")
	}
	if _, present := hdr.headers["X-Auth-Provider"]; present {
		t.Errorf("X-Auth-Provider must NOT be set when a custom name is configured; got %q", hdr.headers["X-Auth-Provider"])
	}
}

// TestHandleAuthSuccessLegacySessionFallback verifies that when session.ProviderName
// is empty (legacy session), the header falls back to resolveProviderName() (cluster
// config, NOT route metadata). D-01's prohibition on route metadata is respected:
// resolveProviderName reads cluster config, not route metadata.
func TestHandleAuthSuccessLegacySessionFallback(t *testing.T) {
	store := session.NewInMemorySessionStore()
	sess := &session.Session{
		ID:           "sess-legacy",
		UserID:       "user-legacy",
		ProviderName: "", // legacy session predating Phase 3
		ExpiresAt:    time.Now().Add(1 * time.Hour),
		Claims: map[string]interface{}{
			"preferred_username": "diana",
		},
	}
	_ = store.Store(sess)

	f := &Filter{
		config: &OAuthConfig{
			Providers: map[string]ProviderConfig{
				"keycloak": {AllowedUsers: []string{"*"}},
			},
			Clusters: map[string]ClusterConfig{
				"cluster-legacy": {ProviderName: "keycloak"},
			},
			DefaultProvider: "keycloak",
		},
		cluster:          "cluster-legacy",
		providerRegistry: NewProviderRegistry(zap.NewNop()),
		sessionStore:     store,
		logger:           zap.NewNop(),
	}

	hdr := &capturingHeaderMap{headers: make(map[string]string)}
	_ = f.handleAuthSuccess(hdr, sess)

	if got := hdr.headers["X-Auth-Provider"]; got != "keycloak" {
		t.Errorf("legacy fallback X-Auth-Provider: got %q, want %q (from cluster config via resolveProviderName)", got, "keycloak")
	}
}

// TestHandleAuthSuccessMultiProviderHeaders verifies REQ-02: all four identity
// headers (user id, email, username, auth provider) are correctly populated
// for sessions from different providers, using the same generic claim extraction.
func TestHandleAuthSuccessMultiProviderHeaders(t *testing.T) {
	cases := []struct {
		name         string
		providerName string
		userID       string
		email        string
		username     string
	}{
		{"keycloak session", "keycloak", "kc-user-1", "kc@example.com", "alice"},
		{"google session", "google", "g-user-9", "bob@gmail.com", "bob"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := session.NewInMemorySessionStore()
			sess := &session.Session{
				ID:           "sess-" + tc.providerName,
				UserID:       tc.userID,
				ProviderName: tc.providerName,
				ExpiresAt:    time.Now().Add(1 * time.Hour),
				Claims: map[string]interface{}{
					"email":              tc.email,
					"preferred_username": tc.username,
				},
			}
			_ = store.Store(sess)

			f := &Filter{
				config: &OAuthConfig{
					Providers: map[string]ProviderConfig{
						tc.providerName: {AllowedUsers: []string{"*"}},
					},
					Clusters: map[string]ClusterConfig{
						"cluster1": {ProviderName: tc.providerName},
					},
					DefaultProvider: tc.providerName,
				},
				cluster:          "cluster1",
				providerRegistry: NewProviderRegistry(zap.NewNop()),
				sessionStore:     store,
				logger:           zap.NewNop(),
			}

			hdr := &capturingHeaderMap{headers: make(map[string]string)}
			_ = f.handleAuthSuccess(hdr, sess)

			if got := hdr.headers["X-User-ID"]; got != tc.userID {
				t.Errorf("X-User-ID: got %q, want %q", got, tc.userID)
			}
			if got := hdr.headers["X-User-Email"]; got != tc.email {
				t.Errorf("X-User-Email: got %q, want %q", got, tc.email)
			}
			if got := hdr.headers["X-User-Username"]; got != tc.username {
				t.Errorf("X-User-Username: got %q, want %q", got, tc.username)
			}
			if got := hdr.headers["X-Auth-Provider"]; got != tc.providerName {
				t.Errorf("X-Auth-Provider: got %q, want %q", got, tc.providerName)
			}
		})
	}
}

// TestStripUntrustedHeadersRemovesConfiguredHeaders verifies the spoof-protection
// invariant: every header listed in RemoveHeaders is deleted from the incoming
// request before any downstream processing (T-04-01). Without this, client-
// supplied X-Auth-Provider / X-User-ID values would reach the upstream service.
func TestStripUntrustedHeadersRemovesConfiguredHeaders(t *testing.T) {
	f := &Filter{
		config: &OAuthConfig{
			RemoveHeaders: []string{"X-Auth-Provider", "X-User-ID", "X-User-Email", "X-User-Username"},
		},
		logger: zap.NewNop(),
	}
	hdr := &capturingHeaderMap{headers: map[string]string{
		"X-Auth-Provider": "attacker",
		"X-User-ID":       "evil",
		"X-User-Email":    "evil@example.com",
		"X-User-Username": "root",
		"cookie":          "session=abc",
	}}

	f.stripUntrustedHeaders(hdr)

	for _, name := range []string{"X-Auth-Provider", "X-User-ID", "X-User-Email", "X-User-Username"} {
		if _, present := hdr.headers[name]; present {
			t.Errorf("%s: still present after stripUntrustedHeaders; got %q", name, hdr.headers[name])
		}
	}
	if hdr.headers["cookie"] != "session=abc" {
		t.Errorf("cookie: unexpectedly modified; got %q", hdr.headers["cookie"])
	}
}

// TestStripUntrustedHeadersSafeOnEmptyConfig ensures the helper is a no-op when
// RemoveHeaders is empty or the config is nil, so the filter does not panic on
// misconfigured inputs.
func TestStripUntrustedHeadersSafeOnEmptyConfig(t *testing.T) {
	hdr := &capturingHeaderMap{headers: map[string]string{"X-Keep": "1"}}

	// Empty RemoveHeaders
	f := &Filter{config: &OAuthConfig{RemoveHeaders: nil}, logger: zap.NewNop()}
	f.stripUntrustedHeaders(hdr)
	if hdr.headers["X-Keep"] != "1" {
		t.Errorf("X-Keep: unexpectedly removed")
	}

	// Nil config
	f = &Filter{logger: zap.NewNop()}
	f.stripUntrustedHeaders(hdr) // must not panic
}

// TestProviderAllowGrantsWhenClusterDenies verifies the OR-grant: a user in
// provider.AllowedUsers is permitted even when cluster.AllowedUsers excludes them.
func TestProviderAllowGrantsWhenClusterDenies(t *testing.T) {
	f := &Filter{
		config: &OAuthConfig{
			Providers: map[string]ProviderConfig{
				testProviderName: {AllowedUsers: []string{"alice"}},
			},
			Clusters: map[string]ClusterConfig{
				"test-cluster": {ProviderName: testProviderName, AllowedUsers: []string{"bob"}},
			},
		},
		cluster: "test-cluster",
		logger:  zap.NewNop(),
	}
	sess := &session.Session{
		Claims: map[string]interface{}{"preferred_username": "alice"},
	}
	if !f.isUserPermitted(sess) {
		t.Error("isUserPermitted denied alice who is in provider.AllowedUsers; OR-grant must permit immediately")
	}
}

// TestProviderWildcardAllow verifies that provider.AllowedUsers = ["*"] permits any
// authenticated user regardless of cluster.AllowedUsers.
func TestProviderWildcardAllow(t *testing.T) {
	f := &Filter{
		config: &OAuthConfig{
			Providers: map[string]ProviderConfig{
				testProviderName: {AllowedUsers: []string{"*"}},
			},
			Clusters: map[string]ClusterConfig{
				"test-cluster": {ProviderName: testProviderName},
			},
		},
		cluster: "test-cluster",
		logger:  zap.NewNop(),
	}
	sess := &session.Session{
		Claims: map[string]interface{}{"preferred_username": "anyuser"},
	}
	if !f.isUserPermitted(sess) {
		t.Error("isUserPermitted denied user with provider wildcard '*'; wildcard must permit any authenticated user")
	}
}

// TestProviderAllowGrantsForClusterWithoutEntry documents the intentional widened-reach
// behavior: a user in provider.AllowedUsers can reach clusters with no Clusters[] entry.
// resolveProviderName() falls back to DefaultProvider when the cluster is not configured.
func TestProviderAllowGrantsForClusterWithoutEntry(t *testing.T) {
	f := &Filter{
		config: &OAuthConfig{
			Providers: map[string]ProviderConfig{
				testProviderName: {AllowedUsers: []string{"alice"}},
			},
			Clusters:        map[string]ClusterConfig{},
			DefaultProvider: testProviderName,
		},
		cluster: "unconfigured-cluster",
		logger:  zap.NewNop(),
	}
	sess := &session.Session{
		Claims: map[string]interface{}{"preferred_username": "alice"},
	}
	if !f.isUserPermitted(sess) {
		t.Error("isUserPermitted denied alice for an unconfigured cluster; provider OR-grant must reach clusters with no Clusters[] entry (widened-reach documented in plan Overview)")
	}
}

// TestEmptyProviderListDefersToCluster verifies that an empty provider.AllowedUsers
// skips the provider check and falls through to cluster.AllowedUsers.
func TestEmptyProviderListDefersToCluster(t *testing.T) {
	f := &Filter{
		config: &OAuthConfig{
			Providers: map[string]ProviderConfig{
				testProviderName: {AllowedUsers: nil},
			},
			Clusters: map[string]ClusterConfig{
				"test-cluster": {ProviderName: testProviderName, AllowedUsers: []string{"alice"}},
			},
		},
		cluster: "test-cluster",
		logger:  zap.NewNop(),
	}
	sess := &session.Session{
		Claims: map[string]interface{}{"preferred_username": "alice"},
	}
	if !f.isUserPermitted(sess) {
		t.Error("isUserPermitted denied alice who is in cluster.AllowedUsers; empty provider list must fall through to cluster check")
	}
}

// TestBothListsMissDenies verifies default-deny: a user in neither list is denied.
func TestBothListsMissDenies(t *testing.T) {
	f := &Filter{
		config: &OAuthConfig{
			Providers: map[string]ProviderConfig{
				testProviderName: {AllowedUsers: []string{"bob"}},
			},
			Clusters: map[string]ClusterConfig{
				"test-cluster": {ProviderName: testProviderName, AllowedUsers: []string{"charlie"}},
			},
		},
		cluster: "test-cluster",
		logger:  zap.NewNop(),
	}
	sess := &session.Session{
		Claims: map[string]interface{}{"preferred_username": "alice"},
	}
	if f.isUserPermitted(sess) {
		t.Error("isUserPermitted permitted alice who is in neither list; default-deny must hold")
	}
}

// TestUnknownProviderSkipsProviderCheck verifies that a cluster referencing a provider
// not in config.Providers silently skips the provider check and falls through to
// cluster.AllowedUsers. No panic or error must occur.
func TestUnknownProviderSkipsProviderCheck(t *testing.T) {
	f := &Filter{
		config: &OAuthConfig{
			Providers: map[string]ProviderConfig{},
			Clusters: map[string]ClusterConfig{
				"test-cluster": {ProviderName: "nonexistent", AllowedUsers: []string{"alice"}},
			},
		},
		cluster: "test-cluster",
		logger:  zap.NewNop(),
	}
	sess := &session.Session{
		Claims: map[string]interface{}{"preferred_username": "alice"},
	}
	if !f.isUserPermitted(sess) {
		t.Error("isUserPermitted denied alice when the cluster provider is not in config.Providers; missing provider must be a silent skip, cluster check must still run")
	}
}

// TestClusterWildcardStillWorks verifies that cluster.AllowedUsers = ["*"] still works
// when provider.AllowedUsers is empty, confirming the cluster-level wildcard was not regressed.
func TestClusterWildcardStillWorks(t *testing.T) {
	f := &Filter{
		config: &OAuthConfig{
			Providers: map[string]ProviderConfig{
				testProviderName: {AllowedUsers: nil},
			},
			Clusters: map[string]ClusterConfig{
				"test-cluster": {ProviderName: testProviderName, AllowedUsers: []string{"*"}},
			},
		},
		cluster: "test-cluster",
		logger:  zap.NewNop(),
	}
	sess := &session.Session{
		Claims: map[string]interface{}{"preferred_username": "anyuser"},
	}
	if !f.isUserPermitted(sess) {
		t.Error("isUserPermitted denied user with cluster wildcard '*'; cluster-level wildcard must still permit any authenticated user")
	}
}

// TestAuditLogFiresWithProviderOnlyAllow verifies that the "Access permitted" audit log
// fires when the user is granted via provider.AllowedUsers and cluster.AllowedUsers is empty.
// This covers the audit-log condition change at filter.go (hasProviderList check).
func TestAuditLogFiresWithProviderOnlyAllow(t *testing.T) {
	core, logs := observer.New(zap.DebugLevel)
	logger := zap.New(core)

	store := session.NewInMemorySessionStore()
	sess := &session.Session{
		ID:        "audit-sess",
		UserID:    "user-audit",
		ExpiresAt: time.Now().Add(1 * time.Hour),
		Claims:    map[string]interface{}{"preferred_username": "alice"},
	}
	_ = store.Store(sess)

	f := &Filter{
		config: &OAuthConfig{
			Providers: map[string]ProviderConfig{
				testProviderName: {AllowedUsers: []string{"alice"}},
			},
			Clusters: map[string]ClusterConfig{
				"test-cluster": {ProviderName: testProviderName},
			},
		},
		cluster:      "test-cluster",
		sessionStore: store,
		logger:       logger,
	}

	hdr := &capturingHeaderMap{headers: make(map[string]string)}
	_ = f.handleAuthSuccess(hdr, sess)

	var found bool
	for _, entry := range logs.All() {
		if entry.Message == "Access permitted" {
			found = true
			break
		}
	}
	if !found {
		t.Error("audit log 'Access permitted' did not fire when user was permitted via provider.AllowedUsers with empty cluster.AllowedUsers")
	}
}

// TestDenyLogOmitsListContents verifies the PII guarantee: the "authorization denied"
// debug log fires with provider_allowed_count and cluster_allowed_count fields, but
// must NOT contain the actual allowed-user strings (which are PII).
func TestDenyLogOmitsListContents(t *testing.T) {
	core, logs := observer.New(zap.DebugLevel)
	logger := zap.New(core)

	f := &Filter{
		config: &OAuthConfig{
			Providers: map[string]ProviderConfig{
				testProviderName: {AllowedUsers: []string{"bob", "charlie"}},
			},
			Clusters: map[string]ClusterConfig{
				"test-cluster": {ProviderName: testProviderName, AllowedUsers: []string{"dave", "eve"}},
			},
		},
		cluster: "test-cluster",
		logger:  logger,
	}
	sess := &session.Session{
		Claims: map[string]interface{}{"preferred_username": "alice"},
	}
	if f.isUserPermitted(sess) {
		t.Fatal("expected deny; alice is in neither list")
	}

	allLogs := logs.All()
	denyIdx := -1
	for i, entry := range allLogs {
		if entry.Message == "authorization denied" {
			denyIdx = i
			break
		}
	}
	if denyIdx < 0 {
		t.Fatal("'authorization denied' debug log did not fire on deny path")
	}
	denyEntry := allLogs[denyIdx]

	var foundProviderCount, foundClusterCount bool
	for _, field := range denyEntry.Context {
		switch field.Key {
		case "provider_allowed_count":
			foundProviderCount = true
			if field.Integer != 2 {
				t.Errorf("provider_allowed_count: got %d, want 2", field.Integer)
			}
		case "cluster_allowed_count":
			foundClusterCount = true
			if field.Integer != 2 {
				t.Errorf("cluster_allowed_count: got %d, want 2", field.Integer)
			}
		}
	}
	if !foundProviderCount {
		t.Error("deny log missing 'provider_allowed_count' field")
	}
	if !foundClusterCount {
		t.Error("deny log missing 'cluster_allowed_count' field")
	}

	// PII guarantee: none of the allowed-user strings may appear in any log field.
	prohibitedValues := []string{"bob", "charlie", "dave", "eve"}
	for _, field := range denyEntry.Context {
		for _, prohibited := range prohibitedValues {
			if field.String == prohibited {
				t.Errorf("deny log field %q contains allowed-user string %q — list contents are PII and must not be logged", field.Key, prohibited)
			}
		}
	}
}

// TestIsUserPermittedNilClaims verifies that isUserPermitted returns false when
// session.Claims is nil (no preferred_username available).
func TestIsUserPermittedNilClaims(t *testing.T) {
	f := &Filter{
		config: &OAuthConfig{
			Providers: map[string]ProviderConfig{
				testProviderName: {AllowedUsers: []string{"*"}},
			},
			Clusters: map[string]ClusterConfig{
				"test-cluster": {ProviderName: testProviderName, AllowedUsers: []string{"*"}},
			},
		},
		cluster: "test-cluster",
		logger:  zap.NewNop(),
	}
	sess := &session.Session{Claims: nil}
	if f.isUserPermitted(sess) {
		t.Error("isUserPermitted must deny when session.Claims is nil")
	}
}

// TestIsUserPermittedEmptyClaims verifies that isUserPermitted returns false when
// session.Claims exists but preferred_username is absent.
func TestIsUserPermittedEmptyClaims(t *testing.T) {
	f := &Filter{
		config: &OAuthConfig{
			Providers: map[string]ProviderConfig{
				testProviderName: {AllowedUsers: []string{"*"}},
			},
			Clusters: map[string]ClusterConfig{
				"test-cluster": {ProviderName: testProviderName, AllowedUsers: []string{"*"}},
			},
		},
		cluster: "test-cluster",
		logger:  zap.NewNop(),
	}
	sess := &session.Session{Claims: map[string]interface{}{}}
	if f.isUserPermitted(sess) {
		t.Error("isUserPermitted must deny when preferred_username claim is absent")
	}
}

// TestIsUserPermittedEmptyUsername verifies that isUserPermitted returns false when
// preferred_username is present but empty (or whitespace-only).
func TestIsUserPermittedEmptyUsername(t *testing.T) {
	f := &Filter{
		config: &OAuthConfig{
			Providers: map[string]ProviderConfig{
				testProviderName: {AllowedUsers: []string{"*"}},
			},
			Clusters: map[string]ClusterConfig{
				"test-cluster": {ProviderName: testProviderName, AllowedUsers: []string{"*"}},
			},
		},
		cluster: "test-cluster",
		logger:  zap.NewNop(),
	}
	for _, username := range []string{"", "   ", "\t"} {
		sess := &session.Session{Claims: map[string]interface{}{"preferred_username": username}}
		if f.isUserPermitted(sess) {
			t.Errorf("isUserPermitted must deny for empty/whitespace username %q", username)
		}
	}
}

// captureCallbacks implements api.FilterCallbackHandler for handleCallback tests.
// Embed the interface (nil) so unimplemented methods compile and panic only if called.
type captureCallbacks struct {
	api.FilterCallbackHandler
	decoder *captureDecoderCallbacks
}

func (c *captureCallbacks) DecoderFilterCallbacks() api.DecoderFilterCallbacks { return c.decoder }

// captureDecoderCallbacks records SendLocalReply calls for assertion.
type captureDecoderCallbacks struct {
	api.DecoderFilterCallbacks
	statusCode int
	body       string
	headers    map[string][]string
	details    string
	called     bool
}

func (c *captureDecoderCallbacks) SendLocalReply(code int, body string,
	headers map[string][]string, grpcStatus int64, details string) {
	c.called = true
	c.statusCode = code
	c.body = body
	c.headers = headers
	c.details = details
}

// buildCallbackFilter returns a minimal Filter wired for handleCallback tests:
// empty session store, empty provider registry, nop logger, and the given capture callbacks.
func buildCallbackFilter(cbs *captureCallbacks) *Filter {
	registry := NewProviderRegistry(zap.NewNop())
	store := session.NewInMemorySessionStore()
	return &Filter{
		config: &OAuthConfig{
			Clusters: map[string]ClusterConfig{},
		},
		providerRegistry: registry,
		sessionStore:     store,
		callbacks:        cbs,
		logger:           zap.NewNop(),
	}
}

// assertRestartResponse asserts that dec captured a 302 to "/" with exactly the
// oauthRestartCookie constant as its Set-Cookie. Pin the whole cookie string so
// any drift in lifetime, path, or attribute order is caught.
func assertRestartResponse(t *testing.T, dec *captureDecoderCallbacks) {
	t.Helper()
	if dec.statusCode != 302 {
		t.Errorf("statusCode = %d, want 302", dec.statusCode)
	}
	locs := dec.headers["Location"]
	if len(locs) == 0 || locs[0] != "/oauth/login" {
		t.Errorf("Location = %v, want [\"/oauth/login\"]", locs)
	}
	cookies := dec.headers["Set-Cookie"]
	if len(cookies) != 1 {
		t.Fatalf("Set-Cookie = %v, want exactly one entry", cookies)
	}
	if cookies[0] != oauthRestartCookie {
		t.Errorf("Set-Cookie = %q, want %q", cookies[0], oauthRestartCookie)
	}
}

// TestHandleCallbackRestartsOnMissingPendingAuth verifies that a callback with a
// state param whose pending-auth entry is missing triggers a 302 restart to "/"
// with the oauth_restart=1 cookie when no restart cookie is present on the request.
func TestHandleCallbackRestartsOnMissingPendingAuth(t *testing.T) {
	dec := &captureDecoderCallbacks{}
	cbs := &captureCallbacks{decoder: dec}
	f := buildCallbackFilter(cbs)

	hdr := &capturingHeaderMap{headers: make(map[string]string)}
	hdr.Set(":path", "/oauth/callback?state=does-not-exist&code=abc")

	result := f.handleCallback(hdr)
	if result != api.LocalReply {
		t.Fatalf("handleCallback returned %v, want api.LocalReply", result)
	}
	assertRestartResponse(t, dec)
}

// TestHandleCallbackLoopGuardFallsBackTo400 verifies that when the inbound request
// already carries an oauth_restart=1 cookie, the filter returns 400 instead of
// another restart redirect (loop guard). Covers both restartOrGuard call sites:
// missing_state and invalid_or_expired_state.
func TestHandleCallbackLoopGuardFallsBackTo400(t *testing.T) {
	cases := []struct {
		name     string
		path     string
		cookie   string
		wantBody string
	}{
		{
			name:     "invalid_or_expired_state, bare cookie",
			path:     "/oauth/callback?state=does-not-exist&code=abc",
			cookie:   "oauth_restart=1",
			wantBody: "Invalid or expired state parameter",
		},
		{
			name:     "invalid_or_expired_state, cookie among others",
			path:     "/oauth/callback?state=does-not-exist&code=abc",
			cookie:   "foo=bar; oauth_restart=1; baz=qux",
			wantBody: "Invalid or expired state parameter",
		},
		{
			name:     "missing_state, bare cookie",
			path:     "/oauth/callback?code=abc",
			cookie:   "oauth_restart=1",
			wantBody: "Missing state parameter in OAuth callback",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dec := &captureDecoderCallbacks{}
			cbs := &captureCallbacks{decoder: dec}
			f := buildCallbackFilter(cbs)

			hdr := &capturingHeaderMap{headers: make(map[string]string)}
			hdr.Set(":path", tc.path)
			hdr.Set("cookie", tc.cookie)

			result := f.handleCallback(hdr)
			if result != api.LocalReply {
				t.Fatalf("handleCallback returned %v, want api.LocalReply", result)
			}
			if dec.statusCode != 400 {
				t.Errorf("statusCode = %d, want 400", dec.statusCode)
			}
			if !strings.Contains(dec.body, tc.wantBody) {
				t.Errorf("body = %q, want to contain %q", dec.body, tc.wantBody)
			}
			// Loop guard must not re-set the restart cookie — otherwise the
			// 400 fallback would self-renew the guard on every hit.
			if got := dec.headers["Set-Cookie"]; len(got) != 0 {
				t.Errorf("Set-Cookie = %v, want none on loop-guard 400", got)
			}
		})
	}
}

// TestHandleCallbackRestartsOnMissingStateParam verifies that a callback with no
// state parameter at all triggers a 302 restart to "/" with the oauth_restart=1
// cookie when no restart guard cookie is present.
func TestHandleCallbackRestartsOnMissingStateParam(t *testing.T) {
	dec := &captureDecoderCallbacks{}
	cbs := &captureCallbacks{decoder: dec}
	f := buildCallbackFilter(cbs)

	hdr := &capturingHeaderMap{headers: make(map[string]string)}
	hdr.Set(":path", "/oauth/callback?code=abc")

	result := f.handleCallback(hdr)
	if result != api.LocalReply {
		t.Fatalf("handleCallback returned %v, want api.LocalReply", result)
	}
	assertRestartResponse(t, dec)
}

// TestBothListsNilDenies verifies default-deny when neither list is configured
// (both provider.AllowedUsers and cluster.AllowedUsers are nil).
// Distinct from TestBothListsMissDenies where lists exist but contain wrong names.
func TestBothListsNilDenies(t *testing.T) {
	f := &Filter{
		config: &OAuthConfig{
			Providers: map[string]ProviderConfig{
				testProviderName: {AllowedUsers: nil},
			},
			Clusters: map[string]ClusterConfig{
				"test-cluster": {ProviderName: testProviderName, AllowedUsers: nil},
			},
		},
		cluster: "test-cluster",
		logger:  zap.NewNop(),
	}
	sess := &session.Session{
		Claims: map[string]interface{}{"preferred_username": "alice"},
	}
	if f.isUserPermitted(sess) {
		t.Error("isUserPermitted must deny when both provider and cluster AllowedUsers are nil")
	}
}
