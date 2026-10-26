package filter

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/envoyproxy/envoy/contrib/golang/common/go/api"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rashpile/go-envoy-oauth/plugin/metrics"
	"github.com/rashpile/go-envoy-oauth/plugin/oauth"
	"github.com/rashpile/go-envoy-oauth/plugin/session"
)

const testMCPResource = "https://romanian.example/mcp"

func testMCPConfig(t *testing.T) *MCPConfig {
	t.Helper()
	mcp, err := parseMCPConfig(map[string]interface{}{"path": "/mcp", "resource": testMCPResource})
	if err != nil {
		t.Fatalf("parseMCPConfig: %v", err)
	}
	return mcp
}

// newMCPTestFilter returns a DecodeHeaders-ready filter with cluster "pack"
// carrying an mcp block and provider "keycloak" registered with h.
func newMCPTestFilter(t *testing.T, h *recordingHandler) (*Filter, *captureDecoderCallbacks) {
	t.Helper()
	dec := &captureDecoderCallbacks{}
	f := buildCallbackFilter(&captureCallbacks{decoder: dec, cluster: "pack"})
	f.providerRegistry.Register("keycloak", h)
	f.config.DefaultProvider = "keycloak"
	f.config.Providers = map[string]ProviderConfig{
		"keycloak": {IssuerURL: "https://sso.example/realms/pl"},
	}
	f.config.Clusters["pack"] = ClusterConfig{ProviderName: "keycloak", MCP: testMCPConfig(t)}
	return f, dec
}

func TestMCPMetadataReply(t *testing.T) {
	mcp := testMCPConfig(t)

	status, body, headers := mcpMetadataReply("GET", mcp, "https://sso.example/realms/pl")
	if status != 200 {
		t.Fatalf("status = %d, want 200", status)
	}
	var doc map[string]interface{}
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		t.Fatalf("body is not JSON: %v (%q)", err, body)
	}
	want := map[string]interface{}{
		"resource":                 testMCPResource,
		"authorization_servers":    []interface{}{"https://sso.example/realms/pl"},
		"bearer_methods_supported": []interface{}{"header"},
	}
	gotJSON, _ := json.Marshal(doc)
	wantJSON, _ := json.Marshal(want)
	if string(gotJSON) != string(wantJSON) {
		t.Errorf("body = %s, want %s", gotJSON, wantJSON)
	}
	if got := headers["content-type"]; len(got) != 1 || got[0] != "application/json" {
		t.Errorf("content-type = %v, want application/json", got)
	}
	if got := headers["cache-control"]; len(got) != 1 || got[0] != "public, max-age=3600" {
		t.Errorf("cache-control = %v", got)
	}

	for _, method := range []string{"POST", "HEAD"} {
		status, _, headers := mcpMetadataReply(method, mcp, "https://sso.example/realms/pl")
		if status != 405 {
			t.Errorf("%s: status = %d, want 405", method, status)
		}
		if got := headers["allow"]; len(got) != 1 || got[0] != "GET" {
			t.Errorf("%s: allow = %v, want GET", method, got)
		}
	}
}

func TestMCPIssuer(t *testing.T) {
	f, _ := newMCPTestFilter(t, &recordingHandler{})
	f.cluster = "pack"
	if got := f.mcpIssuer(); got != "https://sso.example/realms/pl" {
		t.Errorf("provider registry config: issuer = %q, want the cluster provider's issuer", got)
	}

	// Legacy single-provider config: no providers map, top-level issuer_url.
	f.config.Providers = nil
	f.config.IssuerURL = "https://legacy.example/realms/pl"
	if got := f.mcpIssuer(); got != "https://legacy.example/realms/pl" {
		t.Errorf("legacy config: issuer = %q, want the top-level issuer", got)
	}
}

func TestDecodeHeadersServesMCPMetadata(t *testing.T) {
	const metadataPath = "/.well-known/oauth-protected-resource/mcp"

	t.Run("served without a token", func(t *testing.T) {
		h := &recordingHandler{}
		f, dec := newMCPTestFilter(t, h)
		hdr := &capturingHeaderMap{headers: map[string]string{":path": metadataPath, ":method": "GET"}}

		if result := f.DecodeHeaders(hdr, true); result != api.LocalReply {
			t.Fatalf("DecodeHeaders = %v, want LocalReply", result)
		}
		if dec.statusCode != 200 {
			t.Errorf("status = %d, want 200", dec.statusCode)
		}
		if h.getSessionCookieCalls != 0 {
			t.Errorf("GetSessionCookie calls = %d, want 0", h.getSessionCookieCalls)
		}
	})

	t.Run("served even when exclude_paths matches", func(t *testing.T) {
		f, dec := newMCPTestFilter(t, &recordingHandler{})
		cc := f.config.Clusters["pack"]
		cc.ExcludePaths = []string{"/.well-known"}
		f.config.Clusters["pack"] = cc
		hdr := &capturingHeaderMap{headers: map[string]string{":path": metadataPath, ":method": "GET"}}

		if result := f.DecodeHeaders(hdr, true); result != api.LocalReply || dec.statusCode != 200 {
			t.Errorf("DecodeHeaders = %v status %d, want LocalReply 200", result, dec.statusCode)
		}
	})

	t.Run("cluster without mcp keeps old behavior", func(t *testing.T) {
		h := &recordingHandler{}
		f, dec := newMCPTestFilter(t, h)
		f.config.Clusters["pack"] = ClusterConfig{ProviderName: "keycloak"}
		hdr := &capturingHeaderMap{headers: map[string]string{":path": metadataPath, ":method": "GET"}}

		f.DecodeHeaders(hdr, true)
		if dec.statusCode != 401 {
			t.Errorf("status = %d, want 401 from normal auth", dec.statusCode)
		}
		if h.getSessionCookieCalls != 1 {
			t.Errorf("GetSessionCookie calls = %d, want 1 (normal session auth)", h.getSessionCookieCalls)
		}
	})
}

// mcpStubHandler returns a fixed resource-token result and counts the calls
// that must never happen on the MCP path.
type mcpStubHandler struct {
	mockOAuthHandler
	sess                  *session.Session
	err                   error
	resource              string
	validateCalls         int
	getSessionCookieCalls int
	exchangeCalls         int
}

func (m *mcpStubHandler) ValidateBearerTokenForResource(_ context.Context, _, resource string) (*session.Session, error) {
	m.validateCalls++
	m.resource = resource
	return m.sess, m.err
}

func (m *mcpStubHandler) GetSessionCookie(_ api.RequestHeaderMap) (string, error) {
	m.getSessionCookieCalls++
	return "", errors.New("no cookie")
}

func (m *mcpStubHandler) ExchangeRefreshToken(_ context.Context, _ string) (string, error) {
	m.exchangeCalls++
	return "", errors.New("refused")
}

func aliceSession() *session.Session {
	return &session.Session{
		ID:           "s1",
		UserID:       "user-1",
		ProviderName: "keycloak",
		Token:        "tok",
		ExpiresAt:    time.Now().Add(time.Hour),
		Claims:       map[string]interface{}{"preferred_username": "alice", "email": "alice@example.com"},
	}
}

// newMCPGuardFilter is newMCPTestFilter with an mcpStubHandler and alice allowed.
func newMCPGuardFilter(t *testing.T, h oauth.OAuthHandler) (*Filter, *captureDecoderCallbacks) {
	t.Helper()
	dec := &captureDecoderCallbacks{}
	f := buildCallbackFilter(&captureCallbacks{decoder: dec, cluster: "pack"})
	f.providerRegistry.Register("keycloak", h)
	f.config.DefaultProvider = "keycloak"
	f.config.IssuerURL = "https://sso.example/realms/pl"
	f.config.Providers = map[string]ProviderConfig{
		"keycloak": {IssuerURL: "https://sso.example/realms/pl"},
	}
	f.config.Clusters["pack"] = ClusterConfig{
		ProviderName: "keycloak",
		AllowedUsers: []string{"alice"},
		MCP:          testMCPConfig(t),
	}
	return f, dec
}

func TestMCPChallengeHeaders(t *testing.T) {
	const url = "https://romanian.example/.well-known/oauth-protected-resource/mcp"
	got := mcpChallengeHeaders(url, false)["www-authenticate"]
	if len(got) != 1 || got[0] != `Bearer resource_metadata="`+url+`"` {
		t.Errorf("no token: www-authenticate = %v", got)
	}
	got = mcpChallengeHeaders(url, true)["www-authenticate"]
	if len(got) != 1 || got[0] != `Bearer resource_metadata="`+url+`", error="invalid_token"` {
		t.Errorf("token sent: www-authenticate = %v", got)
	}
}

func TestMatchesMCPPath(t *testing.T) {
	mcp := testMCPConfig(t)
	cases := map[string]bool{
		"/mcp":           true,
		"/mcp?x=1":       true,
		"/mcp/":          true,
		"/mcp/sub":       true,
		"/mcp;x":         false, // ambiguous: rejected, never authenticated
		"/mcp%2fsub":     false,
		"/mcp/..;/admin": false,
		"/mcpx":          false,
		"/other":         false,
		"/":              false,
		"/api/mcp":       false,
		"/mcpx?next=/mc": false,
	}
	for path, want := range cases {
		if got := matchesMCPPath(path, mcp); got != want {
			t.Errorf("matchesMCPPath(%q) = %v, want %v", path, got, want)
		}
	}
}

func TestDecodeHeadersMCPGuard(t *testing.T) {
	const metadataURL = "https://romanian.example/.well-known/oauth-protected-resource/mcp"
	challenge := `Bearer resource_metadata="` + metadataURL + `"`
	invalidChallenge := challenge + `, error="invalid_token"`

	cases := []struct {
		name          string
		path          string
		headers       map[string]string
		handler       *mcpStubHandler
		configure     func(f *Filter)
		wantResult    api.StatusType
		wantStatus    int
		wantChallenge string // "" means no www-authenticate expected
		wantValidate  int
	}{
		{
			name:          "no token",
			headers:       map[string]string{"accept": "application/json"},
			handler:       &mcpStubHandler{},
			wantResult:    api.LocalReply,
			wantStatus:    401,
			wantChallenge: challenge,
		},
		{
			name:          "browser without token gets 401, not a redirect",
			headers:       map[string]string{"accept": "text/html"},
			handler:       &mcpStubHandler{},
			wantResult:    api.LocalReply,
			wantStatus:    401,
			wantChallenge: challenge,
		},
		{
			name:          "invalid or foreign-aud token",
			headers:       map[string]string{"authorization": "Bearer bad"},
			handler:       &mcpStubHandler{err: errors.New("aud mismatch")},
			wantResult:    api.LocalReply,
			wantStatus:    401,
			wantChallenge: invalidChallenge,
			wantValidate:  1,
		},
		{
			name:          "session cookie is ignored",
			headers:       map[string]string{"cookie": "session=s1"},
			handler:       &mcpStubHandler{sess: aliceSession()},
			wantResult:    api.LocalReply,
			wantStatus:    401,
			wantChallenge: challenge,
		},
		{
			name:    "api-key is ignored",
			headers: map[string]string{"api-key": "refresh-token"},
			handler: &mcpStubHandler{sess: aliceSession()},
			configure: func(f *Filter) {
				f.config.EnableAPIKey = true
				f.config.EnableBearerToken = true
			},
			wantResult:    api.LocalReply,
			wantStatus:    401,
			wantChallenge: challenge,
		},
		{
			name:    "user not in allowed_users",
			headers: map[string]string{"authorization": "Bearer ok", "accept": "text/html"},
			handler: &mcpStubHandler{sess: aliceSession()},
			configure: func(f *Filter) {
				cc := f.config.Clusters["pack"]
				cc.AllowedUsers = []string{"bob"}
				f.config.Clusters["pack"] = cc
			},
			wantResult:   api.LocalReply,
			wantStatus:   403,
			wantValidate: 1,
		},
		{
			name:    "exclude_paths cannot open /mcp",
			headers: map[string]string{},
			handler: &mcpStubHandler{},
			configure: func(f *Filter) {
				cc := f.config.Clusters["pack"]
				cc.ExcludePaths = []string{"/mcp"}
				f.config.Clusters["pack"] = cc
			},
			wantResult:    api.LocalReply,
			wantStatus:    401,
			wantChallenge: challenge,
		},
		{
			name:         "valid token",
			headers:      map[string]string{"authorization": "Bearer ok"},
			handler:      &mcpStubHandler{sess: aliceSession()},
			wantResult:   api.Continue,
			wantValidate: 1,
		},
		{
			name:         "valid token on a subpath",
			path:         "/mcp/messages?session=1",
			headers:      map[string]string{"authorization": "Bearer ok"},
			handler:      &mcpStubHandler{sess: aliceSession()},
			wantResult:   api.Continue,
			wantValidate: 1,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, dec := newMCPGuardFilter(t, tc.handler)
			if tc.configure != nil {
				tc.configure(f)
			}
			path := tc.path
			if path == "" {
				path = "/mcp"
			}
			hdr := &capturingHeaderMap{headers: map[string]string{":path": path, ":method": "POST"}}
			for k, v := range tc.headers {
				hdr.headers[k] = v
			}

			if result := f.DecodeHeaders(hdr, true); result != tc.wantResult {
				t.Fatalf("DecodeHeaders = %v, want %v (status %d)", result, tc.wantResult, dec.statusCode)
			}
			if tc.wantResult == api.LocalReply && dec.statusCode != tc.wantStatus {
				t.Errorf("status = %d, want %d", dec.statusCode, tc.wantStatus)
			}
			if tc.wantResult == api.LocalReply {
				got := dec.headers["www-authenticate"]
				if tc.wantChallenge == "" && len(got) != 0 {
					t.Errorf("www-authenticate = %v, want none", got)
				}
				if tc.wantChallenge != "" && (len(got) != 1 || got[0] != tc.wantChallenge) {
					t.Errorf("www-authenticate = %v, want %q", got, tc.wantChallenge)
				}
				if _, ok := dec.headers["Location"]; ok {
					t.Errorf("MCP must never redirect, got Location %v", dec.headers["Location"])
				}
			}
			if tc.handler.validateCalls != tc.wantValidate {
				t.Errorf("ValidateBearerTokenForResource calls = %d, want %d", tc.handler.validateCalls, tc.wantValidate)
			}
			if tc.wantValidate > 0 && tc.handler.resource != testMCPResource {
				t.Errorf("validated against %q, want %q", tc.handler.resource, testMCPResource)
			}
			if tc.handler.getSessionCookieCalls != 0 || tc.handler.exchangeCalls != 0 {
				t.Errorf("cookie lookups = %d, api-key exchanges = %d, want 0 on /mcp",
					tc.handler.getSessionCookieCalls, tc.handler.exchangeCalls)
			}
			if tc.wantResult == api.Continue {
				if got, _ := hdr.Get("X-User-Username"); got != "alice" {
					t.Errorf("X-User-Username = %q, want alice", got)
				}
				if got, _ := hdr.Get("X-User-ID"); got != "user-1" {
					t.Errorf("X-User-ID = %q, want user-1", got)
				}
			}
		})
	}
}

func TestDecodeHeadersMCPProviderDown(t *testing.T) {
	f, dec := newMCPGuardFilter(t, &oauth.DownHandler{ProviderName: "keycloak"})
	hdr := &capturingHeaderMap{headers: map[string]string{":path": "/mcp", "authorization": "Bearer ok"}}

	if result := f.DecodeHeaders(hdr, true); result != api.LocalReply || dec.statusCode != 503 {
		t.Fatalf("DecodeHeaders = %v status %d, want LocalReply 503", result, dec.statusCode)
	}
	if got := dec.headers["www-authenticate"]; len(got) != 0 {
		t.Errorf("www-authenticate = %v, want none on 503", got)
	}
}

func TestDecodeHeadersMCPOtherPathUnchanged(t *testing.T) {
	h := &mcpStubHandler{}
	f, dec := newMCPGuardFilter(t, h)
	hdr := &capturingHeaderMap{headers: map[string]string{":path": "/lessons", "accept": "application/json"}}

	f.DecodeHeaders(hdr, true)
	if dec.statusCode != 401 {
		t.Errorf("status = %d, want 401 from normal auth", dec.statusCode)
	}
	if got := dec.headers["www-authenticate"]; len(got) != 1 || got[0] != "Bearer" {
		t.Errorf("www-authenticate = %v, want the plain Bearer challenge", got)
	}
	if h.getSessionCookieCalls != 1 || h.validateCalls != 0 {
		t.Errorf("cookie lookups = %d, resource validations = %d, want 1 and 0", h.getSessionCookieCalls, h.validateCalls)
	}
}

// clusterAuthCount returns envoy_oauth_cluster_auth_total for cluster and result.
func clusterAuthCount(t *testing.T, reg *prometheus.Registry, cluster, result string) float64 {
	t.Helper()
	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	var total float64
	for _, mf := range families {
		if mf.GetName() != "envoy_oauth_cluster_auth_total" {
			continue
		}
		for _, m := range mf.GetMetric() {
			labels := map[string]string{}
			for _, lp := range m.GetLabel() {
				labels[lp.GetName()] = lp.GetValue()
			}
			if labels["cluster"] == cluster && labels["result"] == result {
				total += m.GetCounter().GetValue()
			}
		}
	}
	return total
}

func TestDecodeHeadersMCPClusterAuthMetrics(t *testing.T) {
	reg := prometheus.NewRegistry()
	metrics.RegisterAuthMetrics(reg)

	run := func(h oauth.OAuthHandler, headers map[string]string) {
		f, _ := newMCPGuardFilter(t, h)
		hdr := &capturingHeaderMap{headers: map[string]string{":path": "/mcp"}}
		for k, v := range headers {
			hdr.headers[k] = v
		}
		f.DecodeHeaders(hdr, true)
	}

	run(&mcpStubHandler{}, nil)
	run(&mcpStubHandler{err: errors.New("bad")}, map[string]string{"authorization": "Bearer bad"})
	run(&oauth.DownHandler{ProviderName: "keycloak"}, map[string]string{"authorization": "Bearer ok"})
	if got := clusterAuthCount(t, reg, "pack", "failure"); got != 3 {
		t.Errorf("failure count = %v, want 3 (no token, invalid token, provider down)", got)
	}

	run(&mcpStubHandler{sess: aliceSession()}, map[string]string{"authorization": "Bearer ok"})
	if got := clusterAuthCount(t, reg, "pack", "success"); got != 1 {
		t.Errorf("success count = %v, want 1", got)
	}
}

func TestIsAmbiguousMCPPath(t *testing.T) {
	mcp := testMCPConfig(t)
	cases := map[string]bool{
		"/mcp;x":            true,
		"/mcp/..;/admin":    true,
		"/mcpadmin;x":       true,
		"/mcp%2f..%2fadmin": true,
		"/mcp//sub":         true,
		"/mcp":              false,
		"/mcp/sub":          false,
		"/mcp?next=/a/../b": false,
		"/other;x":          false,
		"/api/mcp;x":        false,
	}
	for path, want := range cases {
		if got := isAmbiguousMCPPath(path, mcp); got != want {
			t.Errorf("isAmbiguousMCPPath(%q) = %v, want %v", path, got, want)
		}
	}
}

// TestDecodeHeadersMCPAmbiguousPathRejected verifies that paths an upstream
// may normalize to something other than the MCP endpoint are refused, never
// authenticated with an MCP token and forwarded.
func TestDecodeHeadersMCPAmbiguousPathRejected(t *testing.T) {
	for _, path := range []string{"/mcp;x", "/mcp/..;/admin", "/mcpadmin;x", "/mcp%2f..%2fadmin"} {
		t.Run(path, func(t *testing.T) {
			h := &mcpStubHandler{sess: aliceSession()}
			f, dec := newMCPGuardFilter(t, h)
			hdr := &capturingHeaderMap{headers: map[string]string{":path": path, "authorization": "Bearer ok"}}

			if result := f.DecodeHeaders(hdr, true); result != api.LocalReply || dec.statusCode != 400 {
				t.Fatalf("DecodeHeaders = %v status %d, want LocalReply 400", result, dec.statusCode)
			}
			if h.validateCalls != 0 || h.getSessionCookieCalls != 0 {
				t.Errorf("token validations = %d, cookie lookups = %d, want 0", h.validateCalls, h.getSessionCookieCalls)
			}
		})
	}
}
