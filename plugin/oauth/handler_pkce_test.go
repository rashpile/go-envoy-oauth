package oauth

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/rashpile/go-envoy-oauth/plugin/session"
	"go.uber.org/zap"
)

// mockHeaderMap implements api.RequestHeaderMap for testing.
type mockHeaderMap struct {
	headers map[string]string
}

func newMockHeaderMap() *mockHeaderMap {
	return &mockHeaderMap{headers: make(map[string]string)}
}

// HeaderMap interface methods
func (m *mockHeaderMap) GetRaw(name string) string {
	return m.headers[name]
}

func (m *mockHeaderMap) Get(key string) (string, bool) {
	v, ok := m.headers[key]
	return v, ok
}

func (m *mockHeaderMap) Values(key string) []string {
	if v, ok := m.headers[key]; ok {
		return []string{v}
	}
	return nil
}

func (m *mockHeaderMap) Set(key, value string) {
	m.headers[key] = value
}

func (m *mockHeaderMap) Add(key, value string) {
	m.headers[key] = value
}

func (m *mockHeaderMap) Del(key string) {
	delete(m.headers, key)
}

func (m *mockHeaderMap) Range(f func(key, value string) bool) {
	for k, v := range m.headers {
		if !f(k, v) {
			break
		}
	}
}

func (m *mockHeaderMap) RangeWithCopy(f func(key, value string) bool) {
	m.Range(f)
}

func (m *mockHeaderMap) GetAllHeaders() map[string][]string {
	result := make(map[string][]string, len(m.headers))
	for k, v := range m.headers {
		result[k] = []string{v}
	}
	return result
}

// RequestHeaderMap-specific methods
func (m *mockHeaderMap) Scheme() string {
	if v, ok := m.headers["x-forwarded-proto"]; ok {
		return v
	}
	return "http"
}

func (m *mockHeaderMap) Method() string {
	if v, ok := m.headers[":method"]; ok {
		return v
	}
	return "GET"
}

func (m *mockHeaderMap) Host() string {
	if v, ok := m.headers[":authority"]; ok {
		return v
	}
	return "localhost"
}

func (m *mockHeaderMap) Path() string {
	if v, ok := m.headers[":path"]; ok {
		return v
	}
	return "/"
}

func (m *mockHeaderMap) SetMethod(method string) {
	m.headers[":method"] = method
}

func (m *mockHeaderMap) SetHost(host string) {
	m.headers[":authority"] = host
}

func (m *mockHeaderMap) SetPath(path string) {
	m.headers[":path"] = path
}

// newTestOIDCServer starts an httptest server that handles:
//   - /.well-known/openid-configuration (OIDC discovery)
//   - /token (token endpoint — returns a fake JWT)
//   - /userinfo (user info endpoint)
//
// If wantIssuerMismatch is true the token endpoint returns an id_token
// whose iss claim does not match the server's base URL.
func newTestOIDCServer(t *testing.T, wantIssuerMismatch bool) *httptest.Server {
	t.Helper()

	var srv *httptest.Server
	mux := http.NewServeMux()

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		base := srv.URL
		config := map[string]interface{}{
			"issuer":                 base,
			"authorization_endpoint": base + "/auth",
			"token_endpoint":         base + "/token",
			"userinfo_endpoint":      base + "/userinfo",
			"jwks_uri":               base + "/jwks",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(config)
	})

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		// Build a minimal fake JWT with the iss claim.
		// JWT structure: base64(header).base64(payload).base64(sig)
		issuer := srv.URL
		if wantIssuerMismatch {
			issuer = "https://evil-issuer.example.com"
		}

		payload := map[string]interface{}{
			"iss": issuer,
			"sub": "test-user",
			"exp": time.Now().Add(1 * time.Hour).Unix(),
			"aud": "test-client",
		}
		payloadBytes, _ := json.Marshal(payload)
		idToken := fakeJWT(payloadBytes)

		resp := map[string]interface{}{
			"access_token":  "fake-access-token",
			"token_type":    "Bearer",
			"expires_in":    3600,
			"refresh_token": "fake-refresh-token",
			"id_token":      idToken,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"sub":   "test-user",
			"email": "test@example.com",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// fakeJWT builds a minimal unsigned JWT (header.payload.sig) from a JSON payload.
func fakeJWT(payloadJSON []byte) string {
	header := base64RawURL([]byte(`{"alg":"none"}`))
	payload := base64RawURL(payloadJSON)
	return header + "." + payload + ".fakesig"
}

// base64RawURL encodes bytes using base64 URL-safe encoding without padding.
// This is a minimal implementation to avoid importing encoding/base64 in tests.
func base64RawURL(b []byte) string {
	const enc = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	var result []byte
	for i := 0; i < len(b); i += 3 {
		var chunk [3]byte
		n := copy(chunk[:], b[i:])
		result = append(result, enc[chunk[0]>>2])
		result = append(result, enc[((chunk[0]&3)<<4)|chunk[1]>>4])
		if n >= 2 {
			result = append(result, enc[((chunk[1]&15)<<2)|chunk[2]>>6])
		}
		if n == 3 {
			result = append(result, enc[chunk[2]&63])
		}
	}
	return string(result)
}

// newTestHandler creates an OAuthHandlerImpl connected to the given test server.
func newTestHandler(t *testing.T, srv *httptest.Server, providerName string) *OAuthHandlerImpl {
	t.Helper()
	store := session.NewInMemorySessionStore()
	logger, _ := zap.NewDevelopment()

	cookieConfig := &session.CookieConfig{
		Name:     "session",
		Path:     "/",
		Secure:   false,
		HTTPOnly: true,
	}
	cm, err := session.NewCookieManager(nil, nil, cookieConfig)
	if err != nil {
		t.Fatalf("NewCookieManager: %v", err)
	}

	cfg := &OIDCConfig{
		ProviderName: providerName,
		IssuerURL:    srv.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		RedirectURL:  "http://localhost/oauth/callback",
		Scopes:       []string{"openid"},
	}

	h, err := NewOAuthHandler(cfg, store, cm, logger)
	if err != nil {
		t.Fatalf("NewOAuthHandler: %v", err)
	}
	return h.(*OAuthHandlerImpl)
}

// TestNormalizeIssuer verifies normalizeIssuer strips trailing slashes and lowercases.
func TestNormalizeIssuer(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"https://issuer.example.com/", "https://issuer.example.com"},
		{"HTTPS://Issuer.Example.COM", "https://issuer.example.com"},
		{"https://issuer.example.com", "https://issuer.example.com"},
		{"https://issuer.example.com///", "https://issuer.example.com"},
	}
	for _, tc := range cases {
		got := normalizeIssuer(tc.input)
		if got != tc.want {
			t.Errorf("normalizeIssuer(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

// TestPKCEAuthRedirect verifies HandleAuthRedirect uses pure nonce state and PKCE.
func TestPKCEAuthRedirect(t *testing.T) {
	srv := newTestOIDCServer(t, false)
	h := newTestHandler(t, srv, "keycloak")

	header := newMockHeaderMap()
	header.Set(":authority", "app.example.com")
	header.Set("x-forwarded-proto", "https")

	err := h.HandleAuthRedirect(header, "/dashboard")
	if err != nil {
		t.Fatalf("HandleAuthRedirect failed: %v", err)
	}

	location, ok := header.Get("location")
	if !ok || location == "" {
		t.Fatal("expected location header to be set")
	}

	// Parse the auth URL
	parsedURL, err := url.Parse(location)
	if err != nil {
		t.Fatalf("failed to parse location URL: %v", err)
	}
	q := parsedURL.Query()

	// Verify state is a pure nonce (no "|" character)
	state := q.Get("state")
	if state == "" {
		t.Error("expected state parameter in auth URL")
	}
	if strings.Contains(state, "|") {
		t.Errorf("state should be a pure nonce (no '|'), got: %q", state)
	}

	// Verify PKCE parameters are present
	codeChallenge := q.Get("code_challenge")
	if codeChallenge == "" {
		t.Error("expected code_challenge parameter in auth URL")
	}
	codeChallengeMethod := q.Get("code_challenge_method")
	if codeChallengeMethod != "S256" {
		t.Errorf("expected code_challenge_method=S256, got %q", codeChallengeMethod)
	}
}

// TestPKCEPendingAuthStored verifies HandleAuthRedirect stores a PendingAuth in session store.
func TestPKCEPendingAuthStored(t *testing.T) {
	srv := newTestOIDCServer(t, false)
	h := newTestHandler(t, srv, "myprovider")

	header := newMockHeaderMap()
	header.Set(":authority", "app.example.com")

	err := h.HandleAuthRedirect(header, "/mypath")
	if err != nil {
		t.Fatalf("HandleAuthRedirect failed: %v", err)
	}

	location, _ := header.Get("location")
	parsedURL, _ := url.Parse(location)
	nonce := parsedURL.Query().Get("state")

	// PendingAuth should be stored in session store
	pa, err := session.GetPendingAuth(h.sessionStore, nonce)
	if err != nil {
		t.Fatalf("PendingAuth not stored or not retrievable: %v", err)
	}
	if pa.ProviderName != "myprovider" {
		t.Errorf("PendingAuth.ProviderName: got %q, want %q", pa.ProviderName, "myprovider")
	}
	if pa.OriginalPath != "/mypath" {
		t.Errorf("PendingAuth.OriginalPath: got %q, want %q", pa.OriginalPath, "/mypath")
	}
	if pa.CodeVerifier == "" {
		t.Error("PendingAuth.CodeVerifier should not be empty")
	}
}

// TestPKCECallback verifies HandleCallback retrieves PendingAuth and sets location.
func TestPKCECallback(t *testing.T) {
	srv := newTestOIDCServer(t, false)
	h := newTestHandler(t, srv, "keycloak")

	header := newMockHeaderMap()
	header.Set(":authority", "app.example.com")

	// Initiate auth redirect to store PendingAuth
	err := h.HandleAuthRedirect(header, "/after-login")
	if err != nil {
		t.Fatalf("HandleAuthRedirect failed: %v", err)
	}

	location, _ := header.Get("location")
	parsedURL, _ := url.Parse(location)
	nonce := parsedURL.Query().Get("state")

	// Simulate callback
	callbackHeader := newMockHeaderMap()
	callbackHeader.Set(":authority", "app.example.com")
	query := "code=testcode&state=" + nonce

	err = h.HandleCallback(callbackHeader, query)
	if err != nil {
		t.Fatalf("HandleCallback failed: %v", err)
	}

	// Should redirect to original path
	redirectLocation, ok := callbackHeader.Get("location")
	if !ok || redirectLocation == "" {
		t.Error("expected location header after callback")
	}
	if redirectLocation != "/after-login" {
		t.Errorf("expected location %q, got %q", "/after-login", redirectLocation)
	}
}

// TestPKCECallbackNoStateSplit verifies HandleCallback does NOT use "|" split logic.
func TestPKCECallbackNoStateSplit(t *testing.T) {
	srv := newTestOIDCServer(t, false)
	h := newTestHandler(t, srv, "keycloak")

	// Store a PendingAuth manually with a clean nonce (no "|")
	nonce := "cleannonce"
	pa := &session.PendingAuth{
		ProviderName: "keycloak",
		OriginalPath: "/clean",
		CodeVerifier: "verifier123",
		Expiry:       time.Now().Add(5 * time.Minute),
	}
	if err := session.StorePendingAuth(h.sessionStore, nonce, pa); err != nil {
		t.Fatalf("StorePendingAuth failed: %v", err)
	}

	header := newMockHeaderMap()
	header.Set(":authority", "app.example.com")
	query := "code=somecode&state=" + nonce
	err := h.HandleCallback(header, query)
	if err != nil {
		t.Fatalf("HandleCallback with pure nonce failed: %v", err)
	}
	loc, _ := header.Get("location")
	if loc != "/clean" {
		t.Errorf("expected location /clean, got %q", loc)
	}
}

// TestHandleCallbackSetsProviderName verifies that HandleCallback stores a session with
// ProviderName equal to the handler's configured providerName.
func TestHandleCallbackSetsProviderName(t *testing.T) {
	srv := newTestOIDCServer(t, false)
	h := newTestHandler(t, srv, "keycloak")

	// Initiate auth redirect to store PendingAuth (same as TestPKCECallback)
	authHeader := newMockHeaderMap()
	authHeader.Set(":authority", "app.example.com")
	if err := h.HandleAuthRedirect(authHeader, "/after-login"); err != nil {
		t.Fatalf("HandleAuthRedirect failed: %v", err)
	}
	location, _ := authHeader.Get("location")
	parsedURL, _ := url.Parse(location)
	nonce := parsedURL.Query().Get("state")

	// Simulate callback
	callbackHeader := newMockHeaderMap()
	callbackHeader.Set(":authority", "app.example.com")
	query := "code=testcode&state=" + nonce
	if err := h.HandleCallback(callbackHeader, query); err != nil {
		t.Fatalf("HandleCallback failed: %v", err)
	}

	// Extract session ID from Set-Cookie header
	setCookie, ok := callbackHeader.Get("set-cookie")
	if !ok || setCookie == "" {
		t.Fatal("expected set-cookie header after successful callback")
	}
	// Cookie format: "session=<session_id>; Path=..."
	sessionID := ""
	for _, part := range strings.Split(setCookie, ";") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "session=") {
			sessionID = strings.TrimPrefix(part, "session=")
			break
		}
	}
	if sessionID == "" {
		t.Fatalf("could not extract session ID from set-cookie %q", setCookie)
	}

	// Retrieve the stored session and assert ProviderName
	sess, err := h.sessionStore.Get(sessionID)
	if err != nil {
		t.Fatalf("failed to retrieve session from store: %v", err)
	}
	if sess.ProviderName != "keycloak" {
		t.Errorf("session.ProviderName = %q, want %q", sess.ProviderName, "keycloak")
	}
}

// newTestOIDCServerWithJWKS starts an httptest server like newTestOIDCServer but also
// serves a /jwks endpoint with an RSA public key so that NewTokenValidator can
// initialise successfully and ValidateBearerToken can verify signed tokens.
// It returns the server and a sign function that creates RS256-signed JWTs.
func newTestOIDCServerWithJWKS(t *testing.T) (srv *httptest.Server, signJWT func(subject, clientID string) string) {
	t.Helper()

	// Generate an RSA key pair for signing / verification.
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}

	const keyID = "test-key-1"

	// Build the JWKS JSON from the RSA public key.
	pubKey := &privKey.PublicKey
	jwksJSON := rsaPublicKeyToJWKS(t, pubKey, keyID)

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
		json.NewEncoder(w).Encode(cfg)
	})

	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(jwksJSON)
	})

	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{"sub": "bearer-user", "email": "bearer@example.com"}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	signJWT = func(subject, clientID string) string {
		return signRSAJWT(t, privKey, keyID, srv.URL, subject, clientID)
	}
	return srv, signJWT
}

// rsaPublicKeyToJWKS converts an RSA public key into a minimal JWKS JSON document.
func rsaPublicKeyToJWKS(t *testing.T, pub *rsa.PublicKey, kid string) []byte {
	t.Helper()
	// RFC 7517 JWK representation of an RSA public key.
	n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	// E is typically 65537 (0x010001), encode as big-endian bytes then base64url.
	eBytes := []byte{byte(pub.E >> 16), byte(pub.E >> 8), byte(pub.E)}
	// Trim leading zero bytes.
	for len(eBytes) > 1 && eBytes[0] == 0 {
		eBytes = eBytes[1:]
	}
	e := base64.RawURLEncoding.EncodeToString(eBytes)
	jwks := map[string]interface{}{
		"keys": []map[string]interface{}{
			{
				"kty": "RSA",
				"use": "sig",
				"alg": "RS256",
				"kid": kid,
				"n":   n,
				"e":   e,
			},
		},
	}
	b, err := json.Marshal(jwks)
	if err != nil {
		t.Fatalf("marshal JWKS: %v", err)
	}
	return b
}

// signRSAJWT creates a minimal RS256-signed JWT accepted by go-oidc's verifier.
func signRSAJWT(t *testing.T, key *rsa.PrivateKey, kid, issuer, subject, audience string) string {
	t.Helper()

	now := time.Now()
	header := map[string]interface{}{
		"alg": "RS256",
		"typ": "JWT",
		"kid": kid,
	}
	payload := map[string]interface{}{
		"iss": issuer,
		"sub": subject,
		"aud": audience,
		"iat": now.Unix(),
		"exp": now.Add(1 * time.Hour).Unix(),
	}

	headerJSON, _ := json.Marshal(header)
	payloadJSON, _ := json.Marshal(payload)

	headerEnc := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadEnc := base64.RawURLEncoding.EncodeToString(payloadJSON)
	sigInput := headerEnc + "." + payloadEnc

	h := crypto.SHA256.New()
	h.Write([]byte(sigInput))
	digest := h.Sum(nil)

	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest)
	if err != nil {
		t.Fatalf("rsa.SignPKCS1v15: %v", err)
	}

	return sigInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// TestValidateBearerTokenSetsProviderName verifies that ValidateBearerToken returns a session
// with ProviderName equal to the handler's configured providerName.
func TestValidateBearerTokenSetsProviderName(t *testing.T) {
	srv, signJWT := newTestOIDCServerWithJWKS(t)

	store := session.NewInMemorySessionStore()
	logger, _ := zap.NewDevelopment()
	cookieConfig := &session.CookieConfig{Name: "session", Path: "/", HTTPOnly: true}
	cm, err := session.NewCookieManager(nil, nil, cookieConfig)
	if err != nil {
		t.Fatalf("NewCookieManager: %v", err)
	}

	cfg := &OIDCConfig{
		ProviderName: "google",
		IssuerURL:    srv.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		RedirectURL:  "http://localhost/callback",
		Scopes:       []string{"openid"},
	}

	// NewOAuthHandler will call NewTokenValidator which fetches OIDC discovery and
	// populates the JWKS cache — this now succeeds because the mock server serves /jwks.
	handler, err := NewOAuthHandler(cfg, store, cm, logger)
	if err != nil {
		t.Fatalf("NewOAuthHandler: %v", err)
	}
	h := handler.(*OAuthHandlerImpl)

	if h.tokenValidator == nil {
		t.Skip("tokenValidator could not be initialised — mock OIDC discovery incomplete")
	}

	// Create a properly signed JWT accepted by the verifier.
	token := signJWT("bearer-user", "test-client")

	sess, err := h.ValidateBearerToken(context.Background(), token)
	if err != nil {
		t.Fatalf("ValidateBearerToken failed: %v", err)
	}
	if sess.ProviderName != "google" {
		t.Errorf("session.ProviderName = %q, want %q", sess.ProviderName, "google")
	}
}

// TestOAuthHandlerImpl_SessionCookieDelegation verifies that GetSessionCookie and
// DeleteSessionCookie delegate to the handler's internal cookieManager.
func TestOAuthHandlerImpl_SessionCookieDelegation(t *testing.T) {
	srv := newTestOIDCServer(t, false)
	h := newTestHandler(t, srv, "keycloak")

	// Build a header map with a "session" cookie (matches the cookieName used in newTestHandler).
	getHeader := newMockHeaderMap()
	getHeader.Set("cookie", "session=my-session-id")

	// GetSessionCookie must return the session ID from the cookie.
	got, err := h.GetSessionCookie(getHeader)
	if err != nil {
		t.Fatalf("GetSessionCookie error: %v", err)
	}
	if got != "my-session-id" {
		t.Errorf("GetSessionCookie = %q, want %q", got, "my-session-id")
	}

	// DeleteSessionCookie must set a set-cookie header that clears the cookie.
	deleteHeader := newMockHeaderMap()
	h.DeleteSessionCookie(deleteHeader)
	setCookie, ok := deleteHeader.Get("set-cookie")
	if !ok || setCookie == "" {
		t.Error("DeleteSessionCookie did not set a set-cookie header")
	}
	if !strings.Contains(setCookie, "session=") {
		t.Errorf("DeleteSessionCookie set-cookie %q does not contain 'session='", setCookie)
	}
}

// TestIssuerValidation verifies HandleCallback rejects tokens with mismatched issuer.
func TestIssuerValidation(t *testing.T) {
	srv := newTestOIDCServer(t, true /* wantIssuerMismatch */)
	h := newTestHandler(t, srv, "keycloak")

	// Store PendingAuth for the nonce
	nonce := "issuernonce"
	pa := &session.PendingAuth{
		ProviderName: "keycloak",
		OriginalPath: "/protected",
		CodeVerifier: "verifier-issuer",
		Expiry:       time.Now().Add(5 * time.Minute),
	}
	if err := session.StorePendingAuth(h.sessionStore, nonce, pa); err != nil {
		t.Fatalf("StorePendingAuth failed: %v", err)
	}

	header := newMockHeaderMap()
	header.Set(":authority", "app.example.com")
	query := "code=badcode&state=" + nonce

	err := h.HandleCallback(header, query)
	if err == nil {
		t.Fatal("expected error due to issuer mismatch")
	}
	if !strings.Contains(err.Error(), "issuer mismatch") {
		t.Errorf("expected error to mention 'issuer mismatch', got: %v", err)
	}
}

// TestOAuthHandlerImpl_SessionCookieWriteDelegation verifies that SetSessionCookie and
// FormatSessionCookie delegate to the handler's internal cookieManager.
func TestOAuthHandlerImpl_SessionCookieWriteDelegation(t *testing.T) {
	srv := newTestOIDCServer(t, false)
	// newTestHandler uses CookieConfig{Name: "session"}, so cookie name is "session".
	h := newTestHandler(t, srv, "keycloak")

	// SetSessionCookie must write a set-cookie header containing "session=abc123".
	setHeader := newMockHeaderMap()
	if err := h.SetSessionCookie(setHeader, "abc123"); err != nil {
		t.Fatalf("SetSessionCookie error: %v", err)
	}
	setCookie, ok := setHeader.Get("set-cookie")
	if !ok || setCookie == "" {
		t.Fatal("SetSessionCookie did not set a set-cookie header")
	}
	if !strings.Contains(setCookie, "session=abc123") {
		t.Errorf("expected set-cookie to contain 'session=abc123', got %q", setCookie)
	}

	// FormatSessionCookie must return a string containing "session=xyz".
	formatted := h.FormatSessionCookie("xyz")
	if !strings.Contains(formatted, "session=xyz") {
		t.Errorf("expected formatted cookie to contain 'session=xyz', got %q", formatted)
	}
}
