package oauth

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
)

// testIssuer is a minimal OIDC issuer: discovery document, JWKS, and RS256 signing.
type testIssuer struct {
	srv *httptest.Server
	key *rsa.PrivateKey
}

func newTestIssuer(t *testing.T) *testIssuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	ti := &testIssuer{key: key}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"issuer":                                ti.srv.URL,
			"authorization_endpoint":                ti.srv.URL + "/auth",
			"token_endpoint":                        ti.srv.URL + "/token",
			"jwks_uri":                              ti.srv.URL + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"keys": []map[string]string{{
				"kty": "RSA", "alg": "RS256", "use": "sig", "kid": "k1",
				"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
				"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
			}},
		})
	})
	ti.srv = httptest.NewServer(mux)
	t.Cleanup(ti.srv.Close)
	return ti
}

func (ti *testIssuer) sign(t *testing.T, claims map[string]interface{}) string {
	t.Helper()
	enc := func(v interface{}) string {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		return base64.RawURLEncoding.EncodeToString(b)
	}
	signingInput := enc(map[string]string{"alg": "RS256", "typ": "JWT", "kid": "k1"}) + "." + enc(claims)
	sum := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, ti.key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// TestValidateAccessTokenRequiresThisClient verifies that a validly signed
// access token from the right issuer is accepted only when its azp or aud names
// the gateway's client (issue #8).
func TestValidateAccessTokenRequiresThisClient(t *testing.T) {
	ti := newTestIssuer(t)
	v, err := NewTokenValidator(ti.srv.URL, "gateway", zap.NewNop())
	if err != nil {
		t.Fatalf("NewTokenValidator: %v", err)
	}

	base := func(extra map[string]interface{}) map[string]interface{} {
		c := map[string]interface{}{
			"iss":                ti.srv.URL,
			"sub":                "user-1",
			"preferred_username": "alice",
			"exp":                time.Now().Add(5 * time.Minute).Unix(),
			"iat":                time.Now().Unix(),
		}
		for k, val := range extra {
			c[k] = val
		}
		return c
	}

	tests := []struct {
		name   string
		claims map[string]interface{}
		ok     bool
	}{
		{"azp is this client (Keycloak access token)", base(map[string]interface{}{"aud": "account", "azp": "gateway"}), true},
		{"aud contains this client", base(map[string]interface{}{"aud": []string{"account", "gateway"}, "azp": "other"}), true},
		{"issued to another client", base(map[string]interface{}{"aud": "account", "azp": "other-client"}), false},
		{"no aud and no azp", base(nil), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := v.ValidateAccessToken(context.Background(), ti.sign(t, tt.claims))
			if tt.ok && err != nil {
				t.Errorf("ValidateAccessToken: unexpected error %v", err)
			}
			if !tt.ok && (err == nil || !strings.Contains(err.Error(), "not issued to client")) {
				t.Errorf("ValidateAccessToken error = %v, want a not-issued-to-client rejection", err)
			}
		})
	}
}

func TestIssuedToClient(t *testing.T) {
	if !issuedToClient("gateway", []string{"account"}, "gateway") {
		t.Error("azp match must be accepted")
	}
	if !issuedToClient("other", []string{"account", "gateway"}, "gateway") {
		t.Error("aud match must be accepted")
	}
	if issuedToClient("other", []string{"account"}, "gateway") {
		t.Error("neither azp nor aud names the client, must be rejected")
	}
	if issuedToClient("", nil, "") {
		t.Error("empty client ID must never match")
	}
	if issuedToClient("", []string{""}, "") {
		t.Error("empty client ID must never match an empty aud entry")
	}
}

// TestValidateTokenForAudience verifies that a protected resource accepts a
// token issued to any client of the realm as long as aud names the resource,
// and nothing else (issue #7).
func TestValidateTokenForAudience(t *testing.T) {
	ti := newTestIssuer(t)
	v, err := NewTokenValidator(ti.srv.URL, "gateway", zap.NewNop())
	if err != nil {
		t.Fatalf("NewTokenValidator: %v", err)
	}
	const resource = "https://romanian.example/mcp"

	base := func(extra map[string]interface{}) map[string]interface{} {
		c := map[string]interface{}{
			"iss":                ti.srv.URL,
			"sub":                "user-1",
			"preferred_username": "alice",
			"azp":                "mcp-romanian",
			"aud":                []string{resource},
			"exp":                time.Now().Add(5 * time.Minute).Unix(),
			"iat":                time.Now().Unix(),
		}
		for k, val := range extra {
			if val == nil {
				delete(c, k)
				continue
			}
			c[k] = val
		}
		return c
	}

	tests := []struct {
		name     string
		claims   map[string]interface{}
		audience string
		ok       bool
	}{
		{"aud names the resource, foreign azp", base(nil), resource, true},
		{"aud names the resource among others", base(map[string]interface{}{"aud": []string{"account", resource}}), resource, true},
		// Keycloak emits a single audience as a JSON string, not an array.
		{"aud is a single string", base(map[string]interface{}{"aud": resource}), resource, true},
		{"aud names another pack", base(map[string]interface{}{"aud": []string{"https://english.example/mcp"}}), resource, false},
		{"aud names only the gateway client", base(map[string]interface{}{"aud": []string{"gateway"}, "azp": "gateway"}), resource, false},
		{"expired", base(map[string]interface{}{"exp": time.Now().Add(-time.Minute).Unix()}), resource, false},
		{"wrong issuer", base(map[string]interface{}{"iss": "https://evil.example/realms/pl"}), resource, false},
		{"no subject", base(map[string]interface{}{"sub": nil}), resource, false},
		{"empty audience never matches", base(map[string]interface{}{"aud": []string{""}}), "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims, err := v.ValidateTokenForAudience(context.Background(), ti.sign(t, tt.claims), tt.audience)
			if tt.ok {
				if err != nil {
					t.Fatalf("ValidateTokenForAudience: unexpected error %v", err)
				}
				if claims.Subject != "user-1" || claims.PreferredUsername != "alice" || claims.AuthorizedParty != "mcp-romanian" {
					t.Errorf("claims = %+v, want sub, preferred_username and azp from the token", claims)
				}
				return
			}
			if err == nil {
				t.Error("ValidateTokenForAudience: expected rejection, got nil error")
			}
		})
	}
}

// TestValidateTokenForAudienceKeycloakWithoutBasicScope reproduces the token
// Keycloak 25+ issues to a client without the "basic" client scope: valid
// signature, issuer and aud, but no sub (basic adds sub and auth_time). It must
// be rejected as no_subject, and the same token with sub must pass, so sub is
// the only reason it fails.
func TestValidateTokenForAudienceKeycloakWithoutBasicScope(t *testing.T) {
	ti := newTestIssuer(t)
	v, err := NewTokenValidator(ti.srv.URL, "gateway", zap.NewNop())
	if err != nil {
		t.Fatalf("NewTokenValidator: %v", err)
	}
	const resource = "https://personal.example/mcp"

	evaluate := func() map[string]interface{} {
		return map[string]interface{}{
			"exp":                time.Now().Add(5 * time.Minute).Unix(),
			"iat":                time.Now().Unix(),
			"iss":                ti.srv.URL,
			"aud":                resource, // single audience: a JSON string
			"typ":                "Bearer",
			"azp":                "personal-mcp",
			"sid":                "sid-1",
			"scope":              "openid profile",
			"name":               "Alice Example",
			"preferred_username": "alice",
			"given_name":         "Alice",
			"family_name":        "Example",
		}
	}

	_, err = v.ValidateTokenForAudience(context.Background(), ti.sign(t, evaluate()), resource)
	var rte *ResourceTokenError
	if !errors.As(err, &rte) {
		t.Fatalf("error = %v, want a *ResourceTokenError", err)
	}
	if rte.Reason != ReasonNoSubject {
		t.Errorf("Reason = %q, want %q (err: %v)", rte.Reason, ReasonNoSubject, err)
	}
	if rte.Azp != "personal-mcp" || rte.Iss != ti.srv.URL || len(rte.Aud) != 1 || rte.Aud[0] != resource {
		t.Errorf("azp/iss/aud = %q/%q/%v, want the token's values", rte.Azp, rte.Iss, rte.Aud)
	}

	withSub := evaluate()
	withSub["sub"] = "user-1"
	if _, err := v.ValidateTokenForAudience(context.Background(), ti.sign(t, withSub), resource); err != nil {
		t.Errorf("same token with sub: unexpected error %v", err)
	}
}

// TestValidateTokenForAudienceReasons pins the reason class of each rejection.
func TestValidateTokenForAudienceReasons(t *testing.T) {
	ti := newTestIssuer(t)
	v, err := NewTokenValidator(ti.srv.URL, "gateway", zap.NewNop())
	if err != nil {
		t.Fatalf("NewTokenValidator: %v", err)
	}
	const resource = "https://personal.example/mcp"
	valid := func(extra map[string]interface{}) map[string]interface{} {
		c := map[string]interface{}{
			"iss": ti.srv.URL, "sub": "user-1", "aud": resource, "azp": "personal-mcp",
			"exp": time.Now().Add(5 * time.Minute).Unix(), "iat": time.Now().Unix(),
		}
		for k, val := range extra {
			if val == nil {
				delete(c, k)
				continue
			}
			c[k] = val
		}
		return c
	}

	cases := []struct {
		name   string
		token  string
		reason string
	}{
		{"malformed token", "x", ReasonVerifyFailed},
		{"wrong aud", ti.sign(t, valid(map[string]interface{}{"aud": "https://english.example/mcp"})), ReasonVerifyFailed},
		{"expired", ti.sign(t, valid(map[string]interface{}{"exp": time.Now().Add(-time.Minute).Unix()})), ReasonVerifyFailed},
		{"no exp", ti.sign(t, valid(map[string]interface{}{"exp": nil})), ReasonVerifyFailed},
		{"no sub", ti.sign(t, valid(map[string]interface{}{"sub": nil})), ReasonNoSubject},
		{"claims of the wrong type", ti.sign(t, valid(map[string]interface{}{"email_verified": "yes"})), ReasonClaimsDecode},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := v.ValidateTokenForAudience(context.Background(), tc.token, resource)
			var rte *ResourceTokenError
			if !errors.As(err, &rte) || rte.Reason != tc.reason {
				t.Errorf("error = %v, want reason %q", err, tc.reason)
			}
		})
	}
}
