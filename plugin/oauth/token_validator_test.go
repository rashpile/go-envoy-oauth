package oauth

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
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
