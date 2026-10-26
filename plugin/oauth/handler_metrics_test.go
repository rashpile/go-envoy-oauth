package oauth

import (
	"context"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rashpile/go-envoy-oauth/plugin/metrics"
	"go.uber.org/zap"
)

// findIDPLabelValues returns all idp label values observed in any metric whose
// family name starts with the given prefix. Used by OBS-01 regression tests to
// prove the idp label carries the provider registry key (e.g., "keycloak"), not
// the issuer hostname (e.g., "keycloak.example.com").
func findIDPLabelValues(t *testing.T, reg *prometheus.Registry, familyNamePrefix string) []string {
	t.Helper()
	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("reg.Gather() failed: %v", err)
	}
	var values []string
	for _, mf := range families {
		name := mf.GetName()
		if len(name) < len(familyNamePrefix) || name[:len(familyNamePrefix)] != familyNamePrefix {
			continue
		}
		for _, m := range mf.GetMetric() {
			for _, lp := range m.GetLabel() {
				if lp.GetName() == "idp" {
					values = append(values, lp.GetValue())
				}
			}
		}
	}
	return values
}

func contains(slice []string, want string) bool {
	for _, s := range slice {
		if s == want {
			return true
		}
	}
	return false
}

// newHandlerForMetricsTest constructs a minimal OAuthHandlerImpl sufficient to
// exercise the metrics call sites WITHOUT performing OIDC discovery. The handler
// is configured with providerName="keycloak" and a hostname that would, under the
// old behavior, produce idp="keycloak.example.com" via metrics.GetIDPName.
func newHandlerForMetricsTest(_ *testing.T) *OAuthHandlerImpl {
	return &OAuthHandlerImpl{
		config: &OIDCConfig{
			IssuerURL:    "https://keycloak.example.com/realms/test",
			ClientID:     "test-client",
			ClientSecret: "test-secret",
			RedirectURL:  "https://app.example.com/callback",
			ProviderName: "keycloak",
		},
		providerName:      "keycloak",
		refreshTokenCache: make(map[string]*tokenCacheEntry),
		logger:            zap.NewNop(),
	}
}

// TestHandleCallbackMetricsUsesProviderName verifies OBS-01: RecordLogin and
// RecordCallbackDuration in HandleCallback use h.providerName (the registry key)
// as the idp label value, not the issuer hostname.
func TestHandleCallbackMetricsUsesProviderName(t *testing.T) {
	reg := prometheus.NewRegistry()
	metrics.RegisterAuthMetrics(reg)
	metrics.RegisterOAuthFlowMetrics(reg)

	h := newHandlerForMetricsTest(t)
	hdr := newMockHeaderMap()
	// Malformed query triggers the early metrics.RecordLogin("failure", "invalid_query")
	// + metrics.RecordCallbackDuration path at handler.go lines 245-247.
	_ = h.HandleCallback(hdr, "%ZZ")

	got := findIDPLabelValues(t, reg, "envoy_oauth_login")
	if !contains(got, "keycloak") {
		t.Errorf("HandleCallback metrics: idp label missing %q (got %v)", "keycloak", got)
	}
	if contains(got, "keycloak.example.com") {
		t.Errorf("HandleCallback metrics: idp label still uses hostname %q — OBS-01 not applied", "keycloak.example.com")
	}
}

// TestHandleLogoutMetricsUsesProviderName verifies OBS-01 for HandleLogout.
// We invoke the logout path in a way that reaches the metrics.RecordLogout call.
func TestHandleLogoutMetricsUsesProviderName(t *testing.T) {
	reg := prometheus.NewRegistry()
	metrics.RegisterAuthMetrics(reg)
	metrics.RegisterOAuthFlowMetrics(reg)

	h := newHandlerForMetricsTest(t)
	hdr := newMockHeaderMap()
	// HandleLogout with no session cookie triggers the "no cookie" path which
	// records metrics.RecordLogout(idp, "success", "").
	// The handler also needs h.provider to be non-nil for the logger.Debug call.
	// We set a minimal provider to avoid nil-pointer on h.provider.Issuer.
	h.provider = &OIDCProvider{
		Issuer:             "https://keycloak.example.com/realms/test",
		EndSessionEndpoint: "",
	}
	_, _ = h.HandleLogout(hdr)

	got := findIDPLabelValues(t, reg, "envoy_oauth_logout")
	if !contains(got, "keycloak") {
		t.Errorf("HandleLogout metrics: idp label missing %q (got %v)", "keycloak", got)
	}
	if contains(got, "keycloak.example.com") {
		t.Errorf("HandleLogout metrics: idp label still uses hostname %q — OBS-01 not applied", "keycloak.example.com")
	}
}

// tokenValidationCount returns envoy_oauth_token_validation_total for the given labels.
func tokenValidationCount(t *testing.T, reg *prometheus.Registry, idp, result string) float64 {
	t.Helper()
	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("reg.Gather() failed: %v", err)
	}
	for _, mf := range families {
		if mf.GetName() != "envoy_oauth_token_validation_total" {
			continue
		}
		for _, m := range mf.GetMetric() {
			labels := map[string]string{}
			for _, lp := range m.GetLabel() {
				labels[lp.GetName()] = lp.GetValue()
			}
			if labels["idp"] == idp && labels["result"] == result {
				return m.GetCounter().GetValue()
			}
		}
	}
	return 0
}

// TestValidateBearerTokenForResource verifies that a resource token becomes a
// session for the provider and that the validation metric is recorded (issue #7).
func TestValidateBearerTokenForResource(t *testing.T) {
	reg := prometheus.NewRegistry()
	metrics.RegisterOAuthFlowMetrics(reg)

	ti := newTestIssuer(t)
	tv, err := NewTokenValidator(ti.srv.URL, "test-client", zap.NewNop())
	if err != nil {
		t.Fatalf("NewTokenValidator: %v", err)
	}
	h := newHandlerForMetricsTest(t)
	h.tokenValidator = tv

	const resource = "https://romanian.example/mcp"
	claims := func(aud string) map[string]interface{} {
		return map[string]interface{}{
			"iss":                ti.srv.URL,
			"sub":                "user-1",
			"preferred_username": "alice",
			"email":              "alice@example.com",
			"azp":                "mcp-romanian",
			"aud":                []string{aud},
			"exp":                time.Now().Add(5 * time.Minute).Unix(),
			"iat":                time.Now().Unix(),
		}
	}

	token := ti.sign(t, claims(resource))
	sess, err := h.ValidateBearerTokenForResource(context.Background(), token, resource)
	if err != nil {
		t.Fatalf("ValidateBearerTokenForResource: %v", err)
	}
	if sess.UserID != "user-1" || sess.ProviderName != "keycloak" || sess.Token != token {
		t.Errorf("session = %+v, want UserID user-1, ProviderName keycloak and the token", sess)
	}
	if sess.Claims["preferred_username"] != "alice" || sess.Claims["email"] != "alice@example.com" {
		t.Errorf("session claims = %v, want preferred_username and email", sess.Claims)
	}
	if got := tokenValidationCount(t, reg, "keycloak", "valid"); got != 1 {
		t.Errorf("valid count = %v, want 1", got)
	}

	if _, err := h.ValidateBearerTokenForResource(context.Background(), ti.sign(t, claims("https://english.example/mcp")), resource); err == nil {
		t.Error("token for another resource must be rejected")
	}
	if got := tokenValidationCount(t, reg, "keycloak", "invalid"); got != 1 {
		t.Errorf("invalid count = %v, want 1", got)
	}

	// No validator (discovery failed): error without a metric.
	h.tokenValidator = nil
	if _, err := h.ValidateBearerTokenForResource(context.Background(), token, resource); err == nil {
		t.Error("missing token validator must be an error")
	}
	if got := tokenValidationCount(t, reg, "keycloak", "invalid"); got != 1 {
		t.Errorf("invalid count after nil validator = %v, want 1 (no metric)", got)
	}
}

func TestDownHandlerValidateBearerTokenForResource(t *testing.T) {
	d := &DownHandler{ProviderName: "keycloak"}
	if _, err := d.ValidateBearerTokenForResource(context.Background(), "t", "https://x/mcp"); err == nil {
		t.Error("DownHandler must refuse resource tokens")
	}
}
