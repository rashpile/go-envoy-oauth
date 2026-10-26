package oauth

import (
	"context"
	"fmt"

	"github.com/envoyproxy/envoy/contrib/golang/common/go/api"
	"github.com/rashpile/go-envoy-oauth/plugin/session"
)

// DownHandler is an OAuthHandler placeholder registered for providers whose
// initial OIDC discovery failed (D-01). Every OAuthHandler operation returns
// "provider unavailable" and HealthState() returns StateDown so the filter
// request-path gate short-circuits with 503 (D-03).
//
// ProviderRegistry.startDownHandlerRecovery retries OIDC discovery in the
// background and atomically replaces this sentinel with a live handler on
// success — no Envoy config reload required.
type DownHandler struct {
	ProviderName string
}

// unavailableErr is the standard error returned by every DownHandler method.
func (d *DownHandler) unavailableErr() error {
	return fmt.Errorf("provider %q unavailable: initial OIDC discovery failed", d.ProviderName)
}

func (d *DownHandler) HandleAuthRedirect(_ api.RequestHeaderMap, _ string) error {
	return d.unavailableErr()
}

func (d *DownHandler) HandleCallback(_ api.RequestHeaderMap, _ string) error {
	return d.unavailableErr()
}

func (d *DownHandler) HandleLogout(_ api.RequestHeaderMap) (string, error) {
	return "", d.unavailableErr()
}

func (d *DownHandler) ValidateSession(_ *session.Session) error {
	return d.unavailableErr()
}

func (d *DownHandler) IsNeedValidateSession(_ *session.Session) bool {
	return true // force validation so ValidateSession returns unavailableErr if gate is bypassed
}

func (d *DownHandler) ValidateBearerToken(_ context.Context, _ string) (*session.Session, error) {
	return nil, d.unavailableErr()
}

func (d *DownHandler) ValidateBearerTokenForResource(_ context.Context, _, _ string) (*session.Session, error) {
	return nil, d.unavailableErr()
}

func (d *DownHandler) ExchangeRefreshToken(_ context.Context, _ string) (string, error) {
	return "", d.unavailableErr()
}

func (d *DownHandler) GetSessionCookie(_ api.RequestHeaderMap) (string, error) {
	return "", d.unavailableErr()
}

func (d *DownHandler) DeleteSessionCookie(_ api.RequestHeaderMap) {}

func (d *DownHandler) SetSessionCookie(_ api.RequestHeaderMap, _ string) error {
	return d.unavailableErr()
}

func (d *DownHandler) FormatSessionCookie(_ string) string {
	return ""
}

// HealthState returns StateDown unconditionally (D-01): a DownHandler means
// initial discovery never succeeded.
func (d *DownHandler) HealthState() ProviderState {
	return StateDown
}

// Compile-time check: DownHandler must implement OAuthHandler.
var _ OAuthHandler = (*DownHandler)(nil)
