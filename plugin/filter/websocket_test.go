package filter

import (
	"errors"
	"testing"
	"time"

	"github.com/rashpile/go-envoy-oauth/plugin/session"
	"go.uber.org/zap"
)

// wsValidatingHandler has a session cookie, asks for revalidation, and
// answers ValidateSession with validateErr.
type wsValidatingHandler struct {
	recordingHandler
	validateErr   error
	validateCalls chan struct{}
}

func (h *wsValidatingHandler) ValidateSession(_ *session.Session) error {
	h.validateCalls <- struct{}{}
	return h.validateErr
}

func newWebSocketTestFilter(t *testing.T, validateErr error) (*Filter, *asyncDecoderCallbacks, *wsValidatingHandler) {
	t.Helper()
	dec := newAsyncDecoderCallbacks(false)
	registry := NewProviderRegistry(zap.NewNop())
	h := &wsValidatingHandler{
		recordingHandler: recordingHandler{cookieValue: "ws-session", isNeedValidate: true},
		validateErr:      validateErr,
		validateCalls:    make(chan struct{}, 1),
	}
	registry.Register("kc", h)
	store := session.NewInMemorySessionStore()
	if err := store.Store(&session.Session{
		ID:           "ws-session",
		UserID:       "u1",
		ProviderName: "kc",
		ExpiresAt:    time.Now().Add(time.Hour),
		Claims:       map[string]interface{}{"preferred_username": "alice"},
	}); err != nil {
		t.Fatalf("store session: %v", err)
	}
	f := &Filter{
		config: &OAuthConfig{
			DefaultProvider: "kc",
			Clusters:        map[string]ClusterConfig{},
			Providers:       map[string]ProviderConfig{"kc": {AllowedUsers: []string{"*"}}},
		},
		providerRegistry: registry,
		sessionStore:     store,
		callbacks:        &asyncCallbacks{decoder: dec},
		logger:           zap.NewNop(),
	}
	return f, dec, h
}

func wsUpgradeHeaders() *capturingHeaderMap {
	return &capturingHeaderMap{headers: map[string]string{
		":path":      "/ws",
		"connection": "Upgrade",
		"upgrade":    "websocket",
	}}
}

// TestWebSocketRevokedSessionGets401 verifies that a WebSocket upgrade with a
// session the IdP no longer accepts is refused, like on the HTTP path (issue #13).
func TestWebSocketRevokedSessionGets401(t *testing.T) {
	f, dec, h := newWebSocketTestFilter(t, errors.New("session revoked"))

	f.handleWebSocketAuth(wsUpgradeHeaders(), "/ws", "trace")

	select {
	case <-h.validateCalls:
	case <-time.After(2 * time.Second):
		t.Fatal("ValidateSession was not called for the WebSocket session")
	}
	select {
	case code := <-dec.replied:
		if code != 401 {
			t.Errorf("reply status = %d, want 401", code)
		}
	case <-dec.continued:
		t.Error("revoked session was let through")
	case <-time.After(2 * time.Second):
		t.Fatal("no reply after failed revalidation")
	}
}

// TestWebSocketValidSessionContinuesAfterRevalidation verifies that a session
// that passes revalidation still opens the WebSocket.
func TestWebSocketValidSessionContinuesAfterRevalidation(t *testing.T) {
	f, dec, h := newWebSocketTestFilter(t, nil)

	f.handleWebSocketAuth(wsUpgradeHeaders(), "/ws", "trace")

	select {
	case <-h.validateCalls:
	case <-time.After(2 * time.Second):
		t.Fatal("ValidateSession was not called for the WebSocket session")
	}
	select {
	case <-dec.continued:
	case code := <-dec.replied:
		t.Errorf("valid session got local reply %d, want Continue", code)
	case <-time.After(2 * time.Second):
		t.Fatal("request was neither continued nor answered")
	}
}
