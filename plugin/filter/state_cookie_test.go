package filter

import (
	"strings"
	"testing"
	"time"

	"github.com/envoyproxy/envoy/contrib/golang/common/go/api"
	"github.com/rashpile/go-envoy-oauth/plugin/session"
)

func TestStateCookieRoundTrip(t *testing.T) {
	f := &Filter{config: &OAuthConfig{SessionSecure: true}}
	setCookie := f.stateCookie("state-1", callbackPath)
	for _, attr := range []string{"Path=/oauth/callback", "Max-Age=300", "HttpOnly", "Secure", "SameSite=Lax"} {
		if !strings.Contains(setCookie, attr) {
			t.Errorf("state cookie %q lacks %s", setCookie, attr)
		}
	}

	pair := strings.SplitN(setCookie, ";", 2)[0]
	name, value := stateCookieNameValue("state-1")
	otherName, otherValue := stateCookieNameValue("state-2")
	tests := []struct {
		cookie string
		want   bool
	}{
		{pair, true},
		{"a=b; " + pair + "; c=d", true},
		{name + "=wrong", false},
		{otherName + "=" + otherValue, false},
		{name + "=" + otherValue, false},
		{"", false},
	}
	for _, tt := range tests {
		hdr := &capturingHeaderMap{headers: map[string]string{"cookie": tt.cookie}}
		if got := hasStateCookie(hdr, "state-1"); got != tt.want {
			t.Errorf("hasStateCookie(cookie=%q) = %v, want %v", tt.cookie, got, tt.want)
		}
	}
	if value == "" {
		t.Error("state cookie value is empty")
	}

	clear := f.clearStateCookie("state-1", callbackPath)
	if !strings.HasPrefix(clear, name+"=;") || !strings.Contains(clear, "Max-Age=0") {
		t.Errorf("clear cookie = %q, want an expired %s", clear, name)
	}

	if (&Filter{config: &OAuthConfig{}}).stateCookie("s", callbackPath) == "" {
		t.Error("state cookie must also be set when session_secure is off")
	}
}

// loginStubHandler answers HandleAuthRedirect like the real handler: it sets
// the authorization URL, including the state, in the location header.
type loginStubHandler struct{ mockOAuthHandler }

func (h *loginStubHandler) HandleAuthRedirect(header api.RequestHeaderMap, _ string) error {
	header.Set("location", "https://idp.example.com/auth?client_id=gateway&state=login-state-1")
	return nil
}

// TestHandleLoginSetsStateCookie verifies that the login redirect binds its
// state to the browser with a cookie scoped to the callback path (issue #11).
func TestHandleLoginSetsStateCookie(t *testing.T) {
	dec := &captureDecoderCallbacks{}
	f := buildCallbackFilter(&captureCallbacks{decoder: dec})
	f.providerRegistry.Register("kc", &loginStubHandler{})
	hdr := &capturingHeaderMap{headers: map[string]string{":path": "/oauth/login?provider=kc"}}

	f.handleLogin(hdr)

	if dec.statusCode != 302 {
		t.Fatalf("status = %d, want 302", dec.statusCode)
	}
	name, value := stateCookieNameValue("login-state-1")
	cookies := dec.headers["Set-Cookie"]
	if len(cookies) != 1 || !strings.HasPrefix(cookies[0], name+"="+value+";") {
		t.Errorf("Set-Cookie = %v, want the state cookie %s", cookies, name)
	}
}

// callbackStubHandler completes a callback the way the real handler does:
// it puts the session cookie and the original path into the header map.
type callbackStubHandler struct{ mockOAuthHandler }

func (h *callbackStubHandler) HandleCallback(header api.RequestHeaderMap, _ string) error {
	header.Set("set-cookie", "session_kc=abc; Path=/; HttpOnly")
	header.Set("location", "/app")
	return nil
}

// replyRecordingDecoder records the first local reply for async tests.
type replyRecordingDecoder struct {
	api.DecoderFilterCallbacks
	replies chan map[string][]string
}

func (d *replyRecordingDecoder) SendLocalReply(_ int, _ string, headers map[string][]string, _ int64, _ string) {
	d.replies <- headers
}

func (d *replyRecordingDecoder) RecoverPanic() {}

type replyRecordingCallbacks struct {
	api.FilterCallbackHandler
	decoder *replyRecordingDecoder
}

func (c *replyRecordingCallbacks) DecoderFilterCallbacks() api.DecoderFilterCallbacks {
	return c.decoder
}

// TestHandleCallbackWithStateCookieCompletesAndClearsIt verifies that a
// callback from the browser that started the login completes, sets the
// session cookie and removes the state cookie.
func TestHandleCallbackWithStateCookieCompletesAndClearsIt(t *testing.T) {
	dec := &replyRecordingDecoder{replies: make(chan map[string][]string, 1)}
	f := buildCallbackFilter(&captureCallbacks{})
	f.callbacks = &replyRecordingCallbacks{decoder: dec}
	f.providerRegistry.Register("kc", &callbackStubHandler{})
	if err := session.StorePendingAuth(f.sessionStore, "cb-state", &session.PendingAuth{
		ProviderName: "kc",
		OriginalPath: "/app",
		CodeVerifier: "v",
		Expiry:       time.Now().Add(time.Minute),
	}); err != nil {
		t.Fatalf("StorePendingAuth: %v", err)
	}
	name, value := stateCookieNameValue("cb-state")
	hdr := &capturingHeaderMap{headers: map[string]string{
		":path":  "/oauth/callback?state=cb-state&code=c",
		"cookie": name + "=" + value,
	}}

	if got := f.handleCallback(hdr); got != api.Running {
		t.Fatalf("handleCallback = %v, want api.Running", got)
	}
	var headers map[string][]string
	select {
	case headers = <-dec.replies:
	case <-time.After(2 * time.Second):
		t.Fatal("no reply from async callback")
	}
	if loc := headers["Location"]; len(loc) != 1 || loc[0] != "/app" {
		t.Errorf("Location = %v, want [/app]", loc)
	}
	cookies := strings.Join(headers["Set-Cookie"], "\n")
	if !strings.Contains(cookies, "session_kc=abc") {
		t.Errorf("Set-Cookie %q lacks the session cookie", cookies)
	}
	if !strings.Contains(cookies, name+"=;") {
		t.Errorf("Set-Cookie %q does not clear the state cookie", cookies)
	}
}

// TestHandleCallbackWithoutStateCookieDoesNotComplete verifies that a valid
// state opened in a browser without the state cookie restarts the login in that
// browser instead of completing the other browser's login (issue #11).
func TestHandleCallbackWithoutStateCookieDoesNotComplete(t *testing.T) {
	dec := &captureDecoderCallbacks{}
	f := buildCallbackFilter(&captureCallbacks{decoder: dec})
	f.providerRegistry.Register("kc", &callbackStubHandler{})
	if err := session.StorePendingAuth(f.sessionStore, "foreign-state", &session.PendingAuth{
		ProviderName: "kc",
		OriginalPath: "/app",
		CodeVerifier: "v",
		Expiry:       time.Now().Add(time.Minute),
	}); err != nil {
		t.Fatalf("StorePendingAuth: %v", err)
	}
	hdr := &capturingHeaderMap{headers: map[string]string{":path": "/oauth/callback?state=foreign-state&code=c"}}

	if got := f.handleCallback(hdr); got != api.LocalReply {
		t.Fatalf("handleCallback = %v, want api.LocalReply (no async completion)", got)
	}
	assertRestartResponse(t, dec)
	for _, c := range dec.headers["Set-Cookie"] {
		if strings.Contains(c, "session_kc") {
			t.Errorf("a session cookie was set without the state cookie: %q", c)
		}
	}
}

// TestOfflineCallbackRequiresStateCookie verifies that the API-key callback is
// refused before any code exchange when the state cookie is missing.
func TestOfflineCallbackRequiresStateCookie(t *testing.T) {
	dec := &captureDecoderCallbacks{}
	f := buildCallbackFilter(&captureCallbacks{decoder: dec})
	f.config.EnableAPIKey = true
	hdr := &capturingHeaderMap{headers: map[string]string{}}

	f.handleOfflineCallback(hdr, "/oauth/offline-callback?state=x%7Coffline&code=c")

	if dec.statusCode != 400 {
		t.Errorf("status = %d, want 400", dec.statusCode)
	}
	if !strings.Contains(dec.body, "another browser") {
		t.Errorf("body = %q, want the other-browser message", dec.body)
	}
}
