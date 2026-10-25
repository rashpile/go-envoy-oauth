package filter

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/envoyproxy/envoy/contrib/golang/common/go/api"
	"github.com/rashpile/go-envoy-oauth/plugin/oauth"
	"github.com/rashpile/go-envoy-oauth/plugin/session"
)

func cookieHeader(state, value string) string {
	return stateCookieName(state) + "=" + value
}

func TestStateSetCookieAttributes(t *testing.T) {
	f := &Filter{config: &OAuthConfig{SessionSecure: true, SessionDomain: "example.com"}}
	set := f.stateSetCookie("state-1", "secret", callbackPath, stateCookieMaxAge)
	for _, attr := range []string{stateCookieName("state-1") + "=secret", "Path=/oauth/callback", "Domain=example.com", "Max-Age=300", "HttpOnly", "Secure", "SameSite=Lax"} {
		if !strings.Contains(set, attr) {
			t.Errorf("state cookie %q lacks %s", set, attr)
		}
	}

	insecure := (&Filter{config: &OAuthConfig{}}).stateSetCookie("state-1", "secret", callbackPath, stateCookieMaxAge)
	if strings.Contains(insecure, "Secure") || strings.Contains(insecure, "Domain=") {
		t.Errorf("cookie with session_secure off and no session_domain = %q, want no Secure and no Domain", insecure)
	}

	removed := f.stateSetCookie("state-1", "", callbackPath, -1)
	if !strings.HasPrefix(removed, stateCookieName("state-1")+"=;") || !strings.Contains(removed, "Max-Age=0") {
		t.Errorf("removal cookie = %q, want an expired %s", removed, stateCookieName("state-1"))
	}
}

func TestStateCookieMatches(t *testing.T) {
	secret, hash, err := session.NewStateBinding()
	if err != nil {
		t.Fatalf("NewStateBinding: %v", err)
	}
	stateSum := sha256.Sum256([]byte("state-1"))
	tests := []struct {
		name   string
		cookie string
		want   bool
	}{
		{"secret", cookieHeader("state-1", secret), true},
		{"secret among others", "a=b; " + cookieHeader("state-1", secret) + "; c=d", true},
		{"planted duplicate first", cookieHeader("state-1", "planted") + "; " + cookieHeader("state-1", secret), true},
		{"malformed JSON neighbour", `prefs={"a":1}; ` + cookieHeader("state-1", secret), true},
		{"nameless neighbour", "bad; " + cookieHeader("state-1", secret), true},
		{"trailing semicolon", cookieHeader("state-1", secret) + ";", true},
		{"wrong secret", cookieHeader("state-1", "wrong"), false},
		{"value derived from the public state", cookieHeader("state-1", hex.EncodeToString(stateSum[:])), false},
		{"secret under another state's name", cookieHeader("state-2", secret), false},
		{"no cookie", "", false},
	}
	for _, tt := range tests {
		hdr := &capturingHeaderMap{headers: map[string]string{"cookie": tt.cookie}}
		if got := stateCookieMatches(hdr, "state-1", hash); got != tt.want {
			t.Errorf("%s: stateCookieMatches = %v, want %v", tt.name, got, tt.want)
		}
	}
	hdr := &capturingHeaderMap{headers: map[string]string{"cookie": cookieHeader("state-1", secret)}}
	if stateCookieMatches(hdr, "state-1", "") {
		t.Error("an entry without a stored binding hash must not match")
	}
}

// loginStubHandler answers HandleAuthRedirect like the real handler: the
// authorization URL with the state, and the binding secret for the cookie.
type loginStubHandler struct {
	mockOAuthHandler
	secret string
}

func (h *loginStubHandler) HandleAuthRedirect(header api.RequestHeaderMap, _ string) error {
	header.Set("location", "https://idp.example.com/auth?client_id=gateway&state=login-state-1")
	if h.secret != "" {
		header.Set(oauth.StateBindingHeader, h.secret)
	}
	return nil
}

// TestHandleLoginSetsStateCookie verifies that the login redirect binds its
// state to the browser with a secret cookie scoped to the callback (issue #11).
func TestHandleLoginSetsStateCookie(t *testing.T) {
	dec := &captureDecoderCallbacks{}
	f := buildCallbackFilter(&captureCallbacks{decoder: dec})
	f.providerRegistry.Register("kc", &loginStubHandler{secret: "s3cret"})
	hdr := &capturingHeaderMap{headers: map[string]string{":path": "/oauth/login?provider=kc"}}

	f.handleLogin(hdr)

	if dec.statusCode != 302 {
		t.Fatalf("status = %d, want 302", dec.statusCode)
	}
	cookies := dec.headers["Set-Cookie"]
	if len(cookies) != 1 || !strings.HasPrefix(cookies[0], cookieHeader("login-state-1", "s3cret")+";") || !strings.Contains(cookies[0], "Path=/oauth/callback") {
		t.Errorf("Set-Cookie = %v, want the state cookie with the binding secret on /oauth/callback", cookies)
	}
	if _, ok := hdr.headers[oauth.StateBindingHeader]; ok {
		t.Error("the internal binding header must be removed from the request")
	}
}

func TestHandleLoginWithoutBindingFails(t *testing.T) {
	dec := &captureDecoderCallbacks{}
	f := buildCallbackFilter(&captureCallbacks{decoder: dec})
	f.providerRegistry.Register("kc", &loginStubHandler{})
	hdr := &capturingHeaderMap{headers: map[string]string{":path": "/oauth/login?provider=kc"}}

	f.handleLogin(hdr)

	if dec.statusCode != 500 {
		t.Errorf("status = %d, want 500 when the handler returns no binding secret", dec.statusCode)
	}
	if len(dec.headers["Set-Cookie"]) != 0 {
		t.Errorf("Set-Cookie = %v, want none", dec.headers["Set-Cookie"])
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

func storeBoundPending(t *testing.T, store session.SessionStore, state string) string {
	t.Helper()
	secret, hash, err := session.NewStateBinding()
	if err != nil {
		t.Fatalf("NewStateBinding: %v", err)
	}
	if err := session.StorePendingAuth(store, state, &session.PendingAuth{
		ProviderName: "kc",
		OriginalPath: "/app",
		CodeVerifier: "v",
		BindingHash:  hash,
		Expiry:       time.Now().Add(time.Minute),
	}); err != nil {
		t.Fatalf("StorePendingAuth: %v", err)
	}
	return secret
}

// TestHandleCallbackWithStateCookieCompletesAndClearsIt verifies that a
// callback from the browser that started the login completes, sets the
// session cookie and removes the state cookie.
func TestHandleCallbackWithStateCookieCompletesAndClearsIt(t *testing.T) {
	dec := &replyRecordingDecoder{replies: make(chan map[string][]string, 1)}
	f := buildCallbackFilter(&captureCallbacks{})
	f.callbacks = &replyRecordingCallbacks{decoder: dec}
	f.providerRegistry.Register("kc", &callbackStubHandler{})
	secret := storeBoundPending(t, f.sessionStore, "cb-state")
	hdr := &capturingHeaderMap{headers: map[string]string{
		":path":  "/oauth/callback?state=cb-state&code=c",
		"cookie": cookieHeader("cb-state", secret),
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
	if !strings.Contains(cookies, stateCookieName("cb-state")+"=;") {
		t.Errorf("Set-Cookie %q does not clear the state cookie", cookies)
	}
}

// TestHandleCallbackWithoutBoundCookieDoesNotComplete verifies that a valid
// state opened in a browser without the right state cookie restarts the login
// there instead of completing the other browser's login, and leaves the
// pending login of the original browser in place (issue #11).
func TestHandleCallbackWithoutBoundCookieDoesNotComplete(t *testing.T) {
	stateSum := sha256.Sum256([]byte("foreign-state"))
	for name, cookie := range map[string]string{
		"no cookie":                "",
		"value derived from state": cookieHeader("foreign-state", hex.EncodeToString(stateSum[:])),
		"another login's secret":   cookieHeader("foreign-state", "guess"),
	} {
		t.Run(name, func(t *testing.T) {
			dec := &captureDecoderCallbacks{}
			f := buildCallbackFilter(&captureCallbacks{decoder: dec})
			f.providerRegistry.Register("kc", &callbackStubHandler{})
			storeBoundPending(t, f.sessionStore, "foreign-state")
			hdr := &capturingHeaderMap{headers: map[string]string{
				":path":  "/oauth/callback?state=foreign-state&code=c",
				"cookie": cookie,
			}}

			if got := f.handleCallback(hdr); got != api.LocalReply {
				t.Fatalf("handleCallback = %v, want api.LocalReply (no async completion)", got)
			}
			assertRestartResponse(t, dec)
			if _, err := session.PeekPendingAuth(f.sessionStore, "foreign-state"); err != nil {
				t.Errorf("pending login was consumed: %v", err)
			}
		})
	}
}

// TestOfflineStateCookieRoundTrip verifies that the API-key redirect sets the
// state cookie on the offline callback path and the callback check accepts it.
func TestOfflineStateCookieRoundTrip(t *testing.T) {
	f := buildCallbackFilter(&captureCallbacks{})
	secret, hash, err := session.NewStateBinding()
	if err != nil {
		t.Fatalf("NewStateBinding: %v", err)
	}
	const state = "abc|offline"
	headers := map[string][]string{
		"Location":               {"https://idp.example.com/auth?state=" + "abc%7Coffline"},
		oauth.StateBindingHeader: {secret},
	}

	if !f.attachOfflineStateCookie(headers) {
		t.Fatal("attachOfflineStateCookie = false, want true")
	}
	if _, ok := headers[oauth.StateBindingHeader]; ok {
		t.Error("the internal binding header must not reach the response")
	}
	cookies := headers["Set-Cookie"]
	if len(cookies) != 1 || !strings.HasPrefix(cookies[0], cookieHeader(state, secret)+";") || !strings.Contains(cookies[0], "Path=/oauth/offline-callback") {
		t.Fatalf("Set-Cookie = %v, want the state cookie on /oauth/offline-callback", cookies)
	}

	if err := f.sessionStore.Store(&session.Session{
		ID:        state,
		Claims:    map[string]interface{}{"binding_hash": hash},
		ExpiresAt: time.Now().Add(time.Minute),
	}); err != nil {
		t.Fatalf("store state session: %v", err)
	}
	if !f.offlineStateBound(&capturingHeaderMap{headers: map[string]string{"cookie": cookieHeader(state, secret)}}, state) {
		t.Error("offlineStateBound rejected the cookie set by the redirect")
	}
	if f.offlineStateBound(&capturingHeaderMap{headers: map[string]string{}}, state) {
		t.Error("offlineStateBound accepted a request without the cookie")
	}

	if f.attachOfflineStateCookie(map[string][]string{"Location": {"https://idp.example.com/auth?state=x"}}) {
		t.Error("attachOfflineStateCookie must fail without a binding secret")
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

func TestHasOAuthRestartCookie(t *testing.T) {
	for cookie, want := range map[string]bool{
		"oauth_restart=1":                true,
		"oauth_restart=1;":               true,
		`prefs={"a":1}; oauth_restart=1`: true,
		"bad; oauth_restart=1; lang=x":   true,
		"oauth_restart=0":                false,
		"oauth_restart_other=1":          false,
		"":                               false,
	} {
		hdr := &capturingHeaderMap{headers: map[string]string{"cookie": cookie}}
		if got := hasOAuthRestartCookie(hdr); got != want {
			t.Errorf("hasOAuthRestartCookie(%q) = %v, want %v", cookie, got, want)
		}
	}
}

// TestOfflineStateBoundRejectsUnboundCookies verifies the offline callback
// check against values that do not prove the browser started the login.
func TestOfflineStateBoundRejectsUnboundCookies(t *testing.T) {
	f := buildCallbackFilter(&captureCallbacks{})
	_, hash, err := session.NewStateBinding()
	if err != nil {
		t.Fatalf("NewStateBinding: %v", err)
	}
	const state = "bound|offline"
	const unboundState = "nohash|offline"
	for id, claims := range map[string]map[string]interface{}{
		state:        {"binding_hash": hash},
		unboundState: {"type": "offline_token"},
	} {
		if err := f.sessionStore.Store(&session.Session{ID: id, Claims: claims, ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
			t.Fatalf("store: %v", err)
		}
	}
	stateSum := sha256.Sum256([]byte(state))
	for name, tc := range map[string]struct{ state, cookie string }{
		"wrong secret":               {state, cookieHeader(state, "wrong")},
		"value derived from state":   {state, cookieHeader(state, hex.EncodeToString(stateSum[:]))},
		"entry without binding hash": {unboundState, cookieHeader(unboundState, "anything")},
	} {
		hdr := &capturingHeaderMap{headers: map[string]string{"cookie": tc.cookie}}
		if f.offlineStateBound(hdr, tc.state) {
			t.Errorf("%s: offlineStateBound = true, want false", name)
		}
	}
}

// TestHandleCallbackRejectsEntryWithoutBindingHash verifies that a pending
// login stored without a binding hash (for example from before the upgrade)
// restarts instead of completing with any cookie of the right name.
func TestHandleCallbackRejectsEntryWithoutBindingHash(t *testing.T) {
	dec := &captureDecoderCallbacks{}
	f := buildCallbackFilter(&captureCallbacks{decoder: dec})
	f.providerRegistry.Register("kc", &callbackStubHandler{})
	if err := session.StorePendingAuth(f.sessionStore, "legacy-state", &session.PendingAuth{
		ProviderName: "kc",
		OriginalPath: "/app",
		CodeVerifier: "v",
		Expiry:       time.Now().Add(time.Minute),
	}); err != nil {
		t.Fatalf("StorePendingAuth: %v", err)
	}
	hdr := &capturingHeaderMap{headers: map[string]string{
		":path":  "/oauth/callback?state=legacy-state&code=c",
		"cookie": cookieHeader("legacy-state", "anything"),
	}}

	if got := f.handleCallback(hdr); got != api.LocalReply {
		t.Fatalf("handleCallback = %v, want api.LocalReply", got)
	}
	assertRestartResponse(t, dec)
	if _, err := session.PeekPendingAuth(f.sessionStore, "legacy-state"); err != nil {
		t.Errorf("pending login was consumed: %v", err)
	}
}

// noStateLoginStub returns a binding secret but an authorization URL without a state.
type noStateLoginStub struct{ mockOAuthHandler }

func (h *noStateLoginStub) HandleAuthRedirect(header api.RequestHeaderMap, _ string) error {
	header.Set("location", "https://idp.example.com/auth?client_id=gateway")
	header.Set(oauth.StateBindingHeader, "s3cret")
	return nil
}

func TestHandleLoginWithoutStateFails(t *testing.T) {
	dec := &captureDecoderCallbacks{}
	f := buildCallbackFilter(&captureCallbacks{decoder: dec})
	f.providerRegistry.Register("kc", &noStateLoginStub{})

	f.handleLogin(&capturingHeaderMap{headers: map[string]string{":path": "/oauth/login?provider=kc"}})

	if dec.statusCode != 500 || len(dec.headers["Set-Cookie"]) != 0 {
		t.Errorf("status = %d, Set-Cookie = %v, want 500 and no cookie", dec.statusCode, dec.headers["Set-Cookie"])
	}
}
