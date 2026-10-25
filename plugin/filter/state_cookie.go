package filter

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/url"

	"github.com/envoyproxy/envoy/contrib/golang/common/go/api"
)

// State cookies bind an OAuth state to the browser that started the login, so
// a callback URL opened in another browser cannot complete that login there
// (issue #11). Each login gets its own cookie name, so parallel logins in
// several tabs do not overwrite each other.

const (
	stateCookiePrefix = "oauth_state_"
	callbackPath      = "/oauth/callback"
	offlineCallback   = "/oauth/offline-callback"
	// stateCookieMaxAge matches the pending-auth lifetime (5 minutes).
	stateCookieMaxAge = 300
)

func stateCookieNameValue(state string) (string, string) {
	sum := sha256.Sum256([]byte(state))
	full := hex.EncodeToString(sum[:])
	return stateCookiePrefix + full[:16], full
}

// stateCookie returns the Set-Cookie value that binds state to this browser.
// path limits the cookie to the callback endpoint of the flow.
func (f *Filter) stateCookie(state, path string) string {
	name, value := stateCookieNameValue(state)
	c := &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     path,
		MaxAge:   stateCookieMaxAge,
		HttpOnly: true,
		Secure:   f.config.SessionSecure,
		SameSite: http.SameSiteLaxMode,
	}
	return c.String()
}

// clearStateCookie returns the Set-Cookie value that removes the state cookie.
func (f *Filter) clearStateCookie(state, path string) string {
	name, _ := stateCookieNameValue(state)
	c := &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     path,
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   f.config.SessionSecure,
		SameSite: http.SameSiteLaxMode,
	}
	return c.String()
}

// hasStateCookie reports whether the request carries the cookie set for state.
func hasStateCookie(header api.RequestHeaderMap, state string) bool {
	raw, _ := header.Get("cookie")
	if raw == "" || state == "" {
		return false
	}
	name, value := stateCookieNameValue(state)
	req := &http.Request{Header: http.Header{"Cookie": {raw}}}
	c, err := req.Cookie(name)
	return err == nil && c.Value == value
}

// stateFromAuthURL returns the state query parameter of an authorization URL.
func stateFromAuthURL(authURL string) string {
	u, err := url.Parse(authURL)
	if err != nil {
		return ""
	}
	return u.Query().Get("state")
}
