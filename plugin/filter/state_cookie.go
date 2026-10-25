package filter

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/url"

	"github.com/envoyproxy/envoy/contrib/golang/common/go/api"
	"github.com/rashpile/go-envoy-oauth/plugin/session"
)

// State cookies bind an OAuth state to the browser that started the login, so
// a callback URL opened in another browser cannot complete that login there
// (issue #11). The cookie value is a random secret whose hash is stored with
// the pending login; the state alone is public and is not enough. Each login
// gets its own cookie name, so parallel logins in several tabs do not collide.
//
// The cookie is host-only unless session_domain is set, so the callback must be
// served on the host where the login started (or within session_domain).

const (
	stateCookiePrefix = "oauth_state_"
	callbackPath      = "/oauth/callback"
	offlineCallback   = "/oauth/offline-callback"
	// stateCookieMaxAge matches the pending-auth lifetime (5 minutes).
	stateCookieMaxAge = 300
)

func stateCookieName(state string) string {
	sum := sha256.Sum256([]byte(state))
	return stateCookiePrefix + hex.EncodeToString(sum[:8])
}

// stateSetCookie returns a Set-Cookie value for the state cookie of state.
// A negative maxAge removes the cookie.
func (f *Filter) stateSetCookie(state, value, path string, maxAge int) string {
	c := &http.Cookie{
		Name:     stateCookieName(state),
		Value:    value,
		Path:     path,
		Domain:   f.config.SessionDomain,
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   f.config.SessionSecure,
		SameSite: http.SameSiteLaxMode,
	}
	return c.String()
}

// stateCookieMatches reports whether the request carries a state cookie for
// state whose secret hashes to bindingHash. Every cookie with that name is
// tried, so a second cookie planted under the same name cannot shadow the
// real one.
func stateCookieMatches(header api.RequestHeaderMap, state, bindingHash string) bool {
	if state == "" || bindingHash == "" {
		return false
	}
	for _, c := range cookiesNamed(header, stateCookieName(state)) {
		if session.StateBindingMatches(c.Value, bindingHash) {
			return true
		}
	}
	return false
}

// cookiesNamed returns every request cookie with the given name. Malformed
// pairs from other apps on the same host are skipped instead of making the
// whole header unreadable (http.ParseCookie rejects the header outright).
func cookiesNamed(header api.RequestHeaderMap, name string) []*http.Cookie {
	raw, _ := header.Get("cookie")
	if raw == "" {
		return nil
	}
	req := &http.Request{Header: http.Header{"Cookie": {raw}}}
	return req.CookiesNamed(name)
}

// stateFromAuthURL returns the state query parameter of an authorization URL.
func stateFromAuthURL(authURL string) string {
	u, err := url.Parse(authURL)
	if err != nil {
		return ""
	}
	return u.Query().Get("state")
}
