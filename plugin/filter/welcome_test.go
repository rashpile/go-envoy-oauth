package filter

import (
	"net/url"
	"strings"
	"testing"
)

// TestWelcomeHomeLinkIsSameOrigin verifies that the "Go to Home" link on the
// welcome page only ever points to a same-origin path (issue #10).
func TestWelcomeHomeLinkIsSameOrigin(t *testing.T) {
	tests := []struct {
		homeURL  string
		wantHref string
	}{
		{"/app/page", `href="/app/page"`},
		{"https://app.example.com/app/page", `href="/app/page"`},
		{"javascript:alert(1)", `href="/"`},
		{"https://other.example.com/", `href="/"`},
	}
	for _, tt := range tests {
		dec := &captureDecoderCallbacks{}
		f := buildCallbackFilter(&captureCallbacks{decoder: dec})
		hdr := &capturingHeaderMap{headers: map[string]string{
			":path":      "/oauth/welcome?home-url=" + url.QueryEscape(tt.homeURL),
			":authority": "app.example.com",
		}}

		f.handleWelcome(hdr)

		if dec.statusCode != 200 {
			t.Fatalf("home-url %q: status = %d, want 200", tt.homeURL, dec.statusCode)
		}
		if !strings.Contains(dec.body, tt.wantHref+` class="home-link"`) {
			t.Errorf("home-url %q: page does not contain %s", tt.homeURL, tt.wantHref)
		}
		if strings.Contains(dec.body, "javascript:") {
			t.Errorf("home-url %q: page contains a javascript: URL", tt.homeURL)
		}
	}
}

// TestWelcomeStateRedirectKeepsOnlySafeHomeURL verifies that the clean-URL
// redirect (taken when the IdP adds a state parameter) carries the sanitized
// home-url, not the raw one.
func TestWelcomeStateRedirectKeepsOnlySafeHomeURL(t *testing.T) {
	dec := &captureDecoderCallbacks{}
	f := buildCallbackFilter(&captureCallbacks{decoder: dec})
	hdr := &capturingHeaderMap{headers: map[string]string{
		":path":      "/oauth/welcome?state=s&home-url=" + url.QueryEscape("javascript:alert(1)"),
		":authority": "app.example.com",
	}}

	f.handleWelcome(hdr)

	if dec.statusCode != 302 {
		t.Fatalf("status = %d, want 302", dec.statusCode)
	}
	if loc := dec.headers["Location"]; len(loc) != 1 || loc[0] != "/oauth/welcome" {
		t.Errorf("Location = %v, want [/oauth/welcome]", loc)
	}
}
