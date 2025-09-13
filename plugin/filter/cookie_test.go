package filter

import (
	"reflect"
	"testing"
)

func TestCookieHelper_ParseCookies(t *testing.T) {
	tests := []struct {
		name         string
		cookieHeader string
		want         map[string]string
	}{
		{
			name:         "empty cookie header",
			cookieHeader: "",
			want:         map[string]string{},
		},
		{
			name:         "single cookie",
			cookieHeader: "name=value",
			want:         map[string]string{"name": "value"},
		},
		{
			name:         "multiple cookies",
			cookieHeader: "name1=value1; name2=value2",
			want:         map[string]string{"name1": "value1", "name2": "value2"},
		},
		{
			name:         "cookies with whitespace",
			cookieHeader: "  name1=value1;  name2=value2  ",
			want:         map[string]string{"name1": "value1", "name2": "value2"},
		},
		{
			name:         "cookies with empty parts",
			cookieHeader: "name1=value1;;name2=value2",
			want:         map[string]string{"name1": "value1", "name2": "value2"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &CookieHelper{settings: DefaultCookieSettings()}
			got := h.ParseCookies(tt.cookieHeader)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("CookieHelper.ParseCookies() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCookieHelper_BuildCookieString(t *testing.T) {
	tests := []struct {
		name     string
		settings CookieSettings
		cookieName  string
		cookieValue string
		want     string
	}{
		{
			name: "basic cookie",
			settings: CookieSettings{
				MaxAge:   3600,
				Path:     "/",
				Secure:   false,
				HttpOnly: false,
			},
			cookieName:  "test",
			cookieValue: "value",
			want:     "test=value; Max-Age=3600; Path=/",
		},
		{
			name: "secure and http only cookie",
			settings: CookieSettings{
				MaxAge:   3600,
				Path:     "/",
				Secure:   true,
				HttpOnly: true,
			},
			cookieName:  "test",
			cookieValue: "value",
			want:     "test=value; Max-Age=3600; Path=/; Secure; HttpOnly",
		},
		{
			name: "cookie with domain and samesite",
			settings: CookieSettings{
				MaxAge:   3600,
				Path:     "/api",
				Domain:   "example.com",
				Secure:   true,
				HttpOnly: true,
				SameSite: "Strict",
			},
			cookieName:  "test",
			cookieValue: "value",
			want:     "test=value; Max-Age=3600; Path=/api; Domain=example.com; Secure; HttpOnly; SameSite=Strict",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &CookieHelper{settings: tt.settings}
			got := h.buildCookieString(tt.cookieName, tt.cookieValue)
			if got != tt.want {
				t.Errorf("CookieHelper.buildCookieString() = %v, want %v", got, tt.want)
			}
		})
	}
}
