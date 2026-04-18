package session

import "testing"

func TestSessionProviderNameField(t *testing.T) {
	t.Run("assignable", func(t *testing.T) {
		s := &Session{ProviderName: "keycloak"}
		if s.ProviderName != "keycloak" {
			t.Errorf("expected ProviderName=%q, got %q", "keycloak", s.ProviderName)
		}
	})

	t.Run("independent_of_IDP", func(t *testing.T) {
		s := &Session{
			IDP:          "keycloak.example.com",
			ProviderName: "keycloak",
		}
		if s.IDP != "keycloak.example.com" {
			t.Errorf("expected IDP to be issuer hostname, got %q", s.IDP)
		}
		if s.ProviderName != "keycloak" {
			t.Errorf("expected ProviderName to be registry key, got %q", s.ProviderName)
		}
		if s.IDP == s.ProviderName {
			t.Error("IDP and ProviderName should be distinct values; they were accidentally conflated")
		}
	})

	t.Run("zero_value", func(t *testing.T) {
		s := &Session{ID: "abc"}
		if s.ProviderName != "" {
			t.Errorf("expected zero-value ProviderName to be empty string, got %q", s.ProviderName)
		}
	})
}
