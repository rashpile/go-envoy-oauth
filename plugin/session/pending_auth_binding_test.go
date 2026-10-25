package session

import (
	"encoding/base64"
	"testing"
	"time"
)

func TestStateBinding(t *testing.T) {
	s1, h1, err := NewStateBinding()
	if err != nil {
		t.Fatalf("NewStateBinding: %v", err)
	}
	s2, _, _ := NewStateBinding()
	if s1 == s2 {
		t.Error("two bindings produced the same secret")
	}
	if !StateBindingMatches(s1, h1) {
		t.Error("secret does not match its own hash")
	}
	if raw, err := base64.RawURLEncoding.DecodeString(s1); err != nil || len(raw) != 32 {
		t.Errorf("secret decodes to %d bytes (err %v), want 32", len(raw), err)
	}
	if len(h1) != 64 {
		t.Errorf("hash length = %d, want 64 hex chars", len(h1))
	}
	for _, tt := range []struct{ secret, hash string }{{s2, h1}, {"", h1}, {s1, ""}, {h1, h1}} {
		if StateBindingMatches(tt.secret, tt.hash) {
			t.Errorf("StateBindingMatches(%q, %q) = true, want false", tt.secret, tt.hash)
		}
	}
}

func TestPeekPendingAuthDoesNotConsume(t *testing.T) {
	store := NewInMemorySessionStore()
	if err := StorePendingAuth(store, "n", &PendingAuth{ProviderName: "kc", OriginalPath: "/", CodeVerifier: "v", BindingHash: "h", Expiry: time.Now().Add(time.Minute)}); err != nil {
		t.Fatalf("StorePendingAuth: %v", err)
	}
	pa, err := PeekPendingAuth(store, "n")
	if err != nil || pa.BindingHash != "h" || pa.ProviderName != "kc" {
		t.Fatalf("PeekPendingAuth = %+v, %v", pa, err)
	}
	if _, err := GetPendingAuth(store, "n"); err != nil {
		t.Errorf("entry was consumed by Peek: %v", err)
	}

	if err := StorePendingAuth(store, "old", &PendingAuth{ProviderName: "kc", OriginalPath: "/", CodeVerifier: "v", Expiry: time.Now().Add(-time.Second)}); err != nil {
		t.Fatalf("StorePendingAuth: %v", err)
	}
	if _, err := PeekPendingAuth(store, "old"); err == nil {
		t.Error("PeekPendingAuth returned an expired entry")
	}
}

// TestStoreHandsOutCopies verifies that sessions read from the store are
// independent copies, so one request changing its copy (for example during a
// token refresh) never writes to a struct another request is reading.
func TestStoreHandsOutCopies(t *testing.T) {
	store := NewInMemorySessionStore()
	if err := store.Store(&Session{ID: "s", Token: "t1", Claims: map[string]interface{}{"k": "v"}, ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatalf("Store: %v", err)
	}
	a, _ := store.Get("s")
	a.Token = "changed"
	a.Claims["k"] = "changed"
	b, _ := store.Get("s")
	if b.Token != "t1" || b.Claims["k"] != "v" {
		t.Errorf("store returned a shared session: token %q, claim %v", b.Token, b.Claims["k"])
	}
}
