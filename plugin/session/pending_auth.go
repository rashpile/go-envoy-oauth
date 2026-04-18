package session

import (
	"fmt"
	"time"
)

// PendingAuthUserID is the sentinel UserID stored in session entries for pending-auth state.
// This distinguishes pending-auth entries from real user sessions.
const PendingAuthUserID = "__pending__"

// PendingAuthPrefix is the key prefix for pending-auth entries in the session store.
// Prefixing avoids collisions with real session IDs (D-01, Pitfall 3).
const PendingAuthPrefix = "pending:"

// PendingAuth holds the server-side state for an in-flight OAuth authorization code flow.
// It is keyed by a random nonce and stores the provider name, original request path,
// and PKCE code verifier until the callback arrives (D-01, D-02, D-05).
type PendingAuth struct {
	ProviderName string    // Name of the provider that initiated the flow
	OriginalPath string    // Original request path to redirect to after auth
	CodeVerifier string    // PKCE S256 code verifier (stored for callback exchange)
	Expiry       time.Time // When this pending-auth entry expires
}

// StorePendingAuth encodes pa into a Session and stores it in the session store keyed
// by PendingAuthPrefix + nonce. The sentinel UserID "__pending__" marks it as
// a pending-auth entry rather than a real user session.
func StorePendingAuth(store SessionStore, nonce string, pa *PendingAuth) error {
	sess := &Session{
		ID:     PendingAuthPrefix + nonce,
		UserID: PendingAuthUserID,
		Claims: map[string]interface{}{
			"provider":      pa.ProviderName,
			"original_path": pa.OriginalPath,
			"code_verifier": pa.CodeVerifier,
		},
		CreatedAt: time.Now(),
		ExpiresAt: pa.Expiry,
	}
	return store.Store(sess)
}

// GetPendingAuth retrieves the PendingAuth for the given nonce and deletes it from the
// session store (single-use per D-01). Returns an error if the entry does not exist,
// has expired, or does not carry the expected sentinel UserID.
func GetPendingAuth(store SessionStore, nonce string) (*PendingAuth, error) {
	sess, err := store.Get(PendingAuthPrefix + nonce)
	if err != nil {
		return nil, fmt.Errorf("pending-auth not found for nonce: %w", err)
	}

	if sess.UserID != PendingAuthUserID {
		return nil, fmt.Errorf("invalid pending-auth entry: unexpected UserID %q", sess.UserID)
	}

	pa, err := decodePendingAuth(sess)
	if err != nil {
		return nil, err
	}

	if time.Now().After(pa.Expiry) {
		_ = store.Delete(PendingAuthPrefix + nonce)
		return nil, fmt.Errorf("pending-auth entry expired for nonce")
	}

	// Delete after successful retrieval — single-use semantics (D-01).
	if delErr := store.Delete(PendingAuthPrefix + nonce); delErr != nil {
		// Non-fatal: return the decoded value anyway; worst case a second callback attempt fails.
		_ = delErr
	}

	return pa, nil
}

// PeekPendingAuthProvider returns the provider name from the pending-auth entry for the
// given nonce without deleting it. This allows handleCallback (Plan 02-02) to resolve
// the provider handler before delegating to HandleCallback, which will consume the entry
// via GetPendingAuth.
func PeekPendingAuthProvider(store SessionStore, nonce string) (string, error) {
	sess, err := store.Get(PendingAuthPrefix + nonce)
	if err != nil {
		return "", fmt.Errorf("pending-auth not found for nonce: %w", err)
	}

	if sess.UserID != PendingAuthUserID {
		return "", fmt.Errorf("invalid pending-auth entry: unexpected UserID %q", sess.UserID)
	}

	provider, ok := sess.Claims["provider"].(string)
	if !ok || provider == "" {
		return "", fmt.Errorf("pending-auth entry missing provider name")
	}

	return provider, nil
}

// decodePendingAuth extracts PendingAuth fields from a Session's Claims map.
func decodePendingAuth(sess *Session) (*PendingAuth, error) {
	provider, ok := sess.Claims["provider"].(string)
	if !ok {
		return nil, fmt.Errorf("pending-auth: missing or invalid 'provider' claim")
	}
	originalPath, ok := sess.Claims["original_path"].(string)
	if !ok {
		return nil, fmt.Errorf("pending-auth: missing or invalid 'original_path' claim")
	}
	codeVerifier, ok := sess.Claims["code_verifier"].(string)
	if !ok {
		return nil, fmt.Errorf("pending-auth: missing or invalid 'code_verifier' claim")
	}
	return &PendingAuth{
		ProviderName: provider,
		OriginalPath: originalPath,
		CodeVerifier: codeVerifier,
		Expiry:       sess.ExpiresAt,
	}, nil
}
