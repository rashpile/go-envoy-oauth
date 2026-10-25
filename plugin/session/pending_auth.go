package session

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
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
	BindingHash  string    // SHA-256 of the browser-binding secret sent as the state cookie
	Expiry       time.Time // When this pending-auth entry expires
}

// NewStateBinding returns a random secret for the browser-binding state cookie
// and the hash to store server-side. The state itself is public (it travels in
// URLs), so the cookie must carry a value that cannot be derived from it.
func NewStateBinding() (secret, hash string, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", fmt.Errorf("generate state binding: %w", err)
	}
	secret = base64.RawURLEncoding.EncodeToString(b)
	return secret, hashStateBinding(secret), nil
}

// StateBindingMatches reports whether secret hashes to hash, in constant time.
func StateBindingMatches(secret, hash string) bool {
	if secret == "" || hash == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(hashStateBinding(secret)), []byte(hash)) == 1
}

func hashStateBinding(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
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
			"binding_hash":  pa.BindingHash,
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

// PeekPendingAuth returns the pending-auth entry for nonce without deleting it,
// so the callback can check the browser binding before the entry is consumed.
func PeekPendingAuth(store SessionStore, nonce string) (*PendingAuth, error) {
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
		return nil, fmt.Errorf("pending-auth entry expired for nonce")
	}
	return pa, nil
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
	bindingHash, _ := sess.Claims["binding_hash"].(string)
	return &PendingAuth{
		ProviderName: provider,
		OriginalPath: originalPath,
		CodeVerifier: codeVerifier,
		BindingHash:  bindingHash,
		Expiry:       sess.ExpiresAt,
	}, nil
}
