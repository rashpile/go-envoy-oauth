package session

import (
	"encoding/base64"
	"errors"
	"fmt"
	"math/rand"
	"sync"
	"time"
)

// Session represents a user session
type Session struct {
	ID              string                 // Unique session ID
	UserID          string                 // User identifier from OAuth provider
	Token           string                 // OAuth access token
	TokenExpiresAt  time.Time              // When the access token expires
	IDToken         string                 // OAuth ID token for logout hint
	RefreshToken    string                 // OAuth refresh token (API key)
	IDP             string                 // Identity provider hostname for metrics
	Claims          map[string]interface{} // Additional claims from token
	CreatedAt       time.Time              // When the session was created
	ExpiresAt       time.Time              // When the session expires
}

// IsExpired checks if the session has expired
func (s *Session) IsExpired() bool {
	return time.Now().After(s.ExpiresAt)
}

// NeedsRefresh checks if the session needs a token refresh
// Returns true if the session will expire within 5 minutes
func (s *Session) NeedsRefresh() bool {
	return time.Until(s.ExpiresAt) < 5*time.Minute
}

// SessionStore defines the interface for session storage
type SessionStore interface {
	// Get retrieves a session by ID
	Get(id string) (*Session, error)

	// Store stores a new session or updates an existing one
	Store(session *Session) error

	// Delete removes a session
	Delete(id string) error

	// Cleanup removes expired sessions
	Cleanup()
}

// InMemorySessionStore implements SessionStore using in-memory storage
type InMemorySessionStore struct {
	sessions map[string]*Session
	mu       sync.RWMutex
}

// NewInMemorySessionStore creates a new in-memory session store
func NewInMemorySessionStore() *InMemorySessionStore {
	store := &InMemorySessionStore{
		sessions: make(map[string]*Session),
	}

	// Start cleanup goroutine
	go store.cleanupRoutine()

	return store
}

// Get retrieves a session by ID
func (s *InMemorySessionStore) Get(id string) (*Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	session, exists := s.sessions[id]
	if !exists {
		return nil, fmt.Errorf("session not found")
	}

	if session.IsExpired() {
		delete(s.sessions, id)
		return nil, fmt.Errorf("session expired")
	}

	return session, nil
}

// Store stores a new session or updates an existing one
func (s *InMemorySessionStore) Store(session *Session) error {
	if session == nil {
		return errors.New("session cannot be nil")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.sessions[session.ID] = session
	return nil
}

// Delete removes a session
func (s *InMemorySessionStore) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.sessions[id]; !exists {
		return fmt.Errorf("session not found")
	}

	delete(s.sessions, id)
	return nil
}

// Cleanup removes expired sessions
func (s *InMemorySessionStore) Cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for id, session := range s.sessions {
		if now.After(session.ExpiresAt) {
			delete(s.sessions, id)
		}
	}
}

// startCleanup runs a background goroutine to clean up expired sessions
func (s *InMemorySessionStore) cleanupRoutine() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		s.Cleanup()
	}
}

// NewSession creates a new session with the given parameters
func NewSession(userID, token string, claims map[string]interface{}, expiresAt time.Time) *Session {
	return &Session{
		ID:        generateRandomID(),
		UserID:    userID,
		Token:     token,
		Claims:    claims,
		CreatedAt: time.Now(),
		ExpiresAt: expiresAt,
	}
}

func generateRandomID() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.URLEncoding.EncodeToString(b)
}
