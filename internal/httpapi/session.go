package httpapi

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"sync"
	"time"
)

// SessionCookieName is the cookie that carries the admin session token.
const SessionCookieName = "authdock_session"

// ErrSessionToken reports a failure while generating a random token.
var ErrSessionToken = errors.New("httpapi: cannot generate session token")

// Session is an authenticated administrator session. Sessions live in memory
// only: restarting AuthDock signs the administrator out.
type Session struct {
	Username  string
	Role      string
	ExpiresAt time.Time
}

// SessionStore keeps the active sessions, keyed by a random opaque token.
type SessionStore struct {
	mu       sync.Mutex
	sessions map[string]Session
	ttl      time.Duration
}

// NewSessionStore returns a store whose sessions live for ttl (default 12h).
func NewSessionStore(ttl time.Duration) *SessionStore {
	if ttl <= 0 {
		ttl = 12 * time.Hour
	}
	return &SessionStore{
		sessions: make(map[string]Session),
		ttl:      ttl,
	}
}

// TTL is how long a fresh session stays valid.
func (s *SessionStore) TTL() time.Duration { return s.ttl }

// Create stores a new session and returns its token.
func (s *SessionStore) Create(username, role string, now time.Time) (string, Session, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", Session{}, ErrSessionToken
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	session := Session{
		Username:  username,
		Role:      role,
		ExpiresAt: now.Add(s.ttl),
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(now)
	s.sessions[token] = session
	return token, session, nil
}

// Get returns the session for token when it is still valid.
func (s *SessionStore) Get(token string, now time.Time) (Session, bool) {
	if token == "" {
		return Session{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	session, ok := s.sessions[token]
	if !ok {
		return Session{}, false
	}
	if !now.Before(session.ExpiresAt) {
		delete(s.sessions, token)
		return Session{}, false
	}
	return session, true
}

// Delete drops the session for token, if any.
func (s *SessionStore) Delete(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, token)
}

func (s *SessionStore) pruneLocked(now time.Time) {
	for token, session := range s.sessions {
		if !now.Before(session.ExpiresAt) {
			delete(s.sessions, token)
		}
	}
}
