package httpapi

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"github.com/lyy1119/AuthDock/internal/store"
)

// SessionCookieName is the cookie that carries the management session. It is
// host-only on purpose: the admin session must never travel to the services the
// gateway publishes.
const SessionCookieName = "authdock_session"

// ErrSessionToken reports a failure while generating a random token.
var ErrSessionToken = errors.New("httpapi: cannot generate session token")

// Session is an authenticated account session.
type Session struct {
	Username  string
	Role      string
	ExpiresAt time.Time
}

// Sessions is the session backend. The gateway and the management API share it,
// so one login covers both.
type Sessions interface {
	Create(username, role string, now time.Time) (string, Session, error)
	Get(token string, now time.Time) (Session, bool)
	Delete(token string)
	TTL() time.Duration
}

// newSessionToken returns a fresh opaque token.
func newSessionToken() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", ErrSessionToken
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// hashSessionToken maps a token to the value stored in the database, so a leaked
// database does not leak usable sessions.
func hashSessionToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// SessionStore keeps sessions in memory. It backs the tests and the pure
// portal listener; the binary uses DBSessions.
type SessionStore struct {
	mu       sync.Mutex
	sessions map[string]Session
	ttl      time.Duration
}

// NewSessionStore returns an in-memory store whose sessions live for ttl.
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
	token, err := newSessionToken()
	if err != nil {
		return "", Session{}, err
	}
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

// DBSessions persists sessions in SQLite, so restarting AuthDock no longer signs
// everybody out and the gateway can grow to more than one process later.
type DBSessions struct {
	store *store.Store
	ttl   time.Duration
}

// NewDBSessions returns a database backed session store.
func NewDBSessions(st *store.Store, ttl time.Duration) *DBSessions {
	if ttl <= 0 {
		ttl = 12 * time.Hour
	}
	return &DBSessions{store: st, ttl: ttl}
}

// TTL is how long a fresh session stays valid.
func (d *DBSessions) TTL() time.Duration { return d.ttl }

// Create stores a new session and returns its token.
func (d *DBSessions) Create(username, role string, now time.Time) (string, Session, error) {
	token, err := newSessionToken()
	if err != nil {
		return "", Session{}, err
	}
	expires := now.Add(d.ttl)
	if err := d.store.CreateSession(context.Background(), hashSessionToken(token), username, role, expires); err != nil {
		return "", Session{}, err
	}
	return token, Session{Username: username, Role: role, ExpiresAt: expires}, nil
}

// Get returns the session for token when it is still valid.
func (d *DBSessions) Get(token string, now time.Time) (Session, bool) {
	if token == "" {
		return Session{}, false
	}
	session, ok, err := d.store.GetSession(context.Background(), hashSessionToken(token), now)
	if err != nil || !ok {
		return Session{}, false
	}
	return Session{Username: session.Username, Role: session.Role, ExpiresAt: session.ExpiresAt}, true
}

// Delete drops the session for token, if any.
func (d *DBSessions) Delete(token string) {
	_ = d.store.DeleteSession(context.Background(), hashSessionToken(token))
}
