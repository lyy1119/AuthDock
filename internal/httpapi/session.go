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

// SessionScope separates the two audiences. A management session is never valid
// at the gateway and a gateway session is never valid at the management API.
type SessionScope string

const (
	// ScopeAdmin is the management area behind -addr.
	ScopeAdmin SessionScope = "admin"
	// ScopeGateway is the login portal and the published services.
	ScopeGateway SessionScope = "gateway"
)

// Sessions is the session backend shared by both listeners, with scoped tokens.
type Sessions interface {
	Create(scope SessionScope, username, role string, now time.Time) (string, Session, error)
	Get(scope SessionScope, token string, now time.Time) (Session, bool)
	Delete(scope SessionScope, token string)
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

type sessionKey struct {
	scope SessionScope
	token string
}

// SessionStore keeps sessions in memory. It backs the tests; the binary uses
// DBSessions.
type SessionStore struct {
	mu       sync.Mutex
	sessions map[sessionKey]Session
	ttl      time.Duration
}

// NewSessionStore returns an in-memory store whose sessions live for ttl.
func NewSessionStore(ttl time.Duration) *SessionStore {
	if ttl <= 0 {
		ttl = 12 * time.Hour
	}
	return &SessionStore{
		sessions: make(map[sessionKey]Session),
		ttl:      ttl,
	}
}

// TTL is how long a fresh session stays valid.
func (s *SessionStore) TTL() time.Duration { return s.ttl }

// Create stores a new session for the given scope and returns its token.
func (s *SessionStore) Create(scope SessionScope, username, role string, now time.Time) (string, Session, error) {
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
	s.sessions[sessionKey{scope: scope, token: token}] = session
	return token, session, nil
}

// Get returns the session for token in the given scope when it is still valid.
func (s *SessionStore) Get(scope SessionScope, token string, now time.Time) (Session, bool) {
	if token == "" {
		return Session{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	key := sessionKey{scope: scope, token: token}
	session, ok := s.sessions[key]
	if !ok {
		return Session{}, false
	}
	if !now.Before(session.ExpiresAt) {
		delete(s.sessions, key)
		return Session{}, false
	}
	return session, true
}

// Delete drops the session for token in the given scope, if any.
func (s *SessionStore) Delete(scope SessionScope, token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, sessionKey{scope: scope, token: token})
}

func (s *SessionStore) pruneLocked(now time.Time) {
	for key, session := range s.sessions {
		if !now.Before(session.ExpiresAt) {
			delete(s.sessions, key)
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

// Create stores a new session for the given scope and returns its token.
func (d *DBSessions) Create(scope SessionScope, username, role string, now time.Time) (string, Session, error) {
	token, err := newSessionToken()
	if err != nil {
		return "", Session{}, err
	}
	expires := now.Add(d.ttl)
	if err := d.store.CreateSession(context.Background(), string(scope), hashSessionToken(token), username, role, expires); err != nil {
		return "", Session{}, err
	}
	return token, Session{Username: username, Role: role, ExpiresAt: expires}, nil
}

// Get returns the session for token in the given scope when it is still valid.
func (d *DBSessions) Get(scope SessionScope, token string, now time.Time) (Session, bool) {
	if token == "" {
		return Session{}, false
	}
	session, ok, err := d.store.GetSession(context.Background(), string(scope), hashSessionToken(token), now)
	if err != nil || !ok {
		return Session{}, false
	}
	return Session{Username: session.Username, Role: session.Role, ExpiresAt: session.ExpiresAt}, true
}

// Delete drops the session for token in the given scope, if any.
func (d *DBSessions) Delete(scope SessionScope, token string) {
	_ = d.store.DeleteSession(context.Background(), hashSessionToken(token))
}
