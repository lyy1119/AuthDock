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

// DefaultRefreshTTL is how long a refresh token stays usable.
const DefaultRefreshTTL = 30 * 24 * time.Hour

var (
	// ErrSessionToken reports a failure while generating a random token.
	ErrSessionToken = errors.New("httpapi: cannot generate session token")
	// ErrRefreshInvalid reports a refresh token that is unknown, already used or
	// expired.
	ErrRefreshInvalid = errors.New("httpapi: refresh token is not usable")
)

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

// Issued is the token pair handed out by a login or a refresh.
type Issued struct {
	Access        string
	Refresh       string
	AccessExpiry  time.Time
	RefreshExpiry time.Time
}

// Sessions is the session backend shared by both listeners, with scoped tokens.
//
// A login hands out an access token (short lived, presented on every request)
// and a refresh token (long lived, exchanged exactly once for a new pair).
type Sessions interface {
	Issue(scope SessionScope, username, role string, now time.Time) (Issued, error)
	Refresh(scope SessionScope, refreshToken string, now time.Time) (Issued, error)
	Get(scope SessionScope, token string, now time.Time) (Session, bool)
	// Delete revokes the whole login the token belongs to, refresh token included.
	Delete(scope SessionScope, token string)
	TTL() time.Duration
	RefreshTTL() time.Duration
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

// ── in-memory backend (tests) ───────────────────────────────────────────

type sessionKey struct {
	scope SessionScope
	token string
}

type sessionRow struct {
	session Session
	kind    string
	family  string
}

// SessionStore keeps sessions in memory. It backs the tests; the binary uses
// DBSessions.
type SessionStore struct {
	mu         sync.Mutex
	rows       map[sessionKey]sessionRow
	ttl        time.Duration
	refreshTTL time.Duration
}

// NewSessionStore returns an in-memory store with the given lifetimes.
func NewSessionStore(ttl, refreshTTL time.Duration) *SessionStore {
	if ttl <= 0 {
		ttl = 12 * time.Hour
	}
	if refreshTTL <= 0 {
		refreshTTL = DefaultRefreshTTL
	}
	return &SessionStore{
		rows:       make(map[sessionKey]sessionRow),
		ttl:        ttl,
		refreshTTL: refreshTTL,
	}
}

// TTL is how long a fresh access token stays valid.
func (s *SessionStore) TTL() time.Duration { return s.ttl }

// RefreshTTL is how long a fresh refresh token stays valid.
func (s *SessionStore) RefreshTTL() time.Duration { return s.refreshTTL }

// Issue creates a new login and returns its token pair.
func (s *SessionStore) Issue(scope SessionScope, username, role string, now time.Time) (Issued, error) {
	access, err := newSessionToken()
	if err != nil {
		return Issued{}, err
	}
	refresh, err := newSessionToken()
	if err != nil {
		return Issued{}, err
	}

	session := Session{Username: username, Role: role, ExpiresAt: now.Add(s.ttl)}
	issued := Issued{
		Access:        access,
		Refresh:       refresh,
		AccessExpiry:  session.ExpiresAt,
		RefreshExpiry: now.Add(s.refreshTTL),
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(now)
	s.rows[sessionKey{scope, access}] = sessionRow{session: session, kind: store.SessionKindAccess, family: access}
	s.rows[sessionKey{scope, refresh}] = sessionRow{
		session: Session{Username: username, Role: role, ExpiresAt: issued.RefreshExpiry},
		kind:    store.SessionKindRefresh,
		family:  access,
	}
	return issued, nil
}

// Refresh consumes a refresh token and returns a new pair.
func (s *SessionStore) Refresh(scope SessionScope, refreshToken string, now time.Time) (Issued, error) {
	if refreshToken == "" {
		return Issued{}, ErrRefreshInvalid
	}

	s.mu.Lock()
	key := sessionKey{scope, refreshToken}
	row, ok := s.rows[key]
	if !ok || row.kind != store.SessionKindRefresh || !now.Before(row.session.ExpiresAt) {
		delete(s.rows, key)
		s.mu.Unlock()
		return Issued{}, ErrRefreshInvalid
	}
	delete(s.rows, key)
	username, role := row.session.Username, row.session.Role
	s.mu.Unlock()

	access, err := newSessionToken()
	if err != nil {
		return Issued{}, err
	}
	refresh, err := newSessionToken()
	if err != nil {
		return Issued{}, err
	}
	issued := Issued{
		Access:        access,
		Refresh:       refresh,
		AccessExpiry:  now.Add(s.ttl),
		RefreshExpiry: now.Add(s.refreshTTL),
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.rows[sessionKey{scope, access}] = sessionRow{
		session: Session{Username: username, Role: role, ExpiresAt: issued.AccessExpiry},
		kind:    store.SessionKindAccess,
		family:  row.family,
	}
	s.rows[sessionKey{scope, refresh}] = sessionRow{
		session: Session{Username: username, Role: role, ExpiresAt: issued.RefreshExpiry},
		kind:    store.SessionKindRefresh,
		family:  row.family,
	}
	return issued, nil
}

// Get returns the access session for token in the given scope when it is valid.
func (s *SessionStore) Get(scope SessionScope, token string, now time.Time) (Session, bool) {
	if token == "" {
		return Session{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	key := sessionKey{scope, token}
	row, ok := s.rows[key]
	if !ok || row.kind != store.SessionKindAccess {
		return Session{}, false
	}
	if !now.Before(row.session.ExpiresAt) {
		delete(s.rows, key)
		return Session{}, false
	}
	return row.session, true
}

// Delete revokes every token of the login the given token belongs to.
func (s *SessionStore) Delete(scope SessionScope, token string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	row, ok := s.rows[sessionKey{scope, token}]
	if !ok {
		return
	}
	for key, candidate := range s.rows {
		if key.scope == scope && candidate.family == row.family {
			delete(s.rows, key)
		}
	}
}

func (s *SessionStore) pruneLocked(now time.Time) {
	for key, row := range s.rows {
		if !now.Before(row.session.ExpiresAt) {
			delete(s.rows, key)
		}
	}
}

// ── database backend ────────────────────────────────────────────────────

// DBSessions persists sessions in SQLite, so restarting AuthDock no longer signs
// everybody out and the gateway can grow to more than one process later.
type DBSessions struct {
	store      *store.Store
	ttl        time.Duration
	refreshTTL time.Duration
}

// NewDBSessions returns a database backed session store.
func NewDBSessions(st *store.Store, ttl, refreshTTL time.Duration) *DBSessions {
	if ttl <= 0 {
		ttl = 12 * time.Hour
	}
	if refreshTTL <= 0 {
		refreshTTL = DefaultRefreshTTL
	}
	return &DBSessions{store: st, ttl: ttl, refreshTTL: refreshTTL}
}

// TTL is how long a fresh access token stays valid.
func (d *DBSessions) TTL() time.Duration { return d.ttl }

// RefreshTTL is how long a fresh refresh token stays valid.
func (d *DBSessions) RefreshTTL() time.Duration { return d.refreshTTL }

// Issue creates a new login and returns its token pair.
func (d *DBSessions) Issue(scope SessionScope, username, role string, now time.Time) (Issued, error) {
	access, err := newSessionToken()
	if err != nil {
		return Issued{}, err
	}
	refresh, err := newSessionToken()
	if err != nil {
		return Issued{}, err
	}

	ctx := context.Background()
	accessExpiry := now.Add(d.ttl)
	refreshExpiry := now.Add(d.refreshTTL)
	family := hashSessionToken(access)

	if err := d.store.CreateSession(ctx, string(scope), store.SessionKindAccess,
		hashSessionToken(access), username, role, family, accessExpiry); err != nil {
		return Issued{}, err
	}
	if err := d.store.CreateSession(ctx, string(scope), store.SessionKindRefresh,
		hashSessionToken(refresh), username, role, family, refreshExpiry); err != nil {
		return Issued{}, err
	}
	return Issued{Access: access, Refresh: refresh, AccessExpiry: accessExpiry, RefreshExpiry: refreshExpiry}, nil
}

// Refresh consumes a refresh token and returns a new pair.
func (d *DBSessions) Refresh(scope SessionScope, refreshToken string, now time.Time) (Issued, error) {
	if refreshToken == "" {
		return Issued{}, ErrRefreshInvalid
	}
	access, err := newSessionToken()
	if err != nil {
		return Issued{}, err
	}
	refresh, err := newSessionToken()
	if err != nil {
		return Issued{}, err
	}

	accessExpiry := now.Add(d.ttl)
	refreshExpiry := now.Add(d.refreshTTL)

	session, ok, err := d.store.RotateRefreshSession(context.Background(), string(scope),
		hashSessionToken(refreshToken), hashSessionToken(refresh), hashSessionToken(access),
		accessExpiry, refreshExpiry, now)
	if err != nil {
		return Issued{}, err
	}
	if !ok {
		return Issued{}, ErrRefreshInvalid
	}
	_ = session
	return Issued{Access: access, Refresh: refresh, AccessExpiry: accessExpiry, RefreshExpiry: refreshExpiry}, nil
}

// Get returns the access session for token in the given scope when it is valid.
func (d *DBSessions) Get(scope SessionScope, token string, now time.Time) (Session, bool) {
	if token == "" {
		return Session{}, false
	}
	session, ok, err := d.store.GetSession(context.Background(), string(scope),
		store.SessionKindAccess, hashSessionToken(token), now)
	if err != nil || !ok {
		return Session{}, false
	}
	return Session{Username: session.Username, Role: session.Role, ExpiresAt: session.ExpiresAt}, true
}

// Delete revokes every token of the login the given token belongs to.
func (d *DBSessions) Delete(scope SessionScope, token string) {
	if token == "" {
		return
	}
	_ = d.store.RevokeSessionFamily(context.Background(), hashSessionToken(token))
}
