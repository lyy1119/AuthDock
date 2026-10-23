package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// ErrSessionNotFound reports a session row that cannot be read.
var ErrSessionNotFound = errors.New("store: session not found")

// Session scopes separate the two audiences that log in: the management area and
// the gateway portal. A session is only ever valid for the scope it was created
// for.
const (
	ScopeAdmin   = "admin"
	ScopeGateway = "gateway"
)

// Session kinds. A request presents an access session; a refresh session is only
// ever exchanged for a new pair.
const (
	SessionKindAccess  = "access"
	SessionKindRefresh = "refresh"
)

// Session is one persisted login row. Only the hash of the token is stored, so a
// database leak does not hand out usable sessions.
type Session struct {
	Scope     string
	Kind      string
	Family    string
	Username  string
	Role      string
	CreatedAt time.Time
	ExpiresAt time.Time
}

// CreateSession stores a session row keyed by the hash of its token. An empty
// family makes the row its own family.
func (s *Store) CreateSession(ctx context.Context, scope, kind, tokenHash, username, role, family string, expiresAt time.Time) error {
	if scope != ScopeAdmin && scope != ScopeGateway {
		return fmt.Errorf("store: unknown session scope %q", scope)
	}
	if kind != SessionKindAccess && kind != SessionKindRefresh {
		return fmt.Errorf("store: unknown session kind %q", kind)
	}
	if tokenHash == "" || username == "" || role == "" {
		return errors.New("store: incomplete session")
	}
	if family == "" {
		family = tokenHash
	}
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO sessions (token_hash, username, role, scope, kind, family, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		tokenHash, username, role, scope, kind, family, expiresAt.UTC().Format(time.RFC3339),
	); err != nil {
		return fmt.Errorf("store: insert session: %w", err)
	}
	s.restrictFiles()
	return nil
}

// GetSession returns the live session for a token hash of the given kind.
func (s *Store) GetSession(ctx context.Context, scope, kind, tokenHash string, now time.Time) (Session, bool, error) {
	var (
		session   Session
		createdAt string
		expiresAt string
	)
	err := s.db.QueryRowContext(ctx,
		`SELECT username, role, family, created_at, expires_at
		 FROM sessions WHERE token_hash = ? AND scope = ? AND kind = ?`,
		tokenHash, scope, kind,
	).Scan(&session.Username, &session.Role, &session.Family, &createdAt, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Session{}, false, nil
	}
	if err != nil {
		return Session{}, false, fmt.Errorf("store: read session: %w", err)
	}

	expiry, err := time.Parse(time.RFC3339, expiresAt)
	if err != nil || !now.UTC().Before(expiry) {
		_ = s.DeleteSession(ctx, tokenHash)
		return Session{}, false, nil
	}
	if created, err := time.Parse(time.RFC3339, createdAt); err == nil {
		session.CreatedAt = created
	}
	session.Scope = scope
	session.Kind = kind
	session.ExpiresAt = expiry
	return session, true, nil
}

// RotateRefreshSession exchanges a refresh token for a new access token and a new
// refresh token in one transaction: the presented row is consumed, so a refresh
// token can only ever be used once.
func (s *Store) RotateRefreshSession(
	ctx context.Context,
	scope, oldRefreshHash, newRefreshHash, newAccessHash string,
	accessExpiresAt, refreshExpiresAt, now time.Time,
) (Session, bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Session{}, false, fmt.Errorf("store: begin refresh: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var (
		session   Session
		expiresAt string
	)
	err = tx.QueryRowContext(ctx,
		`SELECT username, role, family, expires_at
		 FROM sessions WHERE token_hash = ? AND scope = ? AND kind = ?`,
		oldRefreshHash, scope, SessionKindRefresh,
	).Scan(&session.Username, &session.Role, &session.Family, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Session{}, false, nil
	}
	if err != nil {
		return Session{}, false, fmt.Errorf("store: read refresh session: %w", err)
	}
	if expiry, parseErr := time.Parse(time.RFC3339, expiresAt); parseErr != nil || !now.UTC().Before(expiry) {
		if _, delErr := tx.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash = ?`, oldRefreshHash); delErr != nil {
			return Session{}, false, fmt.Errorf("store: drop expired refresh: %w", delErr)
		}
		if commitErr := tx.Commit(); commitErr != nil {
			return Session{}, false, fmt.Errorf("store: commit refresh cleanup: %w", commitErr)
		}
		return Session{}, false, nil
	}

	if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash = ?`, oldRefreshHash); err != nil {
		return Session{}, false, fmt.Errorf("store: consume refresh: %w", err)
	}
	for _, row := range []struct {
		kind, hash string
		expires    time.Time
	}{
		{SessionKindAccess, newAccessHash, accessExpiresAt},
		{SessionKindRefresh, newRefreshHash, refreshExpiresAt},
	} {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO sessions (token_hash, username, role, scope, kind, family, expires_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?)`,
			row.hash, session.Username, session.Role, scope, row.kind, session.Family,
			row.expires.UTC().Format(time.RFC3339),
		); err != nil {
			return Session{}, false, fmt.Errorf("store: issue refreshed session: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return Session{}, false, fmt.Errorf("store: commit refresh: %w", err)
	}
	s.restrictFiles()

	session.Scope = scope
	session.Kind = SessionKindRefresh
	session.ExpiresAt = accessExpiresAt
	return session, true, nil
}

// DeleteSession removes one session row.
func (s *Store) DeleteSession(ctx context.Context, tokenHash string) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash = ?`, tokenHash); err != nil {
		return fmt.Errorf("store: delete session: %w", err)
	}
	return nil
}

// RevokeSessionFamily removes every row that belongs to the login the token is
// part of, so signing out also invalidates the refresh token.
func (s *Store) RevokeSessionFamily(ctx context.Context, tokenHash string) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM sessions WHERE family = (SELECT family FROM sessions WHERE token_hash = ?)`,
		tokenHash)
	if err != nil {
		return fmt.Errorf("store: revoke session family: %w", err)
	}
	return nil
}

// PruneSessions drops every expired session, of either kind.
func (s *Store) PruneSessions(ctx context.Context, now time.Time) (int64, error) {
	result, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at <= ?`,
		now.UTC().Format(time.RFC3339))
	if err != nil {
		return 0, fmt.Errorf("store: prune sessions: %w", err)
	}
	removed, _ := result.RowsAffected()
	return removed, nil
}
