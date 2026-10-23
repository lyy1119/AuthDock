package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// SessionStoreError reports a session row that cannot be read.
var ErrSessionNotFound = errors.New("store: session not found")

// Session is one persisted login session. Only the hash of the token is stored,
// so a database leak does not hand out usable sessions.
type Session struct {
	Username  string
	Role      string
	CreatedAt time.Time
	ExpiresAt time.Time
}

// CreateSession stores a session keyed by the hash of its token.
func (s *Store) CreateSession(ctx context.Context, tokenHash, username, role string, expiresAt time.Time) error {
	if tokenHash == "" || username == "" || role == "" {
		return errors.New("store: incomplete session")
	}
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO sessions (token_hash, username, role, expires_at) VALUES (?, ?, ?, ?)`,
		tokenHash, username, role, expiresAt.UTC().Format(time.RFC3339),
	); err != nil {
		return fmt.Errorf("store: insert session: %w", err)
	}
	s.restrictFiles()
	return nil
}

// GetSession returns the live session for a token hash.
func (s *Store) GetSession(ctx context.Context, tokenHash string, now time.Time) (Session, bool, error) {
	var (
		session   Session
		expiresAt string
		createdAt string
	)
	err := s.db.QueryRowContext(ctx,
		`SELECT username, role, created_at, expires_at FROM sessions WHERE token_hash = ?`, tokenHash,
	).Scan(&session.Username, &session.Role, &createdAt, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Session{}, false, nil
	}
	if err != nil {
		return Session{}, false, fmt.Errorf("store: read session: %w", err)
	}

	expiry, err := time.Parse(time.RFC3339, expiresAt)
	if err != nil || !now.UTC().Before(expiry) {
		// Expired: clean it up so the table does not grow forever.
		_ = s.DeleteSession(ctx, tokenHash)
		return Session{}, false, nil
	}
	if created, err := time.Parse(time.RFC3339, createdAt); err == nil {
		session.CreatedAt = created
	}
	session.ExpiresAt = expiry
	return session, true, nil
}

// DeleteSession removes one session.
func (s *Store) DeleteSession(ctx context.Context, tokenHash string) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash = ?`, tokenHash); err != nil {
		return fmt.Errorf("store: delete session: %w", err)
	}
	return nil
}

// PruneSessions drops every expired session.
func (s *Store) PruneSessions(ctx context.Context, now time.Time) (int64, error) {
	result, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at <= ?`,
		now.UTC().Format(time.RFC3339))
	if err != nil {
		return 0, fmt.Errorf("store: prune sessions: %w", err)
	}
	removed, _ := result.RowsAffected()
	return removed, nil
}
