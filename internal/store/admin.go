package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/lyy1119/AuthDock/internal/passwd"
)

const (
	// SettingsKeyGatewayDomain is the settings row holding the gateway base
	// domain, e.g. "gw.example.net".
	SettingsKeyGatewayDomain = "gateway_domain"

	// SettingsKeyUpstreamHost decides which Host header published services see.
	SettingsKeyUpstreamHost = "upstream_host"

	// SettingsKeyUpstreamInsecure allows https upstreams with a certificate the
	// gateway cannot verify, such as a Caddy "tls internal" CA.
	SettingsKeyUpstreamInsecure = "upstream_insecure"
)

// Accepted values for SettingsKeyUpstreamHost.
const (
	// UpstreamHostPreserve forwards the public host the browser used, which is
	// what vhosted upstreams (another Caddy, nginx) need to pick their site.
	UpstreamHostPreserve = "preserve"
	// UpstreamHostUpstream forwards the upstream address instead.
	UpstreamHostUpstream = "upstream"
)

// NormalizeUpstreamHost validates the Host header mode; empty means preserve.
func NormalizeUpstreamHost(mode string) (string, error) {
	switch mode {
	case "":
		return UpstreamHostPreserve, nil
	case UpstreamHostPreserve, UpstreamHostUpstream:
		return mode, nil
	}
	return "", fmt.Errorf("store: unknown upstream host mode %q", mode)
}

// ListUsers returns every account ordered by id.
func (s *Store) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, username, password_hash, role, created_at FROM users ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("store: list users: %w", err)
	}
	defer rows.Close()

	users := make([]User, 0, 8)
	for rows.Next() {
		var (
			user      User
			createdAt string
		)
		if err := rows.Scan(&user.ID, &user.Username, &user.PasswordHash, &user.Role, &createdAt); err != nil {
			return nil, fmt.Errorf("store: scan user: %w", err)
		}
		if t, err := time.Parse(time.RFC3339, createdAt); err == nil {
			user.CreatedAt = t
		}
		users = append(users, user)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: list users: %w", err)
	}
	return users, nil
}

// GetUserByID returns the account with the given id.
func (s *Store) GetUserByID(ctx context.Context, id int64) (*User, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, username, password_hash, role, created_at FROM users WHERE id = ?`, id)

	var (
		user      User
		createdAt string
	)
	if err := row.Scan(&user.ID, &user.Username, &user.PasswordHash, &user.Role, &createdAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("store: query user: %w", err)
	}
	if t, err := time.Parse(time.RFC3339, createdAt); err == nil {
		user.CreatedAt = t
	}
	return &user, nil
}

// CountAdmins reports how many accounts currently have the admin role.
func (s *Store) CountAdmins(ctx context.Context) (int, error) {
	var count int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE role = ?`, RoleAdmin).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("store: count admins: %w", err)
	}
	return count, nil
}

// UpdateUserRole changes the role of one account and returns the updated row.
func (s *Store) UpdateUserRole(ctx context.Context, id int64, role string) (*User, error) {
	if role != RoleUser && role != RoleAdmin {
		return nil, fmt.Errorf("store: invalid role %q", role)
	}
	if _, err := s.GetUserByID(ctx, id); err != nil {
		return nil, err
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE users SET role = ? WHERE id = ?`, role, id); err != nil {
		return nil, fmt.Errorf("store: update role: %w", err)
	}
	s.restrictFiles()
	return s.GetUserByID(ctx, id)
}

// SetUserPassword stores a new Argon2id hash for one account.
func (s *Store) SetUserPassword(ctx context.Context, id int64, password string) (*User, error) {
	if err := passwd.ValidateNewPassword(password); err != nil {
		return nil, err
	}
	if _, err := s.GetUserByID(ctx, id); err != nil {
		return nil, err
	}
	hash, err := s.hasher.Hash(password)
	if err != nil {
		return nil, fmt.Errorf("store: hash password: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE users SET password_hash = ? WHERE id = ?`, hash, id); err != nil {
		return nil, fmt.Errorf("store: update password: %w", err)
	}
	s.restrictFiles()
	return s.GetUserByID(ctx, id)
}

// DeleteUser removes an account and, through the foreign key, its gateway
// rules. Callers are responsible for the last-admin and self-deletion guards.
func (s *Store) DeleteUser(ctx context.Context, id int64) error {
	if _, err := s.GetUserByID(ctx, id); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, id); err != nil {
		return fmt.Errorf("store: delete user: %w", err)
	}
	s.restrictFiles()
	return nil
}

// ValidateGatewayDomain accepts "" (not configured) or a bare DNS name such as
// "gw.example.net". A scheme, port, path or whitespace is rejected.
func ValidateGatewayDomain(domain string) error {
	if domain == "" {
		return nil
	}
	if len(domain) > 253 {
		return errors.New("store: gateway domain is too long")
	}
	if strings.ContainsAny(domain, "/:@ \t\r\n") {
		return errors.New("store: gateway domain must be a bare host name")
	}
	for _, label := range strings.Split(domain, ".") {
		if label == "" || len(label) > 63 {
			return errors.New("store: gateway domain has an empty or overlong label")
		}
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return errors.New("store: gateway domain labels must not start or end with a hyphen")
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			switch {
			case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-':
			default:
				return fmt.Errorf("store: gateway domain contains unsupported character %q", c)
			}
		}
	}
	return nil
}

// Setting returns the value stored for key, or the empty string when unset.
func (s *Store) Setting(ctx context.Context, key string) (string, error) {
	var value string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = ?`, key).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("store: read setting %q: %w", key, err)
	}
	return value, nil
}

// SetSetting stores value for key, creating the row when needed.
func (s *Store) SetSetting(ctx context.Context, key, value string) error {
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO settings (key, value) VALUES (?, ?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
		key, value,
	); err != nil {
		return fmt.Errorf("store: write setting %q: %w", key, err)
	}
	s.restrictFiles()
	return nil
}
