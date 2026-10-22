// Package store owns the SQLite database: the schema, the users table and the
// bootstrap administrator account.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite" // registers the pure-Go "sqlite" driver

	"github.com/lyy1119/AuthDock/internal/passwd"
)

const (
	// RoleUser is an ordinary account. It can authenticate against future
	// services but may not sign in to the admin area.
	RoleUser = "user"
	// RoleAdmin may sign in to the admin area.
	RoleAdmin = "admin"

	// BootstrapAdminUsername is the account created the first time AuthDock
	// starts against an empty users table.
	BootstrapAdminUsername = "admin"

	// schemaVersion is tracked in PRAGMA user_version.
	schemaVersion = 1
)

// Schema is applied idempotently on every start-up.
//
// Roles are restricted at the database level, usernames are capped at 20
// characters (SQLite length() counts characters, matching rune counting in the
// passwd package) and password hashes are stored as Argon2id PHC strings.
const schema = `
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE,
    password_hash TEXT    NOT NULL,
    role          TEXT    NOT NULL DEFAULT 'user',
    created_at    TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    CONSTRAINT users_username_len CHECK (length(username) BETWEEN 1 AND 20),
    CONSTRAINT users_role_valid   CHECK (role IN ('user', 'admin'))
);
CREATE INDEX IF NOT EXISTS users_role_idx ON users (role);
`

var (
	// ErrUserNotFound reports a lookup that matched no row.
	ErrUserNotFound = errors.New("store: user not found")
	// ErrUserExists reports an insert that collided with an existing username.
	ErrUserExists = errors.New("store: username already exists")
)

// User is one row of the users table.
type User struct {
	ID           int64
	Username     string
	PasswordHash string
	Role         string
	CreatedAt    time.Time
}

// IsAdmin reports whether the account may sign in to the admin area.
func (u *User) IsAdmin() bool { return u.Role == RoleAdmin }

// Store is a handle on the AuthDock database.
type Store struct {
	db     *sql.DB
	hasher *passwd.Hasher
	path   string

	// dummyOnce guards the throw-away hash used to equalise timing for unknown
	// usernames.
	dummyOnce sync.Once
	dummyHash string
}

// Open opens (creating if needed) the SQLite database at path, applies the
// schema and returns a ready Store. Use ":memory:" for an in-memory database.
func Open(path string, hasher *passwd.Hasher) (*Store, error) {
	if hasher == nil {
		return nil, errors.New("store: a password hasher is required")
	}
	if path == "" {
		return nil, errors.New("store: database path is empty")
	}

	inMemory := path == ":memory:"
	if !inMemory {
		if dir := filepath.Dir(path); dir != "" && dir != "." {
			if err := os.MkdirAll(dir, 0o700); err != nil {
				return nil, fmt.Errorf("store: create database directory: %w", err)
			}
		}
	}

	pragmas := "_pragma=busy_timeout(5000)&_pragma=foreign_keys(ON)"
	if !inMemory {
		pragmas += "&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)"
	}
	dsn := "file:" + path + "?" + pragmas
	if inMemory {
		dsn = "file::memory:?_pragma=busy_timeout(5000)&_pragma=foreign_keys(ON)"
	}

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: open database: %w", err)
	}
	// A single connection keeps the file-backed database free of SQLITE_BUSY
	// surprises. AuthDock serves one small admin area, so this is not a
	// bottleneck.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: ping database: %w", err)
	}

	s := &Store{db: db, hasher: hasher, path: path}
	if err := s.migrate(ctx); err != nil {
		db.Close()
		return nil, err
	}

	if !inMemory {
		if err := restrictDBFiles(path); err != nil {
			db.Close()
			return nil, err
		}
	}
	return s, nil
}

// restrictDBFiles keeps the database and its write-ahead-log sidecars private to
// the service user. SQLite creates the sidecars itself, so they are chmod'ed
// when already present and the process umask covers the ones created later.
func restrictDBFiles(path string) error {
	for _, suffix := range []string{"", "-wal", "-shm"} {
		err := os.Chmod(path+suffix, 0o600)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("store: restrict database permissions: %w", err)
		}
	}
	return nil
}

// Close releases the database handle.
func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate(ctx context.Context) error {
	var version int
	if err := s.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return fmt.Errorf("store: read schema version: %w", err)
	}
	if version >= schemaVersion {
		return nil
	}
	if _, err := s.db.ExecContext(ctx, schema); err != nil {
		return fmt.Errorf("store: apply schema: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version = %d", schemaVersion)); err != nil {
		return fmt.Errorf("store: record schema version: %w", err)
	}
	return nil
}

// SeedBootstrapAdmin makes sure the users table is not empty. When the table is
// empty it inserts the default administrator account with a freshly generated
// random password and returns that password so the caller can print it exactly
// once. Only the Argon2id hash is stored; the plaintext cannot be recovered.
//
// The second return value reports whether an account was created in this call.
func (s *Store) SeedBootstrapAdmin(ctx context.Context) (password string, created bool, err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", false, fmt.Errorf("store: begin seed transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var count int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&count); err != nil {
		return "", false, fmt.Errorf("store: count users: %w", err)
	}
	if count > 0 {
		return "", false, nil
	}

	password, err = passwd.GeneratePassword(passwd.BootstrapPasswordLen)
	if err != nil {
		return "", false, fmt.Errorf("store: generate bootstrap password: %w", err)
	}
	hash, err := s.hasher.Hash(password)
	if err != nil {
		return "", false, fmt.Errorf("store: hash bootstrap password: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)`,
		BootstrapAdminUsername, hash, RoleAdmin,
	); err != nil {
		return "", false, fmt.Errorf("store: insert bootstrap admin: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return "", false, fmt.Errorf("store: commit seed transaction: %w", err)
	}
	s.restrictFiles()
	return password, true, nil
}

// restrictFiles re-applies private permissions after a write, because SQLite
// creates the -wal and -shm sidecars lazily with the process umask.
func (s *Store) restrictFiles() {
	if s.path == "" || s.path == ":memory:" {
		return
	}
	if err := restrictDBFiles(s.path); err != nil {
		// Not fatal: the database itself was already restricted in Open.
		_ = err
	}
}

// GetUserByUsername returns the account with the given username, matched
// exactly (usernames are case sensitive).
func (s *Store) GetUserByUsername(ctx context.Context, username string) (*User, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, username, password_hash, role, created_at FROM users WHERE username = ?`, username)

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

// VerifyPassword reports whether password matches the hash stored for user.
func (s *Store) VerifyPassword(user *User, password string) error {
	if user == nil || user.PasswordHash == "" {
		return passwd.ErrMismatch
	}
	return s.hasher.Verify(password, user.PasswordHash)
}

// VerifyDummy runs a verification against a throw-away hash. The login handler
// calls it when a username does not exist so that failing lookups cost as much
// as failing password checks and timing does not reveal which usernames exist.
func (s *Store) VerifyDummy(password string) {
	s.dummyOnce.Do(func() {
		// The plaintext is random and immediately discarded.
		plaintext, err := passwd.GeneratePassword(passwd.BootstrapPasswordLen + 8)
		if err != nil {
			return
		}
		hash, err := s.hasher.Hash(plaintext)
		if err != nil {
			return
		}
		s.dummyHash = hash
	})
	if s.dummyHash == "" {
		return
	}
	_ = s.hasher.Verify(password, s.dummyHash)
}

// CreateUser hashes password and inserts a new account. There is no HTTP surface
// for it yet; it backs tests and the future admin area.
func (s *Store) CreateUser(ctx context.Context, username, password, role string) (*User, error) {
	if err := passwd.ValidateUsername(username); err != nil {
		return nil, err
	}
	if role != RoleUser && role != RoleAdmin {
		return nil, fmt.Errorf("store: invalid role %q", role)
	}
	if password == "" {
		return nil, passwd.ErrInvalidPassword
	}

	hash, err := s.hasher.Hash(password)
	if err != nil {
		return nil, fmt.Errorf("store: hash password: %w", err)
	}
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)`,
		username, hash, role,
	); err != nil {
		if isUniqueViolation(err) {
			return nil, ErrUserExists
		}
		return nil, fmt.Errorf("store: insert user: %w", err)
	}
	s.restrictFiles()
	return s.GetUserByUsername(ctx, username)
}

func isUniqueViolation(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "unique constraint") || strings.Contains(msg, "constraint failed: users.username")
}
