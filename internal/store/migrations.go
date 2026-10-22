package store

// migrations are applied in order. The database remembers the last applied entry
// in PRAGMA user_version, so adding a schema change means appending one string
// here; existing databases migrate forward on the next start.
var migrations = []string{
	// 1: accounts. Roles are restricted at the database level, usernames are
	// capped at 20 characters (SQLite length() counts characters, matching rune
	// counting in the passwd package) and password hashes are stored as
	// Argon2id PHC strings.
	`
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
`,

	// 2: gateway configuration. settings is a small key/value table for the
	// gateway domain and future knobs; gateway_rules holds the per-user routing
	// rules the admin area edits. Deleting a user removes their rules.
	`
CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS gateway_rules (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    subdomain  TEXT    NOT NULL,
    path       TEXT    NOT NULL DEFAULT '*',
    upstream   TEXT    NOT NULL,
    created_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    CONSTRAINT gateway_rules_subdomain_len CHECK (length(subdomain) BETWEEN 1 AND 63),
    CONSTRAINT gateway_rules_path_len      CHECK (length(path) BETWEEN 1 AND 255)
);
CREATE INDEX IF NOT EXISTS gateway_rules_user_idx ON gateway_rules (user_id);
`,
}

// schemaVersion is how many migrations this build expects.
var schemaVersion = len(migrations)
