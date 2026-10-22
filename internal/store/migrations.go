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
	// gateway domain and future knobs.
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

	// 3: the gate table replaces the per-user gateway rules. A gate maps
	// https://<to_prefix>.<gateway domain>/<to_suffix><rest> to <from>/<rest>,
	// so it carries a display name instead of an owner.
	`
CREATE TABLE IF NOT EXISTS gate (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT    NOT NULL,
    "from"     TEXT    NOT NULL,
    to_prefix  TEXT    NOT NULL,
    to_suffix  TEXT    NOT NULL DEFAULT '',
    created_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    CONSTRAINT gate_name_len   CHECK (length(name) BETWEEN 1 AND 50),
    CONSTRAINT gate_from_len   CHECK (length("from") BETWEEN 1 AND 255),
    CONSTRAINT gate_prefix_len CHECK (length(to_prefix) BETWEEN 1 AND 63),
    CONSTRAINT gate_suffix_len CHECK (length(to_suffix) <= 255)
);
CREATE UNIQUE INDEX IF NOT EXISTS gate_route_idx ON gate (to_prefix, to_suffix);
DROP TABLE IF EXISTS gateway_rules;
`,

	// 4: gates can be scoped. A NULL user_id means the gate is available to
	// every account; a set user_id restricts it to that account, and deleting
	// the account removes its gates.
	`
ALTER TABLE gate ADD COLUMN user_id INTEGER REFERENCES users (id) ON DELETE CASCADE;
CREATE INDEX IF NOT EXISTS gate_user_idx ON gate (user_id);
`,
}

// schemaVersion is how many migrations this build expects.
var schemaVersion = len(migrations)
