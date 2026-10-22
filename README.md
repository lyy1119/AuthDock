# AuthDock

A SSO pedestal for small personal project.

AuthDock is a small, self-hosted Go service that keeps the accounts for your side
projects in one place. This first iteration ships the foundation: a SQLite
database with a `users` table, Argon2id password storage and an admin-only login
for the management area.

## Requirements

- Go 1.27 or newer

## Run

```sh
go build -o authdock .
./authdock -addr 127.0.0.1:8080 -db data/authdock.db
```

Then open <http://127.0.0.1:8080/login>.

Flags can also be set through the environment: `AUTH_DOCK_ADDR` and
`AUTH_DOCK_DB`.

### The bootstrap administrator

On the first start, when the `users` table is empty, AuthDock creates the
default administrator account `admin` with a random 8-character password and
prints it to stdout **once**:

```text
  AuthDock 已初始化默认管理员账号（users 表原本为空）

    username : admin
    password : ****

  Only show once —— 该密码只显示这一次，请立即保存到安全的地方。
  数据库中只保存 Argon2id 哈希，关闭本提示后无法再取回该密码。
```

Save that password: only the Argon2id hash is stored, so it cannot be recovered.
To reset it, delete the `admin` row from the database and restart; the seeding
runs again because the table is empty.

## API

| Method | Path                 | Description                                            |
| ------ | -------------------- | ------------------------------------------------------ |
| POST   | `/api/auth/login`    | `{"username":"admin","password":"..."}`, admin only    |
| POST   | `/api/auth/logout`   | Drops the current session                              |
| GET    | `/api/auth/session`  | Reports the current session or `401`                   |
| GET    | `/login`             | Login page                                             |
| GET    | `/healthz`           | Liveness probe (`ok`)                                  |

Responses are JSON; failures use a uniform envelope:

```json
{"ok": false, "code": "invalid_credentials", "message": "用户名或密码错误"}
```

Error codes: `invalid_request`, `invalid_credentials`, `admin_only`,
`too_many_attempts`, `unauthenticated`, `method_not_allowed`, `not_found`,
`internal_error`.

A successful login sets an `authdock_session` cookie (`HttpOnly`,
`SameSite=Strict`, `Secure` when served over TLS). Sessions live in memory, so
restarting AuthDock signs the administrator out.

## Data model

```sql
CREATE TABLE users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE,   -- at most 20 characters
    password_hash TEXT    NOT NULL,          -- Argon2id PHC string
    role          TEXT    NOT NULL DEFAULT 'user',  -- 'user' | 'admin'
    created_at    TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    CONSTRAINT users_username_len CHECK (length(username) BETWEEN 1 AND 20),
    CONSTRAINT users_role_valid   CHECK (role IN ('user', 'admin'))
);
```

Roles are `user` and `admin`; only `admin` accounts may sign in to the
management area. Passwords are stored as Argon2id hashes in PHC string form
(`$argon2id$v=19$m=65536,t=3,p=2$...`). Key derivation uses
`golang.org/x/crypto/argon2`; the surrounding PHC encoding lives in
`internal/passwd` and is pinned by a golden-vector test. The cost parameters are
read back from each hash, so they can be raised later without breaking existing
rows.

The database file and its `-wal` / `-shm` sidecars are created with `0600`
permissions because they contain password hashes.

## Security notes

- Only `admin` accounts may sign in; a valid `user` account gets `403`.
- Failed logins are throttled per username (5 failures → 1 minute lock, `429`).
- Verification is constant time, and unknown usernames pay the same Argon2id cost
  as wrong passwords, so timing does not reveal which accounts exist.
- Responses carry `X-Content-Type-Options`, `X-Frame-Options`,
  `Referrer-Policy` and a restrictive `Content-Security-Policy`.

## Layout

```text
main.go                     wiring: flags, database, HTTP server, one-time banner
internal/passwd             Argon2id hashing, password generation, username rules
internal/store              SQLite schema, users table, bootstrap admin seeding
internal/httpapi            routes, login/logout/session handlers, sessions, limiter
internal/httpapi/templates  embedded login and admin placeholder pages
```

## Tests

```sh
go test ./...
```

## License

MIT — see [LICENSE](LICENSE).
