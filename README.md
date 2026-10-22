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

Then open <http://127.0.0.1:8080/login>. Running `./authdock` with no arguments
works out of the box; these are the defaults:

| Flag                    | Default (env)                             | Description                                    |
| ----------------------- | ----------------------------------------- | ---------------------------------------------- |
| `-addr`                 | `127.0.0.1:8080` (`AUTH_DOCK_ADDR`)       | HTTP listen address                            |
| `-db`                   | `data/authdock.db` (`AUTH_DOCK_DB`)       | SQLite database file, relative to the CWD      |
| `-version`              |                                           | Print build information and exit               |
| `-reset-admin-password` |                                           | New random admin password (creates the account if missing), printed once, exit |

The `-db` path is resolved to an absolute path in the start-up log and in the
banner, because a relative path makes it easy to end up with two databases (and
therefore two different bootstrap passwords) depending on the working
directory.

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
  登录时只填冒号右边这 8 个字符，不要带空格或 "password :" 前缀。
  忘记密码可随时执行：authdock -reset-admin-password
  database : /path/to/data/authdock.db
```

Past the first start the table is no longer empty, so the banner does not
reappear; the log says `users table already initialized` and keeps working with
the same database.

### Lost the bootstrap password?

```sh
./authdock -reset-admin-password            # or: make reset-password
```

This generates a new random password, stores its Argon2id hash and prints the
plaintext once. The old password stops working immediately. If the admin account
is gone (for example its row was deleted), the same command recreates it with
the admin role, so it doubles as a lockout recovery path.

Common reasons a login fails even though a password was printed somewhere:

- the password was copied together with the `password : ` prefix or trailing
  whitespace (only the 8 characters themselves are the password);
- the server runs against a different database than the banner came from — the
  start-up log prints the absolute `db` path, so compare them;
- five wrong attempts lock the account for one minute (`429` with a
  `Retry-After` header);
- the admin database was deleted and re-seeded while the old process was still
  running (each seed makes a new password).

### Behind a reverse proxy

The login page builds its URLs from the page location, and the redirects use
relative `Location` references, so AuthDock also works when a proxy mounts it
under a path prefix. That is exactly how code-server serves a forwarded port:

```text
https://<code-server host>/proxy/8080/login   ->   http://127.0.0.1:8080/login
```

Point the proxy at `http://127.0.0.1:8080`. Two details:

- when the proxy terminates TLS, forward `X-Forwarded-Proto: https` so the
  session cookie is issued with the `Secure` flag (code-server does this);
- if the proxy runs in another container or host, start AuthDock with
  `-addr 0.0.0.0:8080` instead of the loopback default.

Absolute paths such as `/api/auth/login` are deliberately absent: behind a
prefix they would be requested from the proxy root and answered by it (the
`405` you get from code-server) instead of reaching AuthDock.

## Build

Bare `make` only prints help; targets do the work:

```sh
make                   # list every target
make build             # Linux x86_64   -> bin/authdock
make build-windows     # Windows x86_64 -> bin/authdock.exe
make build-all         # both at once
make ci                # fmt-check + vet + test + both builds
make release-artifacts # dist/ with tar.gz, zip and checksums.txt
```

Both dependencies are pure Go, so cross-compilation needs no C toolchain:
`CGO_ENABLED` stays `0`. `VERSION`, `COMMIT` and `BUILD_DATE` are injected via
`-ldflags`, so a built binary reports them:

```text
$ bin/authdock -version
AuthDock v0.1.0 (commit abc1234, built 2026-01-01T00:00:00Z)
```

Docker images and GitHub releases are reserved for CI. `make help` lists
`docker-build`, `docker-push` and `release`; they currently explain what is
still missing (a `Dockerfile` and the workflow files) and exit non-zero, so a
pipeline cannot silently publish nothing.

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
Makefile                    build, cross-compile, quality gates, reserved docker/release targets
```

## Tests

```sh
make test        # or: go test ./...
make test-race   # needs cgo and gcc
```

## License

MIT — see [LICENSE](LICENSE).
