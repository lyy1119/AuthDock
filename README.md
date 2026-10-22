# AuthDock

A SSO pedestal for small personal project.

AuthDock is a small, self-hosted Go service that keeps the accounts for your side
projects in one place. This first iteration ships the foundation: a SQLite
database with a `users` table, Argon2id password storage and an admin-only login
for the management area.

## Requirements

- Go 1.27 or newer (the only requirement to build and run the binary)
- Node.js 20 or newer, only when rebuilding the management UI

## Run

```sh
go build -o authdock .
./authdock -addr 127.0.0.1:8080 -portal-addr 127.0.0.1:8081 -db data/authdock.db
```

Then open <http://127.0.0.1:8080/login> for the management area and
<http://gw.example.net:8081/> for the user portal (see below). Running
`./authdock` with no arguments works out of the box; these are the defaults:

| Flag                    | Default (env)                             | Description                                    |
| ----------------------- | ----------------------------------------- | ---------------------------------------------- |
| `-addr`                 | `127.0.0.1:8080` (`AUTH_DOCK_ADDR`)       | Management listen address                      |
| `-portal-addr`          | `127.0.0.1:8081` (`AUTH_DOCK_PORTAL_ADDR`) | User portal listen address                    |
| `-db`                   | `data/authdock.db` (`AUTH_DOCK_DB`)       | SQLite database file, relative to the CWD      |
| `-no-dn-check`          | off                                       | Skip the portal domain check (debug only)      |
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

```sh
make             # list every target
make web         # build only the frontend bundle (npm ci on first run)
make build       # frontend + Linux x86_64 binary -> bin/authdock
make build-backend  # Go only, reusing the committed bundle (no Node needed)
make build-windows  # frontend + Windows x86_64 -> bin/authdock.exe
make build-all      # both platforms
make web-check      # TypeScript type check, no output written
make ci             # fmt-check + vet + test + web-check + both builds
```

Every build target embeds `internal/webui/dist` into the binary, so the result
is a single self-contained executable — copy it to a server and run it. The
bundle is committed to the repository on purpose: `go build` and `go test` work
on a machine without Node, and only `make web` (or a `make build`) needs the
Node toolchain.

Two dependencies are pure Go, so cross-compilation needs no C toolchain:
`CGO_ENABLED` stays `0`. `VERSION`, `COMMIT` and `BUILD_DATE` are injected via
`-ldflags`, so a built binary reports them:

```text
$ bin/authdock -version
AuthDock v0.1.0 (commit abc1234, built 2026-01-01T00:00:00Z)
```

### Frontend development

```sh
make run                  # backend on http://127.0.0.1:8080
cd web && npm run dev     # Vite on http://127.0.0.1:5173, /api proxied to the backend
```

Docker images and GitHub releases are reserved for CI. `make help` lists
`docker-build`, `docker-push` and `release`; they currently explain what is
still missing (a `Dockerfile` and the workflow files) and exit non-zero, so a
pipeline cannot silently publish nothing.

## User portal

The portal is the front door for the people the pedestal serves, and it listens
on its own address (`-portal-addr`, default `127.0.0.1:8081`) so it can be
published or proxied independently of the management port.

**Hard domain check.** Every portal request must arrive with a `Host` matching
the gateway domain from the system settings (`系统设置`). A mismatch — or a
domain that has not been configured yet — drops the TCP connection: no login
page, no error page, nothing. `X-Forwarded-Host` is honoured so the check keeps
working behind a reverse proxy.

For local debugging only, `-no-dn-check` disables that check:

```sh
./authdock -no-dn-check          # portal answers on any Host, even without a domain
```

The portal accepts any account (`user` or `admin`) and shares the session store
with the management API, so signing in as an admin there also unlocks `/admin/`,
while a normal account still gets `403` from the management API.

## Pages

| Listener / Path     | Description                                              |
| ------------------- | -------------------------------------------------------- |
| `/login`            | Admin login page (served by the Go handler, no build)    |
| `/` on the portal   | User login page (own port, see below)                    |
| `/admin/`           | Management app: `#/users`, `#/gates`, `#/settings`       |
| `/healthz`          | Liveness probe (`ok`)                                    |

The management app is a React 19 + Ant Design single-page application built by
Vite from `web/`. Its bundle is emitted into `internal/webui/dist`, committed,
and embedded with `go:embed`, so **a plain `go build` produces one executable
that already contains the UI**. Routes live in the URL hash and every asset URL
is relative, which keeps the app working behind a path-prefixing reverse proxy
(code-server's `/proxy/<port>/`, for example).

## API

### Authentication

| Method | Path                 | Description                                            |
| ------ | -------------------- | ------------------------------------------------------ |
| POST   | `/api/auth/login`    | `{"username":"admin","password":"..."}`, admin only    |
| POST   | `/api/auth/logout`   | Drops the current session                              |
| GET    | `/api/auth/session`  | Reports the current session or `401`                   |

### Portal (only reachable through the gateway domain)

| Method | Path          | Description                                              |
| ------ | ------------- | -------------------------------------------------------- |
| GET    | `/` `/login`  | User login page                                          |
| POST   | `/api/login`  | `{"username","password"}`, any role                      |
| POST   | `/api/logout` | Drops the session                                        |
| GET    | `/api/session`| Reports the current session                              |

### Management (requires an admin session)

| Method | Path                     | Description                                              |
| ------ | ------------------------ | -------------------------------------------------------- |
| GET    | `/api/admin/users`       | List accounts (`self` marks the signed-in one)           |
| POST   | `/api/admin/users`       | `{"username","password","role"}` create an account       |
| PATCH  | `/api/admin/users/{id}`  | `{"role"?, "password"?}` change role and/or password     |
| DELETE | `/api/admin/users/{id}`  | Delete an account                                        |
| GET    | `/api/admin/gates`       | `{"gateway_domain","gates":[...]}`                       |
| POST   | `/api/admin/gates`       | `{"name","from","to_prefix","to_suffix"}`                |
| PATCH  | `/api/admin/gates/{id}`  | Same fields; rewrites one gate                           |
| DELETE | `/api/admin/gates/{id}`  | Delete a gate                                            |
| GET    | `/api/admin/settings`    | `{"gateway_domain":"gw.example.net"}`                    |
| PUT    | `/api/admin/settings`    | `{"gateway_domain":"gw.example.net"}`                    |

Guard rails: a session is re-validated against the database on every management
call (so a role change or deletion takes effect immediately), the last admin
cannot be demoted or deleted, and an admin cannot delete the account they are
signed in with. Demoting your own account succeeds, revokes the session and
answers `{"logged_out":true}`.

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

```sql
CREATE TABLE settings (
    key   TEXT PRIMARY KEY,          -- 'gateway_domain'
    value TEXT NOT NULL
);

CREATE TABLE gate (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT    NOT NULL,     -- display name, e.g. 日历
    "from"     TEXT    NOT NULL,     -- upstream: 10.0.0.1:1234 or http://10.0.0.1:1234
    to_prefix  TEXT    NOT NULL,     -- subdomain label on the gateway domain
    to_suffix  TEXT    NOT NULL DEFAULT '',  -- path prefix before the forwarded path
    user_id    INTEGER REFERENCES users (id) ON DELETE CASCADE,  -- NULL = global
    created_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    UNIQUE (to_prefix, to_suffix)
);
```

A gate publishes one upstream service. With the gateway domain `gw.example.net`,
a gate with `to_prefix = calendar`, `to_suffix = app/` and
`from = 10.0.0.1:1234` means:

```text
https://calendar.gw.example.net/app/<rest>   ->   http://10.0.0.1:1234/<rest>
```

`user_id` is the scope: `NULL` makes a gate available to every account, a value
restricts it to that account, and deleting the account removes its gates.

Schema changes are versioned: `PRAGMA user_version` records how many entries of
`internal/store/migrations.go` have been applied, and an existing database
upgrades in place on the next start (covered by migration tests). Migration 3
introduces the `gate` table and drops the earlier `gateway_rules` table;
migration 4 adds the scope column.

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
- Management endpoints re-check the account and its role in the database on
  every call, and refuse to remove the last administrator or the signed-in
  account.
- The user portal refuses to serve anything unless the request Host matches the
  configured gateway domain; a mismatch drops the connection instead of
  returning a page.
- Passwords chosen in the admin area must be at least 8 bytes; resets store a
  fresh Argon2id hash and never return the old one.
- Responses carry `X-Content-Type-Options`, `X-Frame-Options`,
  `Referrer-Policy` and a `Content-Security-Policy` that allows scripts and
  styles only from the app itself (`'self'`) plus inline, which the embedded
  bundle and the login page need.

## Layout

```text
main.go                     wiring: flags, database, HTTP server, one-time banner
internal/passwd             Argon2id hashing, password generation, username rules
internal/store              SQLite schema, users table, bootstrap admin seeding
internal/httpapi            routes, auth and admin handlers, sessions, limiter
internal/httpapi/templates  the login page served by the Go handler
internal/webui              go:embed of the built bundle + SPA file server
internal/webui/dist         Vite output (committed, embedded into the binary)
web                         React 19 + Ant Design sources (Vite, TypeScript)
Makefile                    build, cross-compile, quality gates, reserved docker/release targets
```

## Tests

```sh
make test        # or: go test ./...
make test-race   # needs cgo and gcc
```

## License

MIT — see [LICENSE](LICENSE).
