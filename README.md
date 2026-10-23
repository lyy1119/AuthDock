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
./authdock -addr 127.0.0.1:8080 -gateway-addr 127.0.0.1:8081 -db data/authdock.db
```

Then open <http://127.0.0.1:8080/login> for the management area and
<http://gw.example.net:8081/> for the user portal (see below). Running
`./authdock` with no arguments works out of the box; these are the defaults:

| Flag                    | Default (env)                             | Description                                    |
| ----------------------- | ----------------------------------------- | ---------------------------------------------- |
| `-addr`                 | `127.0.0.1:8080` (`AUTH_DOCK_ADDR`)       | Management listen address                      |
| `-gateway-addr`         | `127.0.0.1:8081` (`AUTH_DOCK_GATEWAY_ADDR`) | Gateway listen address (portal + services)   |
| `-portal-addr`          | unset (`AUTH_DOCK_PORTAL_ADDR`)            | Optional extra listener serving only the login portal |
| `-db`                   | `data/authdock.db` (`AUTH_DOCK_DB`)       | SQLite database file, relative to the CWD      |
| `-no-dn-check`          | off                                       | Skip the portal domain check (debug only)      |
| `-version`              |                                           | Print build information and exit               |
| `-reset-admin-password` |                                           | New random admin password (creates the account if missing), printed once, exit |

Every listener setting can also come from the environment, which is what the
systemd unit and the container use. A command line flag always wins over its
variable:

| Environment variable      | Flag             | Default           |
| ------------------------- | ---------------- | ----------------- |
| `AUTH_DOCK_ADDR`          | `-addr`          | `127.0.0.1:8080`  |
| `AUTH_DOCK_GATEWAY_ADDR`  | `-gateway-addr`  | `127.0.0.1:8081`  |
| `AUTH_DOCK_PORTAL_ADDR`   | `-portal-addr`   | unset             |
| `AUTH_DOCK_DB`            | `-db`            | `data/authdock.db` |
| `AUTH_DOCK_NO_DN_CHECK`   | `-no-dn-check`   | off (`1`/`true`/`yes`/`on` enable it) |

```sh
AUTH_DOCK_ADDR=127.0.0.1:8080 \
AUTH_DOCK_GATEWAY_ADDR=127.0.0.1:8081 \
AUTH_DOCK_DB=/var/lib/authdock/authdock.db \
  ./authdock
```

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

## Gateway

AuthDock's gateway terminates nothing itself: it speaks plain HTTP on
`-gateway-addr` (default `127.0.0.1:8081`) and expects Caddy (or any reverse
proxy) to own TLS and forward both the apex host and its subdomains to it.

```caddyfile
# TLS terminates here; AuthDock sees plain HTTP plus X-Forwarded-Proto.
gw.example.net, *.gw.example.net {
	reverse_proxy 127.0.0.1:8081
}
```

A wildcard certificate needs the DNS challenge
(`tls { dns <provider> ... }`). The management UI keeps listening on
`127.0.0.1:8080` and should stay private.

**Host routing.** The gateway dispatches on the `Host` header:

| Host                          | Served                                          |
| ----------------------------- | ----------------------------------------------- |
| `gw.example.net` (the apex)   | the login portal and `/api/login`, `/api/session` |
| `<label>.gw.example.net`      | the published service(s) for that label         |
| anything else                 | refused: the connection is dropped, no page     |

**Per account routing.** Two accounts may publish the same public address and
still reach different upstreams: the gateway resolves the gate *for the
signed-in account*.

```text
alice: calendar.gw.example.net -> 127.0.0.1:9101
bob:   calendar.gw.example.net -> 127.0.0.1:9102
```

Resolution order for a request: gates with an exact `<to_prefix>` beat the `*`
wildcard, an account scoped gate beats a global one, and a longer `<to_suffix>`
path prefix beats a shorter one. `to_suffix` is stripped before forwarding, so
`app.gw.example.net/tools/deep` with `to_suffix = tools` reaches the upstream as
`/deep`.

Answers: the right gate is proxied. Anything else — an address that belongs to
another account, or an address nobody published — gets the **same** `404` page,
so a visitor cannot learn which routes other accounts have registered. That page
names the signed-in account, explains that it has no route to this address, and
offers a button back to the portal, which lists the addresses the account can
actually reach. A
visitor without a session is redirected to the portal
(`https://gw.example.net/login?return_to=<original URL>`).

The bounce target is validated against the gateway domain (no open redirect) and
carried three ways, so it survives proxies that rewrite or drop the query
string: the `return_to` query parameter, the JSON body the page posts, and a
short-lived `gateway_return_to` cookie the gateway sets when it redirects. The
first acceptable one wins and is cleared after login. When there is no bounce
target at all — the login page was opened directly — the success panel lists the
addresses the account can reach instead of leaving the visitor on a dead end.

**Talking to the upstream.** Two settings under 系统设置 shape the hop to the
published service:

| Setting | Values | Meaning |
| ------- | ------ | ------- |
| 上游 Host 传递方式 / `upstream_host` | `upstream` (default), `preserve` | `upstream` sends the address the gateway dials, which is what application servers expect (many validate Host); `preserve` forwards the public Host instead, needed only when the upstream picks its site from a virtual host header (a second Caddy or nginx). |
| 跳过上游 HTTPS 证书校验 / `upstream_insecure` | off (default), on | Lets the gateway reach an https upstream whose certificate it cannot verify, such as Caddy's `tls internal` CA. |
| 界面配色 / `theme` | `light` (default), `dark`, `auto` | Colour scheme for the management UI, the login page, the portal and the gateway's own error pages. `auto` follows the operating system. |

Point `from` at the address that already speaks the right protocol: a service
that only serves HTTPS needs `https://10.0.0.1:443`, a plain HTTP service needs
`10.0.0.1:8080`. A redirect the upstream sends back to the very address the
visitor asked for is detected and answered with a page that explains the loop
instead of letting the browser bounce forever — that is the usual symptom of
pointing an `http://` gate at an HTTPS-only upstream.

**Proxy headers.** The gateway accepts `X-Forwarded-Host` and
`X-Forwarded-Proto` from the proxy. When a proxy rewrites `Host` to its upstream
address (nginx does unless you set `proxy_set_header Host $host`), the forwarded
host is what identifies the service and what goes into `return_to` and rewritten
`Location` headers, so the login bounce still lands on the public address.

**Cookies.** The session travels in one cookie, and the gateway owns it
completely:

```http
Set-Cookie: __Secure-gateway_session=...; Domain=gw.example.net; Path=/;
            Secure; HttpOnly; SameSite=Lax; Max-Age=43200
```

- `Domain=` is what makes per-account routing possible: the address
  `calendar.gw.example.net` must be able to see the session.
- `__Secure-` (and `Secure`) is used when the request arrived over TLS;
  a plain HTTP development run falls back to `gateway_session` because browsers
  discard `__Secure-` cookies that are not sent over TLS.
- `SameSite=Lax` rather than `Strict`, so a visitor arriving from an external
  link is not treated as signed out.
- Only set on login (and cleared on logout), never re-emitted on every response.
- `__Secure-gateway_session`, `gateway_session` and the management cookie
  `authdock_session` are **stripped from every request before it goes upstream**
  and any upstream `Set-Cookie` for those names is dropped, so a published
  service can neither read nor overwrite the session. Other cookies pass
  through untouched. Upstream `Location` headers pointing at the upstream host
  are rewritten to the public address.

Sessions live in SQLite (`sessions` table, only a SHA-256 hash of the token is
stored), so restarting AuthDock no longer signs everyone out.

**The two ports are fully separated.**

| | Management (`-addr`, 8080) | Gateway (`-gateway-addr`, 8081) |
| --- | --- | --- |
| Accepts | `admin` accounts only (`403 admin_only` otherwise) | ordinary accounts only (`403 user_only` otherwise) |
| Cookie | `authdock_session`, host-only | `__Secure-gateway_session` / `gateway_session`, `Domain=` the gateway domain |
| Session scope | `admin` | `gateway` |

A session is bound to its scope in the database, so neither cookie is even
recognised by the other port: signing in as an administrator at 8080 leaves the
portal anonymous, and a portal session answers `401` from the management API.
Both SQLite tables and both listeners can be moved to different hosts later
without changing this rule.

## Pages

| Listener / Path     | Description                                              |
| ------------------- | -------------------------------------------------------- |
| `/login`            | Admin login page (served by the Go handler, no build)    |
| `/` on the gateway  | User login page (apex host, see below)                   |
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
| POST   | `/api/login`  | `{"username","password","return_to"?}`, ordinary accounts only (`user_only` otherwise) |
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
| GET    | `/api/admin/settings`    | `{"gateway_domain","upstream_host","upstream_insecure","theme"}` |
| PUT    | `/api/admin/settings`    | Same four fields; `upstream_host` is `upstream`/`preserve`, `theme` is `light`/`dark`/`auto` |

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
restricts it to that account, and deleting the account removes its gates. Routes
are unique per scope (two accounts may publish the same address), enforced with
two partial unique indexes.

```sql
CREATE TABLE sessions (
    token_hash TEXT PRIMARY KEY,   -- SHA-256 of the cookie token
    username   TEXT NOT NULL,
    role       TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    expires_at TEXT NOT NULL
);
```

Schema changes are versioned: `PRAGMA user_version` records how many entries of
`internal/store/migrations.go` have been applied, and an existing database
upgrades in place on the next start (covered by migration tests). Migration 3
introduces the `gate` table and drops the earlier `gateway_rules` table;
migration 4 adds the scope column and migration 5 adds the session table plus the
per-scope route indexes.

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
- The gateway refuses to serve anything unless the request Host belongs to the
  configured gateway domain; a mismatch drops the connection instead of
  returning a page, and the same check covers the login page and every routed
  service.
- Published services never see AuthDock's cookies, and cannot overwrite them.
- `return_to` is validated against the gateway domain, so the login page cannot
  be used as an open redirect.
- Management and gateway sessions are separate scopes in the database: an admin
  cookie is worthless at the portal and a portal cookie is worthless at the
  management API.
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
