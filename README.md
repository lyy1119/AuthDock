# AuthDock

A SSO pedestal for small personal projects.

AuthDock is a single Go binary that owns the accounts behind your side projects.
It keeps them in one SQLite file, signs people in with Argon2id-hashed passwords,
publishes those projects through a small HTTP gateway (TLS left to Caddy), and
ships a React management UI that is embedded in the binary.

- **Accounts**: `users` table, Argon2id hashes, `user` and `admin` roles.
- **Login**: a user portal, plus JSON + bearer token APIs for native clients.
- **Gateway**: `calendar.gw.example.net` → `10.0.0.1:1234`, and two accounts may
  publish the same address to different upstreams.
- **Single artifact**: `go build` produces one executable with the UI inside.

## Contents

- [Quick start](#quick-start)
- [Listeners and topology](#listeners-and-topology)
- [Configuration](#configuration)
- [Authentication model](#authentication-model)
- [API reference](#api-reference)
- [Gateway behaviour](#gateway-behaviour)
- [Management UI](#management-ui)
- [Data model](#data-model)
- [Security notes](#security-notes)
- [Operations and troubleshooting](#operations-and-troubleshooting)
- [Development](#development)
- [License](#license)

## Quick start

```sh
make build          # builds the frontend, then the binary that embeds it
./bin/authdock      # management on :8080, gateway on :8081
```

The first start creates the `admin` account and prints its random password once:

```text
  AuthDock 已初始化默认管理员账号（users 表原本为空）

    username : admin
    password : ****

  Only show once —— 该密码只显示这一次，请立即保存到安全的地方。
  数据库里只保存 Argon2id 哈希，关闭本提示后无法再取回该密码。
  登录时只填冒号右边这 8 个字符，不要带空格或 "password :" 前缀。
  忘记密码可随时执行：authdock -reset-admin-password
  database : /path/to/data/authdock.db
```

Save it, open <http://127.0.0.1:8080/login>, then:

1. 系统设置 → set the **网关域名** (e.g. `gw.example.net`), pick the theme.
2. 用户管理 → create the accounts the projects belong to.
3. 网关设置 → add gates: 名称, 目标 (`<subdomain>.<gateway domain>/<path prefix>`),
   源 (`host:port` or `https://host:port`).

Lost the password? `./bin/authdock -reset-admin-password` (or
`make reset-password`) prints a new one once.

## Listeners and topology

| Listener | Flag / env | Serves |
| -------- | ---------- | ------ |
| Management | `-addr`, `AUTH_DOCK_ADDR` (default `127.0.0.1:8080`) | `/login`, the management UI at `/admin/`, `/api/auth/*`, `/api/admin/*` |
| Gateway | `-gateway-addr`, `AUTH_DOCK_GATEWAY_ADDR` (default `127.0.0.1:8081`) | The portal on the gateway domain itself, published services on its subdomains |
| Portal only | `-portal-addr`, `AUTH_DOCK_PORTAL_ADDR` (unset) | Optional extra listener that serves *only* the login portal; it refuses subdomains |

AuthDock speaks plain HTTP on both. TLS belongs to a reverse proxy:

```caddyfile
# Caddy terminates TLS and forwards both the apex and every subdomain.
gw.example.net, *.gw.example.net {
	reverse_proxy 127.0.0.1:8081
}
```

Caddy's default is to preserve `Host` and add `X-Forwarded-Host`; AuthDock uses
`X-Forwarded-Host`/`X-Forwarded-Proto` when present. A wildcard certificate needs
the DNS challenge (`tls { dns <provider> ... }`). Keep the management listener on
loopback and reach it through an SSH tunnel or a proxy with its own access rule.

## Configuration

A flag always wins over its environment variable. All values are validated at
start-up; an invalid duration is reported and replaced by the default.

| Flag | Environment variable | Default | Meaning |
| ---- | -------------------- | ------- | ------- |
| `-addr` | `AUTH_DOCK_ADDR` | `127.0.0.1:8080` | Management listen address |
| `-gateway-addr` | `AUTH_DOCK_GATEWAY_ADDR` | `127.0.0.1:8081` | Gateway listen address |
| `-portal-addr` | `AUTH_DOCK_PORTAL_ADDR` | unset | Extra portal-only listener (skipped if it equals the gateway address) |
| `-db` | `AUTH_DOCK_DB` | `data/authdock.db` | SQLite file; resolved to an absolute path in logs |
| `-no-dn-check` | `AUTH_DOCK_NO_DN_CHECK` | off | Skip the gateway domain check (debug only; `1`/`true`/`yes`/`on`) |
| `-version` | – | – | Print build information and exit |
| `-reset-admin-password` | – | – | New random admin password, printed once, exit |
| – | `AUTH_DOCK_REFRESH_TTL` | `720h` (30 days) | Lifetime of refresh tokens |

```sh
AUTH_DOCK_ADDR=127.0.0.1:8080 \
AUTH_DOCK_GATEWAY_ADDR=127.0.0.1:8081 \
AUTH_DOCK_DB=/var/lib/authdock/authdock.db \
AUTH_DOCK_REFRESH_TTL=168h \
  ./authdock
```

Everything else (gateway domain, upstream behaviour, theme) lives in the
database and is edited in 系统设置.

## Authentication model

Two audiences, never interchangeable. The scope is a property of the session row
in the database, not of the request.

| | Management (`-addr`) | Gateway (`-gateway-addr`) |
| --- | --- | --- |
| Accepts | `admin` accounts only (`403 admin_only` otherwise) | ordinary accounts only (`403 user_only` otherwise) |
| Session scope | `admin` | `gateway` |
| Cookie | `authdock_session`, host-only | `__Secure-gateway_session` (or `gateway_session` over plain HTTP), `Domain=<gateway domain>` |
| API tokens | `POST /api/auth/login`, `POST /api/auth/token` | `POST /api/login`, `POST /api/token` |

Consequences: signing in as an administrator at the management port leaves the
portal anonymous, and a portal cookie or token is rejected (`401`) by
`/api/admin/*`.

### Cookies (browsers)

```http
Set-Cookie: __Secure-gateway_session=...; Domain=gw.example.net; Path=/;
            Secure; HttpOnly; SameSite=Lax; Max-Age=43200
```

- `Domain=` is what makes per-account routing possible: the app host must be able
  to see the session.
- `__Secure-` and `Secure` appear when the request arrived over TLS; a plain HTTP
  development run falls back to `gateway_session` because browsers drop
  `__Secure-` cookies that are not sent over TLS.
- `SameSite=Lax`, not `Strict`, so arriving from an external link does not look
  like a signed-out visit.
- Set on login, cleared on logout — never re-emitted on every response.

### Tokens (native clients)

Login responses also carry a token pair:

```json
{
  "ok": true,
  "user": { "username": "alice", "role": "user" },
  "expires_at": "2026-01-01T12:00:00Z",
  "refresh_expires_at": "2026-01-31T12:00:00Z",
  "token": "access-token",
  "refresh_token": "refresh-token",
  "addresses": ["https://calendar.gw.example.net/"]
}
```

- `token` is the access token: send it as `Authorization: Bearer <token>`. It
  lives 12h.
- `refresh_token` lives 30 days and is exchanged **once** at `POST /api/token`
  (gateway) or `POST /api/auth/token` (management) for a new pair. The presented
  refresh token is consumed, so a replay is rejected.
- Both tokens are opaque random strings; the database stores only their SHA-256
  hash.
- Signing out (`POST /api/logout`) revokes the whole login: the access token and
  the refresh token of that chain stop working.
- Cookies are still issued for browsers; a request may present either.

## API reference

All responses are JSON. Failures use one envelope:

```json
{ "ok": false, "code": "invalid_credentials", "message": "用户名或密码错误" }
```

| Code | HTTP | Meaning |
| ---- | ---- | ------- |
| `invalid_request` | 400 | Malformed JSON, unknown field, bad value |
| `invalid_credentials` | 401 | Wrong username or password |
| `invalid_refresh_token` | 401 | Refresh token unknown, already used or expired |
| `unauthenticated` | 401 | No session, or the session expired |
| `admin_only` | 403 | Valid credentials, but the account is not an admin |
| `user_only` | 403 | Administrator tried to use the portal |
| `too_many_attempts` | 429 | Five failed logins for that username; `Retry-After` tells you when |
| `username_taken` | 409 | Username already exists |
| `last_admin` | 409 | Refusing to remove or demote the last administrator |
| `self_delete` | 409 | Refusing to delete the signed-in account |
| `gate_exists` | 409 | Another gate already owns this subdomain + path prefix |
| `method_not_allowed` | 405 | Wrong verb for that endpoint |
| `not_found` | 404 | Unknown endpoint, user, gate or address |
| `internal_error` | 500 | Server side failure; details are in the log |

### Authentication (management listener)

```http
POST /api/auth/login    {"username":"admin","password":"..."}   -> token pair
POST /api/auth/token    {"refresh_token":"..."}                 -> new token pair
POST /api/auth/logout                                            -> {"ok":true}
GET  /api/auth/session                                           -> current session or 401
```

The login response also sets the `authdock_session` cookie. Demoting your own
account answers `{"logged_out":true}` and revokes the session.

### Portal (gateway listener, apex host only)

```http
GET  /             or /login     the login page (HTML)
POST /api/login    {"username":"alice","password":"...","return_to":"https://calendar.gw.example.net/today"}
POST /api/token    {"refresh_token":"..."}
POST /api/logout
GET  /api/session                -> user, expiry, gateway domain, reachable addresses
```

`return_to` is validated against the gateway domain and echoed back as
`redirect_to`. It can arrive in the body, in the query string or in the
`gateway_return_to` cookie the gateway sets when it bounces a visitor — the first
acceptable value wins, so a proxy that drops the query string cannot lose it.
Without a target, the response lists the account's `addresses` so the page can
show what it may open.

### Management (requires an admin session or admin token)

```http
GET    /api/admin/users              list accounts (`self` marks the signed-in one)
POST   /api/admin/users              {"username","password","role"} create
PATCH  /api/admin/users/{id}         {"role"?,"password"?} update
DELETE /api/admin/users/{id}         delete (not yourself, never the last admin)

GET    /api/admin/gates              {"gateway_domain","gates":[...]}
POST   /api/admin/gates              {"name","from","to_prefix","to_suffix","user_id"}
PATCH  /api/admin/gates/{id}         same fields
DELETE /api/admin/gates/{id}

GET    /api/admin/settings           {"gateway_domain","upstream_host","upstream_insecure","theme"}
PUT    /api/admin/settings           same four fields
```

## Gateway behaviour

### Host dispatch

| Request host | Served |
| ------------ | ------ |
| the gateway domain (`gw.example.net`) | the portal and its `/api/*` endpoints |
| `<label>.<gateway domain>` (`calendar.gw.example.net`) | the published service for that label |
| anything else | the connection is dropped: no page, nothing revealed |

`-no-dn-check` disables that check for local debugging; the start-up log records
`domain_check=off`.

### Routing

Each gate publishes `https://<to_prefix>.<gateway domain>/<to_suffix><rest>` from
`<from><rest>`. Several gates may share an address:

```text
alice: calendar.gw.example.net -> 127.0.0.1:9101
bob:   calendar.gw.example.net -> 127.0.0.1:9102
```

Resolution order for one request: an exact `<to_prefix>` beats the `*` wildcard,
an account-scoped gate beats a global one, a longer `<to_suffix>` beats a shorter
one. `to_suffix` is stripped before forwarding, so
`app.gw.example.net/tools/deep` with `to_suffix = tools` reaches the upstream as
`/deep`.

### Answers

| Situation | Response |
| --------- | -------- |
| Signed in, gate found | Proxied |
| Signed in, no gate for this account (or nobody published it) | `404` with a neutral page: it names the account, explains there is no route, and offers buttons back to the portal. Foreign and missing addresses are **indistinguishable**, so routes cannot be enumerated. |
| Not signed in | `302` to `https://<gateway domain>/login?return_to=<original URL>` |

### What the upstream sees

- `Host`: the address the gateway dials (default), or the public host when
  「上游 Host 传递方式」 is set to `preserve` — needed only for an upstream that
  picks its site from the virtual host header, such as another Caddy or nginx.
  Most application servers validate `Host`, so `upstream` is the default.
- `X-Forwarded-For`, `X-Forwarded-Host`, `X-Forwarded-Proto` are added.
- **No AuthDock cookies**: `__Secure-gateway_session`, `gateway_session` and
  `authdock_session` are stripped, and any upstream `Set-Cookie` for those names
  is dropped, so a service can neither read nor overwrite the session. Other
  cookies pass through untouched.
- Upstream `Location` headers pointing at the upstream host are rewritten to the
  public address, and percent-encoded paths are preserved.

### Upstream TLS

`from` accepts `host:port` (plain HTTP) or `https://host:port`. An https upstream
whose certificate AuthDock cannot verify — a Caddy with `tls internal`, a self
signed service — needs 「跳过上游 HTTPS 证书校验」 (`upstream_insecure`); without
it the request fails with a clear `502` and the certificate error in the log.

### The redirect guard

If an upstream answers with a redirect that would loop — the target is the
address the visitor just asked for, or a plain HTTP request is answered with an
HTTPS redirect for the same host and path — AuthDock answers `502` with a page
explaining the loop instead of letting the browser bounce. That is what pointing
an `http://` gate at an HTTPS-only service looks like; the fix is an `https://`
`from` (plus the CA opt-in) or an HTTP port on the service.

## Management UI

Served at `/admin/` (React 19 + Ant Design, routes in the URL hash so the server
only ever serves one shell):

| Page | What it does |
| ---- | ------------ |
| 用户管理 | Accounts with an inline password field, a role select, a per-row save button, create dialog and delete. The signed-in account is marked and cannot delete itself; demoting yourself signs you out. |
| 网关设置 | One row per gate: 名称, 目标 (`https://<prefix>.<domain>/<suffix>`, edited inline), 源, 作用域 (global or one account), save and delete, plus a create dialog. |
| 系统设置 | Gateway domain, upstream Host mode, upstream certificate check, and 界面配色 (亮色 / 暗色 / 自动). |

The theme applies to the management UI, the login page, the portal and the
gateway's own error pages; 「自动」 follows the operating system (`auto` is done
in CSS for the server-rendered pages and with `prefers-color-scheme` plus a
cached value in the SPA, so a reload does not flash the wrong palette).

## Data model

```sql
CREATE TABLE users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE,              -- 1-20 characters
    password_hash TEXT    NOT NULL,                     -- Argon2id PHC string
    role          TEXT    NOT NULL DEFAULT 'user',      -- 'user' | 'admin'
    created_at    TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE TABLE settings (
    key   TEXT PRIMARY KEY,                             -- gateway_domain, upstream_host,
    value TEXT NOT NULL                                 -- upstream_insecure, theme
);

CREATE TABLE gate (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT    NOT NULL,                        -- display name, e.g. 日历
    "from"     TEXT    NOT NULL,                        -- 10.0.0.1:1234 or https://10.0.0.1:443
    to_prefix  TEXT    NOT NULL,                        -- subdomain label or '*'
    to_suffix  TEXT    NOT NULL DEFAULT '',             -- path prefix, stripped when forwarding
    user_id    INTEGER REFERENCES users (id) ON DELETE CASCADE,  -- NULL = global
    created_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    UNIQUE (to_prefix, to_suffix)                       -- per scope, see migrations
);

CREATE TABLE sessions (
    token_hash TEXT PRIMARY KEY,                        -- SHA-256 of the token
    username   TEXT NOT NULL,
    role       TEXT NOT NULL,
    scope      TEXT NOT NULL DEFAULT 'admin',           -- 'admin' | 'gateway'
    kind       TEXT NOT NULL DEFAULT 'access',          -- 'access' | 'refresh'
    family     TEXT NOT NULL DEFAULT '',                -- one login = one family
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    expires_at TEXT NOT NULL
);
```

Migrations live in `internal/store/migrations.go` and are applied in order, with
the last applied version stored in `PRAGMA user_version`; an existing database
upgrades in place on the next start.

| Version | Change |
| ------- | ------ |
| 1 | `users` |
| 2 | `settings`, per-user `gateway_rules` |
| 3 | `gate` table, drops `gateway_rules` |
| 4 | `gate.user_id` (scope) |
| 5 | `sessions`; gate routes unique per scope |
| 6 | `sessions.scope` |
| 7 | `sessions.kind` and `sessions.family` (refresh tokens, revocation) |

## Security notes

- Passwords: Argon2id, 64 MiB / 3 passes / 2 lanes; verification is constant time
  and an unknown username costs the same work as a wrong password.
- Only admins may use the management area; only ordinary accounts may use the
  portal. Sessions are scoped in the database, so a cookie or token cannot cross.
- Five failed logins for one username lock it for a minute (`429`).
- The gateway refuses any Host outside the gateway domain (the connection is
  dropped), for the login page and for every routed address.
- Published services never see AuthDock cookies and cannot overwrite them.
- `return_to` only accepts addresses inside the gateway domain (no open
  redirect), and foreign routes look exactly like unassigned ones.
- Sessions store a hash of the token, not the token; refresh tokens are single
  use and a logout revokes the whole chain.
- The database file and its `-wal`/`-shm` sidecars are created `0600`; the process
  umask is tightened at start-up.
- Responses carry `X-Content-Type-Options`, `X-Frame-Options: DENY`,
  `Referrer-Policy: no-referrer` and a `Content-Security-Policy` that allows
  scripts and styles only from the app itself plus inline (the embedded bundle and
  the login page need both).

## Operations and troubleshooting

Logs go to stderr as `log/slog` text. Useful lines:

| Line | Meaning |
| ---- | ------- |
| `AuthDock listening` / `AuthDock gateway listening` | Listeners are up, with their addresses and the DB path |
| `gateway forwarding gate=... user=... upstream=...` | A request was authenticated and proxied |
| `gateway address has no gate` / `belongs to another account` | 404 shown to the visitor; the difference stays in the log |
| `gateway refused a connection` | The Host was not the gateway domain (or the domain is unset) |
| `gateway upstream failed` | The upstream could not be reached (DNS, refused, TLS) |
| `gateway upstream redirects to itself` | The redirect guard fired; see the loop section |
| `portal login succeeded` / `portal login failed` | Login outcomes, with the reason |
| `users table already initialized` | The bootstrap banner is not printed again |

Symptom → cause:

| Symptom | Likely cause | Fix |
| ------- | ------------ | --- |
| Login page loads unstyled, or nothing happens on submit | A reverse proxy dropped `Host`/`X-Forwarded-*`, or the static files are blocked by an outer CSP | Forward `Host` and `X-Forwarded-Proto`; check the browser console |
| `405` on `/api/...` when served through a proxy | The request hit the proxy root instead of the app (a path-prefix setup) | Use relative URLs (the app does) and make sure the prefix is stripped both ways |
| Endless `308` to the same address | The gate's `from` speaks plain HTTP to an HTTPS-only upstream | Use `https://` in `from` plus the CA opt-in, or an HTTP port |
| `502` mentioning `x509` | The upstream certificate cannot be verified (`tls internal`) | 系统设置 → 跳过上游 HTTPS 证书校验 |
| `502 bad gateway` without x509 | The upstream is unreachable | Check `from` and the service |
| Subdomains answer nothing at all | The proxy points at `-portal-addr`, which refuses subdomains, or the Host is not under the gateway domain | Point the proxy at `-gateway-addr`; check the configured domain |
| Signed in, but stuck on the "signed in" panel | No bounce target reached the server | The gateway sets a `gateway_return_to` cookie; check that the proxy forwards query strings and cookies |
| `404` "这个地址暂时不可用" | No gate for this account (or none at all) | 网关设置 → add a gate for that account |
| The login form rejects a correct password | Five failures locked it, or the password was copied with the `password : ` prefix | Wait a minute; type only the eight characters |

Backups: stop the process (or use `sqlite3 authdock.db ".backup out.db"`) and
copy the file; it holds the hashes, gates and sessions. Expired sessions are
deleted when they are touched and by `PruneSessions`.

## Development

```sh
make                # list every target
make build          # frontend + Linux x86_64 binary with the UI embedded
make build-backend  # Go only, reusing the committed bundle (no Node needed)
make build-windows  # frontend + Windows x86_64 binary
make test           # go test ./...
make test-race      # with the race detector (needs cgo)
make web-check      # TypeScript type check
make ci             # fmt-check + vet + test + web-check + both builds
make run            # run from source with bin/dev.db
```

The frontend lives in `web/` (Vite + React 19 + Ant Design 5 + TypeScript). Its
build output is emitted into `internal/webui/dist`, committed, and embedded with
`go:embed` — that is why `go build` alone produces a complete binary. After
changing frontend sources run `make web` (or any build target), which needs
Node.js 20+.

```text
main.go                     flags, database, the three listeners, banner
internal/passwd             Argon2id hashing, password generation, username rules
internal/store              SQLite schema, migrations, users, gates, settings, sessions
internal/httpapi            routes, auth + admin + portal handlers, gateway proxy
internal/httpapi/templates  login page and portal page (server rendered)
internal/webui              embedded React bundle + SPA file server
web/                        React sources (Vite, TypeScript, Ant Design)
internal/store/migrations.go  ordered schema migrations
```

`go test ./...` covers password handling, the schema and its migrations, the
admin API, the portal, the gateway (routing, cookies, TLS, redirect guard,
privacy) and the SPA handler. `make ci` is what a pipeline should call.

## License

MIT — see [LICENSE](LICENSE).
