package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lyy1119/AuthDock/internal/passwd"
	"github.com/lyy1119/AuthDock/internal/store"
)

const (
	gatewayDomainName = "gw.example.net"
	alicePassword     = "alicepass1"
	bobPassword       = "bobpasswd1"
)

// upstreamRecord captures what a published service received.
type upstreamRecord struct {
	name    string
	mu      sync.Mutex
	paths   []string
	cookies []string
	hosts   []string
	xfHosts []string
}

func (r *upstreamRecord) last() (path, cookie, host string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.paths) == 0 {
		return "", "", ""
	}
	return r.paths[len(r.paths)-1], r.cookies[len(r.cookies)-1], r.hosts[len(r.hosts)-1]
}

// newUpstream starts a stand-in for a published service.
func newUpstream(t *testing.T, name string) (*httptest.Server, *upstreamRecord) {
	t.Helper()
	record := &upstreamRecord{name: name}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		record.mu.Lock()
		record.paths = append(record.paths, r.URL.Path+"?"+r.URL.RawQuery)
		record.cookies = append(record.cookies, r.Header.Get("Cookie"))
		record.hosts = append(record.hosts, r.Host)
		record.xfHosts = append(record.xfHosts, r.Header.Get("X-Forwarded-Host"))
		record.mu.Unlock()

		for _, cookie := range r.Header.Values("X-Test-Set-Cookie") {
			w.Header().Add("Set-Cookie", cookie)
		}
		if r.URL.Query().Has("go") {
			w.Header().Set("Location", "http://"+r.Host+"/elsewhere")
			w.WriteHeader(http.StatusFound)
			return
		}
		w.Header().Set("X-Upstream", record.name)
		_, _ = fmt.Fprintf(w, "hello from %s at %s", record.name, r.URL.Path)
	}))
	t.Cleanup(server.Close)
	return server, record
}

type gatewayEnv struct {
	handler http.Handler
	admin   http.Handler
	db      *store.Store
	clock   *fakeClock
}

func newGatewayEnv(t *testing.T, noDNCheck bool) *gatewayEnv {
	t.Helper()

	hasher, err := passwd.NewHasher(passwd.Params{
		Memory: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32,
	})
	if err != nil {
		t.Fatalf("NewHasher: %v", err)
	}
	db, err := store.Open(filepath.Join(t.TempDir(), "authdock.db"), hasher)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	ctx := context.Background()
	if err := db.SetSetting(ctx, store.SettingsKeyGatewayDomain, gatewayDomainName); err != nil {
		t.Fatalf("SetSetting: %v", err)
	}
	if _, err := db.CreateUser(ctx, "alice", alicePassword, store.RoleUser); err != nil {
		t.Fatalf("create alice: %v", err)
	}
	if _, err := db.CreateUser(ctx, "bob", bobPassword, store.RoleUser); err != nil {
		t.Fatalf("create bob: %v", err)
	}
	if _, err := db.CreateUser(ctx, "boss", "bosspass12", store.RoleAdmin); err != nil {
		t.Fatalf("create boss: %v", err)
	}

	clock := &fakeClock{current: time.Date(2026, time.January, 1, 12, 0, 0, 0, time.UTC)}
	options := Options{
		Store:     db,
		Sessions:  NewDBSessions(db, DefaultSessionTTL),
		Now:       clock.Now,
		Logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		NoDNCheck: noDNCheck,
	}
	return &gatewayEnv{handler: NewGateway(options), admin: New(options), db: db, clock: clock}
}

func (e *gatewayEnv) userID(t *testing.T, username string) int64 {
	t.Helper()
	user, err := e.db.GetUserByUsername(context.Background(), username)
	if err != nil {
		t.Fatalf("GetUserByUsername(%q): %v", username, err)
	}
	return user.ID
}

func (e *gatewayEnv) gate(t *testing.T, name, from, prefix, suffix string, userID *int64) *store.Gate {
	t.Helper()
	gate, err := e.db.CreateGate(context.Background(), name, from, prefix, suffix, userID)
	if err != nil {
		t.Fatalf("CreateGate(%q): %v", name, err)
	}
	return gate
}

// requestAt performs a request as the browser would after Caddy forwarded it.
func requestAt(handler http.Handler, method, host, uri string, cookie *http.Cookie, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, "http://"+host+uri, nil)
	req.Host = host
	if cookie != nil {
		req.AddCookie(cookie)
	}
	for name, value := range headers {
		req.Header.Set(name, value)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

// login authenticates at the portal and returns the gateway cookie.
func (e *gatewayEnv) login(t *testing.T, username, password, returnTo string) *http.Cookie {
	t.Helper()
	payload, err := json.Marshal(map[string]string{
		"username": username, "password": password, "return_to": returnTo,
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "http://"+gatewayDomainName+"/api/login", bytes.NewReader(payload))
	req.Host = gatewayDomainName
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	e.handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("login = %d, body = %s", rec.Code, rec.Body.String())
	}
	cookie := gatewayCookie(t, rec)
	if cookie == nil {
		t.Fatal("login produced no gateway cookie")
	}
	return cookie
}

func TestGatewayServesPortalAtApex(t *testing.T) {
	env := newGatewayEnv(t, false)

	rec := requestAt(env.handler, http.MethodGet, gatewayDomainName, "/", nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("apex / = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "使用你的账号登录") {
		t.Fatal("apex did not serve the login page")
	}

	if rec := requestAt(env.handler, http.MethodGet, gatewayDomainName, "/login", nil, nil); rec.Code != http.StatusOK {
		t.Fatalf("apex /login = %d, want 200", rec.Code)
	}
}

func TestGatewayRefusesForeignHost(t *testing.T) {
	env := newGatewayEnv(t, false)

	rec := requestAt(env.handler, http.MethodGet, "evil.example.org", "/", nil, nil)
	if rec.Code != http.StatusMisdirectedRequest {
		t.Fatalf("foreign host = %d, want 421", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "使用你的账号登录") {
		t.Fatal("the login page leaked to a foreign host")
	}
}

func TestGatewayBouncesAnonymousToLogin(t *testing.T) {
	env := newGatewayEnv(t, false)
	env.gate(t, "public", "127.0.0.1:9", "public", "", nil)

	rec := requestAt(env.handler, http.MethodGet, "public."+gatewayDomainName, "/deep/path?x=1", nil, nil)
	if rec.Code != http.StatusFound {
		t.Fatalf("anonymous gate request = %d, want 302", rec.Code)
	}

	location := rec.Header().Get("Location")
	parsed, err := url.Parse(location)
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	if parsed.Host != gatewayDomainName || parsed.Path != "/login" {
		t.Fatalf("Location = %q, want the gateway login page", location)
	}
	returnTo := parsed.Query().Get("return_to")
	if returnTo != "http://public."+gatewayDomainName+"/deep/path?x=1" {
		t.Fatalf("return_to = %q", returnTo)
	}
}

// TestGatewayRoutesTheSameHostPerUser is the core requirement: alice and bob both
// publish calendar.gw.example.net and reach different upstreams.
func TestGatewayRoutesTheSameHostPerUser(t *testing.T) {
	env := newGatewayEnv(t, false)

	aliceUpstream, aliceRecord := newUpstream(t, "alice-calendar")
	bobUpstream, bobRecord := newUpstream(t, "bob-calendar")

	aliceID := env.userID(t, "alice")
	bobID := env.userID(t, "bob")
	env.gate(t, "alice calendar", aliceUpstream.Listener.Addr().String(), "calendar", "", &aliceID)
	env.gate(t, "bob calendar", bobUpstream.Listener.Addr().String(), "calendar", "", &bobID)

	aliceCookie := env.login(t, "alice", alicePassword, "")
	bobCookie := env.login(t, "bob", bobPassword, "")

	aliceRec := requestAt(env.handler, http.MethodGet, "calendar."+gatewayDomainName, "/today", aliceCookie, nil)
	if aliceRec.Code != http.StatusOK {
		t.Fatalf("alice request = %d, body = %s", aliceRec.Code, aliceRec.Body.String())
	}
	if upstream := aliceRec.Header().Get("X-Upstream"); upstream != "alice-calendar" {
		t.Fatalf("alice reached %q, want alice-calendar", upstream)
	}

	bobRec := requestAt(env.handler, http.MethodGet, "calendar."+gatewayDomainName, "/today", bobCookie, nil)
	if bobRec.Code != http.StatusOK {
		t.Fatalf("bob request = %d, body = %s", bobRec.Code, bobRec.Body.String())
	}
	if upstream := bobRec.Header().Get("X-Upstream"); upstream != "bob-calendar" {
		t.Fatalf("bob reached %q, want bob-calendar", upstream)
	}

	// Both upstreams saw the same public path.
	if path, _, _ := aliceRecord.last(); path != "/today?" {
		t.Fatalf("alice upstream path = %q", path)
	}
	if path, _, _ := bobRecord.last(); path != "/today?" {
		t.Fatalf("bob upstream path = %q", path)
	}

	// The upstream host is rewritten, the original one is in X-Forwarded-Host.
	if _, _, host := aliceRecord.last(); !strings.HasPrefix(host, "127.0.0.1:") {
		t.Fatalf("upstream Host = %q, want the upstream address", host)
	}
	aliceRecord.mu.Lock()
	forwarded := aliceRecord.xfHosts[len(aliceRecord.xfHosts)-1]
	aliceRecord.mu.Unlock()
	if forwarded != "calendar."+gatewayDomainName {
		t.Fatalf("X-Forwarded-Host = %q", forwarded)
	}
}

func TestGatewayStripsOwnCookiesAndFiltersSetCookie(t *testing.T) {
	env := newGatewayEnv(t, false)
	upstream, record := newUpstream(t, "svc")
	env.gate(t, "svc", upstream.Listener.Addr().String(), "svc", "", nil)

	cookie := env.login(t, "alice", alicePassword, "")

	rec := requestAt(env.handler, http.MethodGet, "svc."+gatewayDomainName, "/", cookie, map[string]string{
		"Cookie":            cookie.Name + "=" + cookie.Value + "; theme=dark",
		"X-Test-Set-Cookie": "gateway_session=evil; Path=/",
	})
	// The header above replaces the cookie jar value, which is what we want: the
	// upstream must not see any of AuthDock's cookies.
	if rec.Code != http.StatusOK {
		t.Fatalf("request = %d, body = %s", rec.Code, rec.Body.String())
	}

	_, forwardedCookies, _ := record.last()
	if strings.Contains(forwardedCookies, "gateway_session") || strings.Contains(forwardedCookies, "authdock_session") {
		t.Fatalf("upstream received an AuthDock cookie: %q", forwardedCookies)
	}
	if !strings.Contains(forwardedCookies, "theme=dark") {
		t.Fatalf("upstream lost the application cookie: %q", forwardedCookies)
	}

	for _, setCookie := range rec.Result().Header.Values("Set-Cookie") {
		if strings.Contains(setCookie, "gateway_session") {
			t.Fatalf("upstream Set-Cookie for the session was forwarded: %q", setCookie)
		}
	}
}

func TestGatewayKeepsUpstreamCookies(t *testing.T) {
	env := newGatewayEnv(t, false)
	upstream, _ := newUpstream(t, "svc")
	env.gate(t, "svc", upstream.Listener.Addr().String(), "svc", "", nil)
	cookie := env.login(t, "alice", alicePassword, "")

	rec := requestAt(env.handler, http.MethodGet, "svc."+gatewayDomainName, "/", cookie, map[string]string{
		"X-Test-Set-Cookie": "app_session=abc; Path=/; HttpOnly",
	})
	found := false
	for _, setCookie := range rec.Result().Header.Values("Set-Cookie") {
		if strings.HasPrefix(setCookie, "app_session=abc") {
			found = true
		}
	}
	if !found {
		t.Fatalf("the application cookie was dropped: %v", rec.Result().Header.Values("Set-Cookie"))
	}
}

func TestGatewayForbidsAnotherUsersGate(t *testing.T) {
	env := newGatewayEnv(t, false)
	upstream, _ := newUpstream(t, "bob-only")
	bobID := env.userID(t, "bob")
	env.gate(t, "bob only", upstream.Listener.Addr().String(), "private", "", &bobID)

	aliceCookie := env.login(t, "alice", alicePassword, "")
	rec := requestAt(env.handler, http.MethodGet, "private."+gatewayDomainName, "/", aliceCookie, nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("alice on bob's gate = %d, want 403", rec.Code)
	}
}

func TestGatewayGlobalGateIsVisibleToEveryAccount(t *testing.T) {
	env := newGatewayEnv(t, false)
	upstream, _ := newUpstream(t, "public")
	env.gate(t, "public", upstream.Listener.Addr().String(), "public", "", nil)

	aliceCookie := env.login(t, "alice", alicePassword, "")
	rec := requestAt(env.handler, http.MethodGet, "public."+gatewayDomainName, "/", aliceCookie, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("alice on the global gate = %d, body = %s", rec.Code, rec.Body.String())
	}
}

func TestGatewayUnknownSubdomainIs404(t *testing.T) {
	env := newGatewayEnv(t, false)
	cookie := env.login(t, "alice", alicePassword, "")

	rec := requestAt(env.handler, http.MethodGet, "nothing."+gatewayDomainName, "/", cookie, nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown subdomain = %d, want 404", rec.Code)
	}
}

func TestGatewayStripsThePublicPathPrefix(t *testing.T) {
	env := newGatewayEnv(t, false)
	upstream, record := newUpstream(t, "tools")
	env.gate(t, "tools", upstream.Listener.Addr().String(), "app", "tools", nil)

	cookie := env.login(t, "alice", alicePassword, "")
	rec := requestAt(env.handler, http.MethodGet, "app."+gatewayDomainName, "/tools/deep/file?a=b", cookie, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("prefixed request = %d, body = %s", rec.Code, rec.Body.String())
	}
	if path, _, _ := record.last(); path != "/deep/file?a=b" {
		t.Fatalf("upstream path = %q, want /deep/file?a=b", path)
	}

	// A path outside the prefix is not part of the gate.
	miss := requestAt(env.handler, http.MethodGet, "app."+gatewayDomainName, "/other", cookie, nil)
	if miss.Code != http.StatusNotFound {
		t.Fatalf("path outside the prefix = %d, want 404", miss.Code)
	}
}

func TestGatewayRewritesUpstreamRedirects(t *testing.T) {
	env := newGatewayEnv(t, false)
	upstream, _ := newUpstream(t, "svc")
	env.gate(t, "svc", upstream.Listener.Addr().String(), "svc", "", nil)

	cookie := env.login(t, "alice", alicePassword, "")
	rec := requestAt(env.handler, http.MethodGet, "svc."+gatewayDomainName, "/?go=1", cookie, nil)
	if rec.Code != http.StatusFound {
		t.Fatalf("redirect = %d, want 302", rec.Code)
	}
	if location := rec.Header().Get("Location"); location != "http://svc."+gatewayDomainName+"/elsewhere" {
		t.Fatalf("Location = %q, want the public address", location)
	}
}

func TestGatewayReturnToValidation(t *testing.T) {
	env := newGatewayEnv(t, false)

	login := func(returnTo string) string {
		payload, _ := json.Marshal(map[string]string{
			"username": "alice", "password": alicePassword, "return_to": returnTo,
		})
		req := httptest.NewRequest(http.MethodPost, "http://"+gatewayDomainName+"/api/login", bytes.NewReader(payload))
		req.Host = gatewayDomainName
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		env.handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("login = %d, body = %s", rec.Code, rec.Body.String())
		}
		var body portalSessionResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode: %v", err)
		}
		return body.RedirectTo
	}

	if got := login("https://calendar." + gatewayDomainName + "/today"); got != "https://calendar."+gatewayDomainName+"/today" {
		t.Fatalf("valid return_to = %q", got)
	}
	for _, evil := range []string{
		"https://evil.example.org/",
		"https://" + gatewayDomainName + ".evil.org/",
		"//evil.example.org/path",
		"javascript:alert(1)",
	} {
		if got := login(evil); got != "" {
			t.Fatalf("return_to %q was accepted as %q", evil, got)
		}
	}
}

func TestGatewayNoDNCheckRoutesByFirstLabel(t *testing.T) {
	env := newGatewayEnv(t, true)
	upstream, _ := newUpstream(t, "svc")
	// Even with a mismatched host the debug mode resolves gates by first label.
	env.gate(t, "svc", upstream.Listener.Addr().String(), "svc", "", nil)

	cookie := env.login(t, "alice", alicePassword, "")
	rec := requestAt(env.handler, http.MethodGet, "svc.local", "/", cookie, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("debug request = %d, body = %s", rec.Code, rec.Body.String())
	}
}

// TestGatewaySessionSurvivesRestart is why sessions moved into the database.
func TestGatewaySessionSurvivesRestart(t *testing.T) {
	env := newGatewayEnv(t, false)
	upstream, _ := newUpstream(t, "svc")
	env.gate(t, "svc", upstream.Listener.Addr().String(), "svc", "", nil)
	cookie := env.login(t, "alice", alicePassword, "")

	// A second handler with a fresh session cache but the same database.
	options := Options{
		Store:    env.db,
		Sessions: NewDBSessions(env.db, DefaultSessionTTL),
		Now:      env.clock.Now,
		Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	fresh := NewGateway(options)

	rec := requestAt(fresh, http.MethodGet, "svc."+gatewayDomainName, "/", cookie, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("request after \"restart\" = %d, want 200 (the session must survive)", rec.Code)
	}
}

// TestGatewayIgnoresTheAdminSession keeps the two ports apart: signing in as an
// administrator at the management port is not a gateway login.
func TestGatewayIgnoresTheAdminSession(t *testing.T) {
	env := newGatewayEnv(t, false)
	upstream, _ := newUpstream(t, "svc")
	env.gate(t, "svc", upstream.Listener.Addr().String(), "svc", "", nil)

	payload, _ := json.Marshal(map[string]string{"username": "boss", "password": "bosspass12"})
	loginReq := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8080/api/auth/login", bytes.NewReader(payload))
	loginReq.Header.Set("Content-Type", "application/json")
	loginRec := httptest.NewRecorder()
	env.admin.ServeHTTP(loginRec, loginReq)
	if loginRec.Code != http.StatusOK {
		t.Fatalf("admin login = %d, body = %s", loginRec.Code, loginRec.Body.String())
	}

	var adminCookie *http.Cookie
	for _, cookie := range loginRec.Result().Cookies() {
		if cookie.Name == SessionCookieName && cookie.Value != "" {
			adminCookie = cookie
		}
	}
	if adminCookie == nil {
		t.Fatal("admin login produced no management cookie")
	}

	rec := requestAt(env.handler, http.MethodGet, "svc."+gatewayDomainName, "/", adminCookie, nil)
	if rec.Code != http.StatusFound {
		t.Fatalf("gateway with a management cookie = %d, want 302 to the portal", rec.Code)
	}
	if location := rec.Header().Get("Location"); !strings.Contains(location, "/login?return_to=") {
		t.Fatalf("Location = %q, want the portal login", location)
	}
}

// TestGatewayPortalSessionUsesTheGatewayScope covers the bug where the portal
// session endpoint answered with the management scope, so an administrator
// signed in on the management port showed up as signed in at the portal.
func TestGatewayPortalSessionUsesTheGatewayScope(t *testing.T) {
	env := newGatewayEnv(t, false)

	payload, _ := json.Marshal(map[string]string{"username": "boss", "password": "bosspass12"})
	loginReq := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8080/api/auth/login", bytes.NewReader(payload))
	loginReq.Header.Set("Content-Type", "application/json")
	loginRec := httptest.NewRecorder()
	env.admin.ServeHTTP(loginRec, loginReq)
	if loginRec.Code != http.StatusOK {
		t.Fatalf("admin login = %d", loginRec.Code)
	}
	var adminCookie *http.Cookie
	for _, cookie := range loginRec.Result().Cookies() {
		if cookie.Name == SessionCookieName && cookie.Value != "" {
			adminCookie = cookie
		}
	}
	if adminCookie == nil {
		t.Fatal("admin login produced no management cookie")
	}

	// The portal session endpoint must ignore the management cookie entirely.
	rec := requestAt(env.handler, http.MethodGet, gatewayDomainName, "/api/session", adminCookie, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("portal /api/session with a management cookie = %d, want 401", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "boss") {
		t.Fatalf("the portal leaked the administrator session: %s", rec.Body.String())
	}

	// And it does report a real portal session.
	alice := env.login(t, "alice", alicePassword, "")
	rec = requestAt(env.handler, http.MethodGet, gatewayDomainName, "/api/session", alice, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("portal /api/session with a portal cookie = %d, body = %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "alice") {
		t.Fatalf("portal session body = %s", rec.Body.String())
	}
}

// TestGatewayUsesForwardedHostForReturnTo covers a reverse proxy that rewrites
// Host to the upstream address: the redirect must still carry the public URL,
// otherwise the login page rejects return_to and the visitor is stuck.
func TestGatewayUsesForwardedHostForReturnTo(t *testing.T) {
	env := newGatewayEnv(t, false)
	env.gate(t, "public", "127.0.0.1:9", "public", "", nil)

	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8081/week", nil)
	req.Host = "127.0.0.1:8081"
	req.Header.Set("X-Forwarded-Host", "public."+gatewayDomainName)
	req.Header.Set("X-Forwarded-Proto", "https")
	rec := httptest.NewRecorder()
	env.handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	location, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	if location.Host != gatewayDomainName {
		t.Fatalf("login host = %q, want the gateway domain", location.Host)
	}
	returnTo := location.Query().Get("return_to")
	if returnTo != "https://public."+gatewayDomainName+"/week" {
		t.Fatalf("return_to = %q, want the public address, not the upstream one", returnTo)
	}
}

func TestGatewayExplainsAMissingGate(t *testing.T) {
	env := newGatewayEnv(t, false)
	upstream, _ := newUpstream(t, "svc")
	aliceID := env.userID(t, "alice")
	env.gate(t, "alice calendar", upstream.Listener.Addr().String(), "calendar", "", &aliceID)

	cookie := env.login(t, "alice", alicePassword, "")
	rec := requestAt(env.handler, http.MethodGet, "nope."+gatewayDomainName, "/", cookie, nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("missing gate = %d, want 404", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "没有配置网关") {
		t.Fatalf("the 404 page does not explain the problem: %s", body)
	}
	// It lists what this account can reach, which is the actionable part.
	if !strings.Contains(body, "https://calendar."+gatewayDomainName+"/") {
		t.Fatalf("the 404 page does not list the account's addresses: %s", body)
	}
	if !strings.Contains(body, "alice") {
		t.Fatalf("the 404 page does not name the account: %s", body)
	}
}

func TestGatewayExplainsAnotherAccountsGate(t *testing.T) {
	env := newGatewayEnv(t, false)
	upstream, _ := newUpstream(t, "bob-only")
	bobID := env.userID(t, "bob")
	env.gate(t, "bob only", upstream.Listener.Addr().String(), "private", "", &bobID)

	aliceCookie := env.login(t, "alice", alicePassword, "")
	rec := requestAt(env.handler, http.MethodGet, "private."+gatewayDomainName, "/", aliceCookie, nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("another account's gate = %d, want 403", rec.Code)
	}
	if body := rec.Body.String(); !strings.Contains(body, "属于其他账号") {
		t.Fatalf("the 403 page does not explain the problem: %s", body)
	}
}
