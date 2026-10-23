package httpapi

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lyy1119/AuthDock/internal/passwd"
	"github.com/lyy1119/AuthDock/internal/store"
)

const (
	testAdminUsername = "admin"
	testAdminPassword = "AdminPass1"
	testPlainUsername = "alice"
	testPlainPassword = "AlicePass1"
)

type fakeClock struct{ current time.Time }

func (c *fakeClock) Now() time.Time          { return c.current }
func (c *fakeClock) Advance(d time.Duration) { c.current = c.current.Add(d) }

type testEnv struct {
	handler  http.Handler
	db       *store.Store
	clock    *fakeClock
	sessions *SessionStore
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()

	hasher, err := passwd.NewHasher(passwd.Params{
		Memory:      8 * 1024,
		Iterations:  1,
		Parallelism: 1,
		SaltLength:  16,
		KeyLength:   32,
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
	if _, err := db.CreateUser(ctx, testAdminUsername, testAdminPassword, store.RoleAdmin); err != nil {
		t.Fatalf("create admin: %v", err)
	}
	if _, err := db.CreateUser(ctx, testPlainUsername, testPlainPassword, store.RoleUser); err != nil {
		t.Fatalf("create user: %v", err)
	}

	clock := &fakeClock{current: time.Date(2026, time.January, 1, 12, 0, 0, 0, time.UTC)}
	sessions := NewSessionStore(DefaultSessionTTL)
	handler := New(Options{
		Store:    db,
		Now:      clock.Now,
		Sessions: sessions,
		Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	return &testEnv{handler: handler, db: db, clock: clock, sessions: sessions}
}

type loginPayload struct {
	Username string
	Password string
}

func (p loginPayload) marshal(t *testing.T) []byte {
	t.Helper()
	body, err := json.Marshal(map[string]string{"username": p.Username, "password": p.Password})
	if err != nil {
		t.Fatalf("marshal login payload: %v", err)
	}
	return body
}

func doLogin(t *testing.T, env *testEnv, username, password string) *httptest.ResponseRecorder {
	t.Helper()
	body := loginPayload{Username: username, Password: password}.marshal(t)
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.handler.ServeHTTP(rec, req)
	return rec
}

func sessionCookie(t *testing.T, rec *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == SessionCookieName && cookie.Value != "" {
			return cookie
		}
	}
	return nil
}

func doRequest(t *testing.T, env *testEnv, method, path string, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	env.handler.ServeHTTP(rec, req)
	return rec
}

func decodeBody(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response %q: %v", rec.Body.String(), err)
	}
	return body
}

func errorCode(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	code, _ := decodeBody(t, rec)["code"].(string)
	return code
}

func TestLoginSucceedsForAdmin(t *testing.T) {
	env := newTestEnv(t)

	rec := doLogin(t, env, testAdminUsername, testAdminPassword)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}

	body := decodeBody(t, rec)
	if ok, _ := body["ok"].(bool); !ok {
		t.Fatalf("response ok = %v, want true", body["ok"])
	}
	user, _ := body["user"].(map[string]any)
	if user["username"] != testAdminUsername || user["role"] != store.RoleAdmin {
		t.Fatalf("user = %v, want admin account", user)
	}
	if _, leaked := body["password_hash"]; leaked {
		t.Fatal("login response leaks the stored password hash")
	}

	cookie := sessionCookie(t, rec)
	if cookie == nil {
		t.Fatal("login response carries no session cookie")
	}
	if !cookie.HttpOnly {
		t.Error("session cookie is not HttpOnly")
	}
	if cookie.SameSite != http.SameSiteStrictMode {
		t.Errorf("session cookie SameSite = %v, want Strict", cookie.SameSite)
	}
	if cookie.Path != "/" {
		t.Errorf("session cookie Path = %q, want /", cookie.Path)
	}

	session := doRequest(t, env, http.MethodGet, "/api/auth/session", cookie)
	if session.Code != http.StatusOK {
		t.Fatalf("session status = %d, body = %s", session.Code, session.Body.String())
	}
	sessionBody := decodeBody(t, session)
	sessionUser, _ := sessionBody["user"].(map[string]any)
	if sessionUser["username"] != testAdminUsername {
		t.Fatalf("session user = %v", sessionUser)
	}
}

func TestLoginRejectsWrongPassword(t *testing.T) {
	env := newTestEnv(t)

	rec := doLogin(t, env, testAdminUsername, "wrong-password")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body = %s", rec.Code, rec.Body.String())
	}
	if code := errorCode(t, rec); code != "invalid_credentials" {
		t.Fatalf("error code = %q, want invalid_credentials", code)
	}
	if cookie := sessionCookie(t, rec); cookie != nil {
		t.Fatal("failed login still handed out a session cookie")
	}
}

func TestLoginRejectsUnknownUsername(t *testing.T) {
	env := newTestEnv(t)

	rec := doLogin(t, env, "ghost", "whatever-password")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body = %s", rec.Code, rec.Body.String())
	}
	if code := errorCode(t, rec); code != "invalid_credentials" {
		t.Fatalf("error code = %q, want invalid_credentials", code)
	}
}

func TestLoginRejectsNonAdminRole(t *testing.T) {
	env := newTestEnv(t)

	rec := doLogin(t, env, testPlainUsername, testPlainPassword)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body = %s", rec.Code, rec.Body.String())
	}
	if code := errorCode(t, rec); code != "admin_only" {
		t.Fatalf("error code = %q, want admin_only", code)
	}
	if cookie := sessionCookie(t, rec); cookie != nil {
		t.Fatal("non-admin login handed out a session cookie")
	}
}

func TestLoginRejectsMalformedRequests(t *testing.T) {
	env := newTestEnv(t)

	post := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		env.handler.ServeHTTP(rec, req)
		return rec
	}

	cases := map[string]string{
		"invalid json":     `{"username":`,
		"unknown field":    `{"username":"admin","password":"x","role":"admin"}`,
		"empty username":   `{"username":"","password":"x"}`,
		"long username":    `{"username":"` + strings.Repeat("a", passwd.MaxUsernameLen+1) + `","password":"x"}`,
		"empty password":   `{"username":"admin","password":""}`,
		"oversized body":   `{"username":"admin","password":"` + strings.Repeat("a", 8<<10) + `"}`,
		"non-string field": `{"username":123,"password":"x"}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			rec := post(body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400; body = %s", rec.Code, rec.Body.String())
			}
			if code := errorCode(t, rec); code != "invalid_request" {
				t.Fatalf("error code = %q, want invalid_request", code)
			}
		})
	}
}

func TestLoginMethodNotAllowed(t *testing.T) {
	env := newTestEnv(t)

	rec := doRequest(t, env, http.MethodGet, "/api/auth/login", nil)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rec.Code)
	}
}

func TestLoginThrottlesRepeatedFailures(t *testing.T) {
	env := newTestEnv(t)

	for attempt := 1; attempt <= 5; attempt++ {
		rec := doLogin(t, env, testAdminUsername, "wrong-password")
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d status = %d, want 401", attempt, rec.Code)
		}
	}

	rec := doLogin(t, env, testAdminUsername, "wrong-password")
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429; body = %s", rec.Code, rec.Body.String())
	}
	if retryAfter := rec.Header().Get("Retry-After"); retryAfter == "" {
		t.Fatal("429 response is missing Retry-After")
	}

	// Even the correct password is refused while the lock is active.
	locked := doLogin(t, env, testAdminUsername, testAdminPassword)
	if locked.Code != http.StatusTooManyRequests {
		t.Fatalf("status with correct password = %d, want 429", locked.Code)
	}

	// Once the cool-down passes the account may try again.
	env.clock.Advance(2 * time.Minute)
	rec = doLogin(t, env, testAdminUsername, testAdminPassword)
	if rec.Code != http.StatusOK {
		t.Fatalf("status after cool-down = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}
}

func TestSuccessfulLoginResetsThrottle(t *testing.T) {
	env := newTestEnv(t)

	for attempt := 1; attempt <= 4; attempt++ {
		if rec := doLogin(t, env, testAdminUsername, "wrong-password"); rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d status = %d, want 401", attempt, rec.Code)
		}
	}
	if rec := doLogin(t, env, testAdminUsername, testAdminPassword); rec.Code != http.StatusOK {
		t.Fatalf("correct login status = %d, want 200", rec.Code)
	}

	// A fresh budget: the first failure after a success must not be throttled.
	if rec := doLogin(t, env, testAdminUsername, "wrong-password"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("status after successful login = %d, want 401", rec.Code)
	}
}

func TestLogoutDropsSession(t *testing.T) {
	env := newTestEnv(t)

	login := doLogin(t, env, testAdminUsername, testAdminPassword)
	cookie := sessionCookie(t, login)
	if cookie == nil {
		t.Fatal("login produced no session cookie")
	}

	req := httptest.NewRequest(http.MethodPost, "/api/auth/logout", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	env.handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("logout status = %d, want 200", rec.Code)
	}

	session := doRequest(t, env, http.MethodGet, "/api/auth/session", cookie)
	if session.Code != http.StatusUnauthorized {
		t.Fatalf("session status after logout = %d, want 401", session.Code)
	}
}

func TestSessionExpires(t *testing.T) {
	env := newTestEnv(t)

	login := doLogin(t, env, testAdminUsername, testAdminPassword)
	cookie := sessionCookie(t, login)
	if cookie == nil {
		t.Fatal("login produced no session cookie")
	}

	env.clock.Advance(DefaultSessionTTL + time.Minute)
	if rec := doRequest(t, env, http.MethodGet, "/api/auth/session", cookie); rec.Code != http.StatusUnauthorized {
		t.Fatalf("expired session status = %d, want 401", rec.Code)
	}
}

func TestSessionWithoutCookie(t *testing.T) {
	env := newTestEnv(t)

	rec := doRequest(t, env, http.MethodGet, "/api/auth/session", nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if code := errorCode(t, rec); code != "unauthenticated" {
		t.Fatalf("error code = %q, want unauthenticated", code)
	}
}

func TestLoginPageIsServed(t *testing.T) {
	env := newTestEnv(t)

	rec := doRequest(t, env, http.MethodGet, "/login", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if contentType := rec.Header().Get("Content-Type"); !strings.HasPrefix(contentType, "text/html") {
		t.Fatalf("Content-Type = %q, want text/html", contentType)
	}
	body := rec.Body.String()
	for _, want := range []string{"AuthDock", "api/auth/login", "alert("} {
		if !strings.Contains(body, want) {
			t.Errorf("login page does not contain %q", want)
		}
	}
	// The page must not hard-code an absolute API path: behind a path-prefixed
	// reverse proxy (code-server's /proxy/<port>/) it has to stay relative.
	if strings.Contains(body, `'/api/auth/login'`) || strings.Contains(body, `"/api/auth/login"`) {
		t.Error("login page hard-codes an absolute API path, which breaks under a prefixed reverse proxy")
	}
}

func TestLoginPageRedirectsWhenAuthenticated(t *testing.T) {
	env := newTestEnv(t)

	login := doLogin(t, env, testAdminUsername, testAdminPassword)
	cookie := sessionCookie(t, login)
	if cookie == nil {
		t.Fatal("login produced no session cookie")
	}

	rec := doRequest(t, env, http.MethodGet, "/login", cookie)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", rec.Code)
	}
	// Relative on purpose: see TestRedirectsStayRelativeUnderAPathPrefix.
	if location := rec.Header().Get("Location"); location != "admin/" {
		t.Fatalf("Location = %q, want admin/", location)
	}
}

func TestIndexRedirectsAnonymousVisitor(t *testing.T) {
	env := newTestEnv(t)

	rec := doRequest(t, env, http.MethodGet, "/", nil)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", rec.Code)
	}
	// Relative on purpose: see TestRedirectsStayRelativeUnderAPathPrefix.
	if location := rec.Header().Get("Location"); location != "login" {
		t.Fatalf("Location = %q, want login", location)
	}
}

// TestRedirectsStayRelativeUnderAPathPrefix covers the code-server port
// forwarding setup: the browser talks to https://host/proxy/<port>/..., the
// proxy strips that prefix and forwards a plain "/" to the app. An absolute
// Location such as "/login" would resolve against the proxy root and 404; a
// relative reference is resolved by the browser against the prefixed URL.
func TestRedirectsStayRelativeUnderAPathPrefix(t *testing.T) {
	env := newTestEnv(t)

	rec := doRequest(t, env, http.MethodGet, "/", nil)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", rec.Code)
	}
	location := rec.Header().Get("Location")
	if strings.HasPrefix(location, "/") || strings.HasPrefix(location, "http") {
		t.Fatalf("Location = %q, want a relative reference so the proxy prefix survives", location)
	}
	if location != "login" {
		t.Fatalf("Location = %q, want login", location)
	}

	login := doLogin(t, env, testAdminUsername, testAdminPassword)
	cookie := sessionCookie(t, login)
	if cookie == nil {
		t.Fatal("login produced no session cookie")
	}
	rec = doRequest(t, env, http.MethodGet, "/login", cookie)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", rec.Code)
	}
	if location := rec.Header().Get("Location"); location != "admin/" {
		t.Fatalf("Location = %q, want admin/", location)
	}
}

func TestIndexRedirectsAdminToUserManagement(t *testing.T) {
	env := newTestEnv(t)

	login := doLogin(t, env, testAdminUsername, testAdminPassword)
	cookie := sessionCookie(t, login)
	if cookie == nil {
		t.Fatal("login produced no session cookie")
	}

	rec := doRequest(t, env, http.MethodGet, "/", cookie)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", rec.Code)
	}
	if location := rec.Header().Get("Location"); location != "admin/" {
		t.Fatalf("Location = %q, want admin/", location)
	}
}

func TestUnknownAPIPath(t *testing.T) {
	env := newTestEnv(t)

	rec := doRequest(t, env, http.MethodGet, "/api/nope", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
	if code := errorCode(t, rec); code != "not_found" {
		t.Fatalf("error code = %q, want not_found", code)
	}
}

func TestHealthEndpoint(t *testing.T) {
	env := newTestEnv(t)

	rec := doRequest(t, env, http.MethodGet, "/healthz", nil)
	if rec.Code != http.StatusOK || rec.Body.String() != "ok\n" {
		t.Fatalf("health = %d %q", rec.Code, rec.Body.String())
	}
}

func TestSecurityHeaders(t *testing.T) {
	env := newTestEnv(t)

	rec := doRequest(t, env, http.MethodGet, "/login", nil)
	headers := []string{"X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy", "Content-Security-Policy"}
	for _, header := range headers {
		if rec.Header().Get(header) == "" {
			t.Errorf("response is missing %s", header)
		}
	}
}

func TestSessionCookieIsSecureOverTLS(t *testing.T) {
	env := newTestEnv(t)

	body := loginPayload{Username: testAdminUsername, Password: testAdminPassword}.marshal(t)
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.TLS = &tls.ConnectionState{}
	rec := httptest.NewRecorder()
	env.handler.ServeHTTP(rec, req)

	cookie := sessionCookie(t, rec)
	if cookie == nil {
		t.Fatal("login produced no session cookie")
	}
	if !cookie.Secure {
		t.Fatal("session cookie is not marked Secure on a TLS request")
	}
}

// TestLoginPageFollowsTheThemeSetting keeps the standalone page in sync with the
// colour scheme chosen in the system settings.
func TestLoginPageFollowsTheThemeSetting(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()

	if rec := doRequest(t, env, http.MethodGet, "/login", nil); !strings.Contains(rec.Body.String(), `data-theme="light"`) {
		t.Fatalf("default theme was not applied: %s", rec.Body.String())
	}

	if err := env.db.SetSetting(ctx, store.SettingsKeyTheme, store.ThemeDark); err != nil {
		t.Fatalf("SetSetting: %v", err)
	}
	rec := doRequest(t, env, http.MethodGet, "/login", nil)
	if !strings.Contains(rec.Body.String(), `data-theme="dark"`) {
		t.Fatalf("dark theme was not applied: %s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "data-theme='dark'") {
		t.Fatalf("the page carries no dark palette: %s", rec.Body.String())
	}
}
