package httpapi

import (
	"bytes"
	"context"
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

const portalDomain = "gw.example.net"

type portalEnv struct {
	handler http.Handler
	admin   http.Handler
	db      *store.Store
	clock   *fakeClock
}

// newPortalEnv builds a portal handler over a temporary database with the
// gateway domain configured unless withDomain is false.
func newPortalEnv(t *testing.T, withDomain bool, noDNCheck bool) *portalEnv {
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
	if withDomain {
		if err := db.SetSetting(ctx, store.SettingsKeyGatewayDomain, portalDomain); err != nil {
			t.Fatalf("SetSetting: %v", err)
		}
	}
	if _, err := db.CreateUser(ctx, "alice", "alicepass1", store.RoleUser); err != nil {
		t.Fatalf("create alice: %v", err)
	}
	if _, err := db.CreateUser(ctx, "boss", "bosspass12", store.RoleAdmin); err != nil {
		t.Fatalf("create boss: %v", err)
	}

	clock := &fakeClock{current: time.Date(2026, time.January, 1, 12, 0, 0, 0, time.UTC)}
	// Both handlers share one session store, exactly like the two listeners do.
	options := Options{
		Store:     db,
		Sessions:  NewSessionStore(DefaultSessionTTL),
		Now:       clock.Now,
		Logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		NoDNCheck: noDNCheck,
	}
	return &portalEnv{handler: NewPortal(options), admin: New(options), db: db, clock: clock}
}

// portalRequest performs a request with an explicit Host header.
func portalRequest(t *testing.T, env *portalEnv, method, path, host string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var reader io.Reader
	if body != nil {
		payload, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		reader = bytes.NewReader(payload)
	}
	req := httptest.NewRequest(method, path, reader)
	if host != "" {
		req.Host = host
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	env.handler.ServeHTTP(rec, req)
	return rec
}

func TestPortalRefusesMismatchedHost(t *testing.T) {
	env := newPortalEnv(t, true, false)

	for _, host := range []string{"evil.example.org", "10.0.0.5:8081", portalDomain + ".evil.org"} {
		rec := portalRequest(t, env, http.MethodGet, "/", host, nil)
		if rec.Code != http.StatusMisdirectedRequest {
			t.Fatalf("GET / with Host %q = %d, want 421 (refused)", host, rec.Code)
		}
		if strings.Contains(rec.Body.String(), "使用你的账号登录") {
			t.Fatalf("the login page was served for Host %q", host)
		}
	}

	// The login endpoint is refused as well.
	rec := portalRequest(t, env, http.MethodPost, "/api/login", "evil.example.org", map[string]string{
		"username": "alice", "password": "alicepass1",
	})
	if rec.Code != http.StatusMisdirectedRequest {
		t.Fatalf("POST /api/login from a wrong host = %d, want 421", rec.Code)
	}
}

func TestPortalServesPageForGatewayDomain(t *testing.T) {
	env := newPortalEnv(t, true, false)

	for _, path := range []string{"/", "/login"} {
		rec := portalRequest(t, env, http.MethodGet, path, portalDomain, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s = %d, want 200", path, rec.Code)
		}
		if contentType := rec.Header().Get("Content-Type"); !strings.HasPrefix(contentType, "text/html") {
			t.Fatalf("GET %s content type = %q", path, contentType)
		}
		if !strings.Contains(rec.Body.String(), "使用你的账号登录") {
			t.Fatalf("GET %s did not serve the portal page", path)
		}
	}

	// The host may carry a port and upper case letters.
	for _, host := range []string{portalDomain + ":8081", strings.ToUpper(portalDomain)} {
		if rec := portalRequest(t, env, http.MethodGet, "/", host, nil); rec.Code != http.StatusOK {
			t.Fatalf("GET / with Host %q = %d, want 200", host, rec.Code)
		}
	}
}

func TestPortalUsesForwardedHost(t *testing.T) {
	env := newPortalEnv(t, true, false)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "127.0.0.1:8081"
	req.Header.Set("X-Forwarded-Host", portalDomain)
	rec := httptest.NewRecorder()
	env.handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET / with X-Forwarded-Host = %d, want 200", rec.Code)
	}
}

func TestPortalRefusesWhenDomainIsUnset(t *testing.T) {
	env := newPortalEnv(t, false, false)

	rec := portalRequest(t, env, http.MethodGet, "/", portalDomain, nil)
	if rec.Code != http.StatusMisdirectedRequest {
		t.Fatalf("GET / without a configured domain = %d, want 421", rec.Code)
	}
}

func TestPortalNoDNCheckBypassesTheDomainGuard(t *testing.T) {
	env := newPortalEnv(t, false, true)

	rec := portalRequest(t, env, http.MethodGet, "/", "127.0.0.1:8081", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET / with -no-dn-check = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "使用你的账号登录") {
		t.Fatal("the portal page was not served with -no-dn-check")
	}
}

func TestPortalLoginAcceptsNormalUser(t *testing.T) {
	env := newPortalEnv(t, true, false)

	rec := portalRequest(t, env, http.MethodPost, "/api/login", portalDomain, map[string]string{
		"username": "alice", "password": "alicepass1",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("portal login = %d, body = %s", rec.Code, rec.Body.String())
	}
	body := decodeBody(t, rec)
	user, _ := body["user"].(map[string]any)
	if user["username"] != "alice" || user["role"] != store.RoleUser {
		t.Fatalf("user = %v", user)
	}
	cookie := sessionCookie(t, rec)
	if cookie == nil {
		t.Fatal("portal login produced no session cookie")
	}

	// The session is valid at the portal but carries no admin rights.
	sessionReq := httptest.NewRequest(http.MethodGet, "/api/session", nil)
	sessionReq.Host = portalDomain
	sessionReq.AddCookie(cookie)
	sessionRec := httptest.NewRecorder()
	env.handler.ServeHTTP(sessionRec, sessionReq)
	if sessionRec.Code != http.StatusOK {
		t.Fatalf("portal session = %d, body = %s", sessionRec.Code, sessionRec.Body.String())
	}

	adminReq := httptest.NewRequest(http.MethodGet, "/api/admin/users", nil)
	adminReq.AddCookie(cookie)
	adminRec := httptest.NewRecorder()
	env.admin.ServeHTTP(adminRec, adminReq)
	if adminRec.Code != http.StatusForbidden {
		t.Fatalf("admin API with a user session = %d, want 403", adminRec.Code)
	}
}

func TestPortalLoginRejectsBadCredentials(t *testing.T) {
	env := newPortalEnv(t, true, false)

	for name, payload := range map[string]map[string]string{
		"wrong password": {"username": "alice", "password": "nope-nope"},
		"unknown user":   {"username": "ghost", "password": "whatever1"},
		"empty password": {"username": "alice", "password": ""},
	} {
		rec := portalRequest(t, env, http.MethodPost, "/api/login", portalDomain, payload)
		want := http.StatusUnauthorized
		if payload["password"] == "" {
			want = http.StatusBadRequest
		}
		if rec.Code != want {
			t.Fatalf("%s = %d, want %d", name, rec.Code, want)
		}
		if cookie := sessionCookie(t, rec); cookie != nil {
			t.Fatalf("%s handed out a session cookie", name)
		}
	}
}

func TestPortalLogout(t *testing.T) {
	env := newPortalEnv(t, true, false)

	login := portalRequest(t, env, http.MethodPost, "/api/login", portalDomain, map[string]string{
		"username": "boss", "password": "bosspass12",
	})
	cookie := sessionCookie(t, login)
	if cookie == nil {
		t.Fatal("login produced no session cookie")
	}

	req := httptest.NewRequest(http.MethodPost, "/api/logout", nil)
	req.Host = portalDomain
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	env.handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("logout = %d, want 200", rec.Code)
	}
}

func TestPortalPageRejectsOtherMethods(t *testing.T) {
	env := newPortalEnv(t, true, false)

	rec := portalRequest(t, env, http.MethodPost, "/", portalDomain, nil)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST / = %d, want 405", rec.Code)
	}
}

// TestPortalDropsTheConnectionForAWrongHost exercises the real refusal path: a
// hijackable connection is closed without a response, so the client sees an EOF
// rather than any page.
func TestPortalDropsTheConnectionForAWrongHost(t *testing.T) {
	env := newPortalEnv(t, true, false)
	server := httptest.NewServer(env.handler)
	defer server.Close()

	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Host = "evil.example.org"

	response, err := server.Client().Do(req)
	if err == nil {
		response.Body.Close()
		t.Fatalf("wrong Host returned %d, want a dropped connection", response.StatusCode)
	}
	if !strings.Contains(err.Error(), "EOF") && !strings.Contains(err.Error(), "reset") {
		t.Fatalf("unexpected error: %v", err)
	}

	// The correct Host still works on the same server.
	okReq, err := http.NewRequest(http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	okReq.Host = portalDomain
	okResponse, err := server.Client().Do(okReq)
	if err != nil {
		t.Fatalf("correct Host failed: %v", err)
	}
	defer okResponse.Body.Close()
	if okResponse.StatusCode != http.StatusOK {
		t.Fatalf("correct Host = %d, want 200", okResponse.StatusCode)
	}
}
