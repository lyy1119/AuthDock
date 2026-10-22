package httpapi

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/lyy1119/AuthDock/internal/store"
)

// adminCookie logs in as the seeded admin and returns its session cookie.
func adminCookie(t *testing.T, env *testEnv) *http.Cookie {
	t.Helper()
	rec := doLogin(t, env, testAdminUsername, testAdminPassword)
	cookie := sessionCookie(t, rec)
	if cookie == nil {
		t.Fatalf("admin login failed: status=%d body=%s", rec.Code, rec.Body.String())
	}
	return cookie
}

// doJSON performs a request with an optional JSON body.
func doJSON(t *testing.T, env *testEnv, method, path string, cookie *http.Cookie, body any) *httptest.ResponseRecorder {
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
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	env.handler.ServeHTTP(rec, req)
	return rec
}

func jsonUsers(t *testing.T, rec *httptest.ResponseRecorder) []adminUser {
	t.Helper()
	var body adminUserListResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode users: %v (%s)", err, rec.Body.String())
	}
	return body.Users
}

func userIDByName(t *testing.T, users []adminUser, name string) int64 {
	t.Helper()
	for _, user := range users {
		if user.Username == name {
			return user.ID
		}
	}
	t.Fatalf("user %q not found in %+v", name, users)
	return 0
}

func TestAdminAPIRequiresSession(t *testing.T) {
	env := newTestEnv(t)

	for _, path := range []string{"/api/admin/users", "/api/admin/settings", "/api/admin/gates"} {
		rec := doJSON(t, env, http.MethodGet, path, nil, nil)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("GET %s without a session = %d, want 401", path, rec.Code)
		}
		if code := errorCode(t, rec); code != "unauthenticated" {
			t.Fatalf("GET %s error code = %q, want unauthenticated", path, code)
		}
	}
}

func TestAdminAPIRequiresAdminRole(t *testing.T) {
	env := newTestEnv(t)

	token, _, err := env.sessions.Create(testPlainUsername, store.RoleUser, env.clock.Now())
	if err != nil {
		t.Fatalf("create user session: %v", err)
	}
	cookie := &http.Cookie{Name: SessionCookieName, Value: token}

	for _, path := range []string{"/api/admin/users", "/api/admin/settings", "/api/admin/gates"} {
		rec := doJSON(t, env, http.MethodGet, path, cookie, nil)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("GET %s as a normal user = %d, want 403", path, rec.Code)
		}
		if code := errorCode(t, rec); code != "admin_only" {
			t.Fatalf("GET %s error code = %q, want admin_only", path, code)
		}
	}
}

func TestAdminListUsers(t *testing.T) {
	env := newTestEnv(t)
	cookie := adminCookie(t, env)

	rec := doJSON(t, env, http.MethodGet, "/api/admin/users", cookie, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "$argon2id") {
		t.Fatal("the users response leaks password hashes")
	}

	users := jsonUsers(t, rec)
	if len(users) != 2 {
		t.Fatalf("got %d users, want 2", len(users))
	}
	for _, user := range users {
		switch user.Username {
		case testAdminUsername:
			if !user.Self || user.Role != store.RoleAdmin {
				t.Fatalf("admin entry = %+v, want self admin", user)
			}
		case testPlainUsername:
			if user.Self || user.Role != store.RoleUser {
				t.Fatalf("alice entry = %+v, want non-self user", user)
			}
		}
	}
}

func TestAdminCreateUser(t *testing.T) {
	env := newTestEnv(t)
	cookie := adminCookie(t, env)

	rec := doJSON(t, env, http.MethodPost, "/api/admin/users", cookie, map[string]string{
		"username": "bob",
		"password": "bobpassword1",
		"role":     "user",
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}

	// The new account exists and cannot sign in to the admin area.
	login := doLogin(t, env, "bob", "bobpassword1")
	if login.Code != http.StatusForbidden {
		t.Fatalf("login as the new user role account = %d, want 403", login.Code)
	}

	duplicate := doJSON(t, env, http.MethodPost, "/api/admin/users", cookie, map[string]string{
		"username": "bob",
		"password": "bobpassword1",
		"role":     "user",
	})
	if duplicate.Code != http.StatusConflict || errorCode(t, duplicate) != "username_taken" {
		t.Fatalf("duplicate username = %d %q, want 409 username_taken", duplicate.Code, errorCode(t, duplicate))
	}

	short := doJSON(t, env, http.MethodPost, "/api/admin/users", cookie, map[string]string{
		"username": "carol",
		"password": "short",
		"role":     "user",
	})
	if short.Code != http.StatusBadRequest {
		t.Fatalf("short password = %d, want 400", short.Code)
	}

	badName := doJSON(t, env, http.MethodPost, "/api/admin/users", cookie, map[string]string{
		"username": strings.Repeat("x", 21),
		"password": "longenough1",
		"role":     "user",
	})
	if badName.Code != http.StatusBadRequest {
		t.Fatalf("21 character username = %d, want 400", badName.Code)
	}

	badRole := doJSON(t, env, http.MethodPost, "/api/admin/users", cookie, map[string]string{
		"username": "dave",
		"password": "longenough1",
		"role":     "root",
	})
	if badRole.Code != http.StatusBadRequest {
		t.Fatalf("invalid role = %d, want 400", badRole.Code)
	}
}

func TestAdminUpdateUser(t *testing.T) {
	env := newTestEnv(t)
	cookie := adminCookie(t, env)

	users := jsonUsers(t, doJSON(t, env, http.MethodGet, "/api/admin/users", cookie, nil))
	aliceID := userIDByName(t, users, testPlainUsername)

	// Promote alice and give her a new password in one request.
	rec := doJSON(t, env, http.MethodPatch, "/api/admin/users/"+itoa(aliceID), cookie, map[string]string{
		"role":     "admin",
		"password": "alicepassword2",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}

	// She can now sign in with the new password and holds the admin role.
	login := doLogin(t, env, testPlainUsername, "alicepassword2")
	if login.Code != http.StatusOK {
		t.Fatalf("login with the new password = %d, body = %s", login.Code, login.Body.String())
	}
	body := decodeBody(t, login)
	user, _ := body["user"].(map[string]any)
	if user["role"] != store.RoleAdmin {
		t.Fatalf("role = %v, want admin", user["role"])
	}

	// The old password no longer works.
	if old := doLogin(t, env, testPlainUsername, testPlainPassword); old.Code != http.StatusUnauthorized {
		t.Fatalf("login with the old password = %d, want 401", old.Code)
	}

	unknown := doJSON(t, env, http.MethodPatch, "/api/admin/users/9999", cookie, map[string]string{"role": "admin"})
	if unknown.Code != http.StatusNotFound {
		t.Fatalf("patch of an unknown user = %d, want 404", unknown.Code)
	}
}

func TestAdminCannotDemoteLastAdmin(t *testing.T) {
	env := newTestEnv(t)
	cookie := adminCookie(t, env)

	users := jsonUsers(t, doJSON(t, env, http.MethodGet, "/api/admin/users", cookie, nil))
	adminID := userIDByName(t, users, testAdminUsername)

	rec := doJSON(t, env, http.MethodPatch, "/api/admin/users/"+itoa(adminID), cookie, map[string]string{"role": "user"})
	if rec.Code != http.StatusConflict || errorCode(t, rec) != "last_admin" {
		t.Fatalf("demoting the last admin = %d %q, want 409 last_admin", rec.Code, errorCode(t, rec))
	}

	// With a second admin the demotion is allowed, and it ends the own session.
	aliceID := userIDByName(t, users, testPlainUsername)
	if rec := doJSON(t, env, http.MethodPatch, "/api/admin/users/"+itoa(aliceID), cookie, map[string]string{"role": "admin"}); rec.Code != http.StatusOK {
		t.Fatalf("promote alice = %d, body = %s", rec.Code, rec.Body.String())
	}

	rec = doJSON(t, env, http.MethodPatch, "/api/admin/users/"+itoa(adminID), cookie, map[string]string{"role": "user"})
	if rec.Code != http.StatusOK {
		t.Fatalf("demote self = %d, body = %s", rec.Code, rec.Body.String())
	}
	var body adminUserResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !body.LoggedOut {
		t.Fatal("demoting the signed-in account did not report logged_out")
	}

	// The session is gone.
	if session := doRequest(t, env, http.MethodGet, "/api/auth/session", cookie); session.Code != http.StatusUnauthorized {
		t.Fatalf("session after self demotion = %d, want 401", session.Code)
	}
}

func TestAdminDeleteUser(t *testing.T) {
	env := newTestEnv(t)
	cookie := adminCookie(t, env)

	users := jsonUsers(t, doJSON(t, env, http.MethodGet, "/api/admin/users", cookie, nil))
	adminID := userIDByName(t, users, testAdminUsername)
	aliceID := userIDByName(t, users, testPlainUsername)

	self := doJSON(t, env, http.MethodDelete, "/api/admin/users/"+itoa(adminID), cookie, nil)
	if self.Code != http.StatusConflict || errorCode(t, self) != "self_delete" {
		t.Fatalf("deleting yourself = %d %q, want 409 self_delete", self.Code, errorCode(t, self))
	}

	unknown := doJSON(t, env, http.MethodDelete, "/api/admin/users/9999", cookie, nil)
	if unknown.Code != http.StatusNotFound {
		t.Fatalf("deleting an unknown user = %d, want 404", unknown.Code)
	}

	rec := doJSON(t, env, http.MethodDelete, "/api/admin/users/"+itoa(aliceID), cookie, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("delete alice = %d, body = %s", rec.Code, rec.Body.String())
	}
	remaining := jsonUsers(t, doJSON(t, env, http.MethodGet, "/api/admin/users", cookie, nil))
	if len(remaining) != 1 || remaining[0].Username != testAdminUsername {
		t.Fatalf("users after delete = %+v", remaining)
	}
}

func TestAdminSettings(t *testing.T) {
	env := newTestEnv(t)
	cookie := adminCookie(t, env)

	rec := doJSON(t, env, http.MethodGet, "/api/admin/settings", cookie, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var body adminSettingsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode settings: %v", err)
	}
	if body.Settings.GatewayDomain != "" {
		t.Fatalf("gateway domain = %q, want empty", body.Settings.GatewayDomain)
	}

	put := doJSON(t, env, http.MethodPut, "/api/admin/settings", cookie, map[string]string{"gateway_domain": "gw.example.net"})
	if put.Code != http.StatusOK {
		t.Fatalf("put status = %d, body = %s", put.Code, put.Body.String())
	}
	after := doJSON(t, env, http.MethodGet, "/api/admin/settings", cookie, nil)
	if !strings.Contains(after.Body.String(), "gw.example.net") {
		t.Fatalf("gateway domain not stored: %s", after.Body.String())
	}

	for _, invalid := range []string{"https://gw.example.net", "gw.example.net/path", "gw.example.net:8080"} {
		rec := doJSON(t, env, http.MethodPut, "/api/admin/settings", cookie, map[string]string{"gateway_domain": invalid})
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("gateway domain %q = %d, want 400", invalid, rec.Code)
		}
	}
}

func TestAdminGates(t *testing.T) {
	env := newTestEnv(t)
	cookie := adminCookie(t, env)

	rec := doJSON(t, env, http.MethodGet, "/api/admin/gates", cookie, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("gates status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var list adminGateListResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatalf("decode gates: %v", err)
	}
	if len(list.Gates) != 0 {
		t.Fatalf("expected no gates, got %+v", list.Gates)
	}

	created := doJSON(t, env, http.MethodPost, "/api/admin/gates", cookie, map[string]string{
		"name":      "日历",
		"from":      "10.0.0.1:1234",
		"to_prefix": "Calendar",
		"to_suffix": "/app/",
	})
	if created.Code != http.StatusCreated {
		t.Fatalf("create gate = %d, body = %s", created.Code, created.Body.String())
	}
	var createdGate adminGateResponse
	if err := json.Unmarshal(created.Body.Bytes(), &createdGate); err != nil {
		t.Fatalf("decode gate: %v", err)
	}
	if createdGate.Gate.ID == 0 || createdGate.Gate.ToPrefix != "calendar" || createdGate.Gate.ToSuffix != "app/" {
		t.Fatalf("gate was not normalized: %+v", createdGate.Gate)
	}

	duplicate := doJSON(t, env, http.MethodPost, "/api/admin/gates", cookie, map[string]string{
		"name":      "重复",
		"from":      "10.0.0.2:1234",
		"to_prefix": "calendar",
		"to_suffix": "app/",
	})
	if duplicate.Code != http.StatusConflict || errorCode(t, duplicate) != "gate_exists" {
		t.Fatalf("duplicate route = %d %q, want 409 gate_exists", duplicate.Code, errorCode(t, duplicate))
	}

	patched := doJSON(t, env, http.MethodPatch, "/api/admin/gates/"+itoa(createdGate.Gate.ID), cookie, map[string]string{
		"name":      "新日历",
		"from":      "http://10.0.0.2:8080",
		"to_prefix": "cal",
		"to_suffix": "",
	})
	if patched.Code != http.StatusOK {
		t.Fatalf("patch gate = %d, body = %s", patched.Code, patched.Body.String())
	}

	for name, body := range map[string]map[string]string{
		"empty name":      {"name": "", "from": "10.0.0.1:1", "to_prefix": "calendar", "to_suffix": ""},
		"bad upstream":    {"name": "x", "from": "ftp://host", "to_prefix": "calendar", "to_suffix": ""},
		"bad prefix":      {"name": "x", "from": "10.0.0.1:1", "to_prefix": "with.dot", "to_suffix": ""},
		"space in suffix": {"name": "x", "from": "10.0.0.1:1", "to_prefix": "calendar", "to_suffix": "a b"},
	} {
		rec := doJSON(t, env, http.MethodPost, "/api/admin/gates", cookie, body)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%s = %d, want 400", name, rec.Code)
		}
	}

	if rec := doJSON(t, env, http.MethodPatch, "/api/admin/gates/9999", cookie, map[string]string{
		"name": "x", "from": "10.0.0.1:1", "to_prefix": "calendar", "to_suffix": "",
	}); rec.Code != http.StatusNotFound {
		t.Fatalf("patch unknown gate = %d, want 404", rec.Code)
	}

	deleted := doJSON(t, env, http.MethodDelete, "/api/admin/gates/"+itoa(createdGate.Gate.ID), cookie, nil)
	if deleted.Code != http.StatusOK {
		t.Fatalf("delete gate = %d, body = %s", deleted.Code, deleted.Body.String())
	}
	if again := doJSON(t, env, http.MethodDelete, "/api/admin/gates/"+itoa(createdGate.Gate.ID), cookie, nil); again.Code != http.StatusNotFound {
		t.Fatalf("second delete = %d, want 404", again.Code)
	}
}

// assetPath pulls the built script URL out of the embedded index.html.
func assetPath(t *testing.T, html string) string {
	t.Helper()
	marker := `src="./`
	index := strings.Index(html, marker)
	if index < 0 {
		t.Fatalf("index.html has no relative script tag: %s", html)
	}
	rest := html[index+len(marker):]
	end := strings.Index(rest, `"`)
	if end < 0 {
		t.Fatalf("unterminated script tag in index.html: %s", html)
	}
	return rest[:end]
}

func TestAdminPages(t *testing.T) {
	env := newTestEnv(t)
	cookie := adminCookie(t, env)

	// The app shell is served for the SPA entry point and for any client route.
	for _, path := range []string{"/admin/", "/admin/users", "/admin/gates", "/admin/settings"} {
		rec := doRequest(t, env, http.MethodGet, path, cookie)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s = %d, want 200", path, rec.Code)
		}
		if contentType := rec.Header().Get("Content-Type"); !strings.HasPrefix(contentType, "text/html") {
			t.Fatalf("GET %s content type = %q", path, contentType)
		}
		body := rec.Body.String()
		if !strings.Contains(body, `id="root"`) {
			t.Fatalf("GET %s does not look like the app shell", path)
		}
		if strings.Contains(body, `href="/`) || strings.Contains(body, `src="/`) {
			t.Fatalf("GET %s hard-codes an absolute asset URL", path)
		}
	}

	// The built asset is served with an immutable cache header.
	shell := doRequest(t, env, http.MethodGet, "/admin/", cookie).Body.String()
	asset := doRequest(t, env, http.MethodGet, "/admin/"+assetPath(t, shell), nil)
	if asset.Code != http.StatusOK {
		t.Fatalf("built asset = %d, want 200", asset.Code)
	}
	if cache := asset.Header().Get("Cache-Control"); !strings.Contains(cache, "immutable") {
		t.Fatalf("built asset Cache-Control = %q, want immutable", cache)
	}

	// Anonymous visitors are redirected to the login page, relatively.
	anon := doRequest(t, env, http.MethodGet, "/admin/users", nil)
	if anon.Code != http.StatusSeeOther || anon.Header().Get("Location") != "../login" {
		t.Fatalf("anonymous /admin/users = %d %q, want 303 ../login",
			anon.Code, anon.Header().Get("Location"))
	}

	// The bare /admin path sends admins into the app shell.
	root := doRequest(t, env, http.MethodGet, "/admin", cookie)
	if root.Code != http.StatusSeeOther || root.Header().Get("Location") != "admin/" {
		t.Fatalf("/admin = %d %q, want 303 admin/", root.Code, root.Header().Get("Location"))
	}

	// A missing file with an extension is a real 404, not the app shell.
	if rec := doRequest(t, env, http.MethodGet, "/admin/assets/missing.js", cookie); rec.Code != http.StatusNotFound {
		t.Fatalf("missing asset = %d, want 404", rec.Code)
	}
}

func itoa(value int64) string {
	return strconv.FormatInt(value, 10)
}
