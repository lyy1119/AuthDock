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

	for _, path := range []string{"/api/admin/users", "/api/admin/settings", "/api/admin/gateway"} {
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

	for _, path := range []string{"/api/admin/users", "/api/admin/settings", "/api/admin/gateway"} {
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

func TestAdminGatewayRules(t *testing.T) {
	env := newTestEnv(t)
	cookie := adminCookie(t, env)

	data := doJSON(t, env, http.MethodGet, "/api/admin/gateway", cookie, nil)
	if data.Code != http.StatusOK {
		t.Fatalf("gateway status = %d, body = %s", data.Code, data.Body.String())
	}
	var gateway adminGatewayResponse
	if err := json.Unmarshal(data.Body.Bytes(), &gateway); err != nil {
		t.Fatalf("decode gateway: %v", err)
	}
	if len(gateway.Users) != 2 {
		t.Fatalf("gateway users = %d, want 2", len(gateway.Users))
	}
	for _, user := range gateway.Users {
		if len(user.Rules) != 0 {
			t.Fatalf("expected no rules, got %+v", user.Rules)
		}
	}

	adminID := gateway.Users[0].ID
	created := doJSON(t, env, http.MethodPost, "/api/admin/gateway/rules", cookie, map[string]any{
		"user_id":   adminID,
		"subdomain": "calendar",
		"path":      "*",
		"upstream":  "http://10.0.0.1:10123/",
	})
	if created.Code != http.StatusCreated {
		t.Fatalf("create rule = %d, body = %s", created.Code, created.Body.String())
	}
	var ruleBody adminRuleResponse
	if err := json.Unmarshal(created.Body.Bytes(), &ruleBody); err != nil {
		t.Fatalf("decode rule: %v", err)
	}
	if ruleBody.Rule.ID == 0 || ruleBody.Rule.Username != testAdminUsername {
		t.Fatalf("unexpected rule %+v", ruleBody.Rule)
	}

	patched := doJSON(t, env, http.MethodPatch, "/api/admin/gateway/rules/"+itoa(ruleBody.Rule.ID), cookie, map[string]string{
		"subdomain": "*",
		"path":      "/api",
		"upstream":  "http://127.0.0.1:9000/",
	})
	if patched.Code != http.StatusOK {
		t.Fatalf("patch rule = %d, body = %s", patched.Code, patched.Body.String())
	}

	invalid := doJSON(t, env, http.MethodPost, "/api/admin/gateway/rules", cookie, map[string]any{
		"user_id":   adminID,
		"subdomain": "calendar",
		"path":      "*",
		"upstream":  "ftp://127.0.0.1/",
	})
	if invalid.Code != http.StatusBadRequest {
		t.Fatalf("invalid upstream = %d, want 400", invalid.Code)
	}

	unknownUser := doJSON(t, env, http.MethodPost, "/api/admin/gateway/rules", cookie, map[string]any{
		"user_id":   9999,
		"subdomain": "calendar",
		"path":      "*",
		"upstream":  "http://127.0.0.1:9000/",
	})
	if unknownUser.Code != http.StatusNotFound {
		t.Fatalf("rule for an unknown user = %d, want 404", unknownUser.Code)
	}

	deleted := doJSON(t, env, http.MethodDelete, "/api/admin/gateway/rules/"+itoa(ruleBody.Rule.ID), cookie, nil)
	if deleted.Code != http.StatusOK {
		t.Fatalf("delete rule = %d, body = %s", deleted.Code, deleted.Body.String())
	}
	if again := doJSON(t, env, http.MethodDelete, "/api/admin/gateway/rules/"+itoa(ruleBody.Rule.ID), cookie, nil); again.Code != http.StatusNotFound {
		t.Fatalf("second delete = %d, want 404", again.Code)
	}
}

func TestAdminPages(t *testing.T) {
	env := newTestEnv(t)
	cookie := adminCookie(t, env)

	pages := map[string]string{
		"/admin/users":    "用户管理",
		"/admin/gateway":  "网关设置",
		"/admin/settings": "系统设置",
	}
	for path, marker := range pages {
		rec := doRequest(t, env, http.MethodGet, path, cookie)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s = %d, want 200", path, rec.Code)
		}
		if contentType := rec.Header().Get("Content-Type"); !strings.HasPrefix(contentType, "text/html") {
			t.Fatalf("GET %s content type = %q", path, contentType)
		}
		body := rec.Body.String()
		if !strings.Contains(body, marker) {
			t.Fatalf("GET %s does not contain %q", path, marker)
		}
		// Assets and links must stay relative so the pages survive a prefixing
		// reverse proxy.
		if strings.Contains(body, `href="/`) || strings.Contains(body, `src="/`) {
			t.Fatalf("GET %s hard-codes an absolute URL", path)
		}
	}

	// Anonymous visitors are redirected to the login page, relatively.
	anon := doRequest(t, env, http.MethodGet, "/admin/users", nil)
	if anon.Code != http.StatusSeeOther || anon.Header().Get("Location") != "../login" {
		t.Fatalf("anonymous /admin/users = %d %q, want 303 ../login",
			anon.Code, anon.Header().Get("Location"))
	}

	// The bare /admin path sends admins to the user page.
	root := doRequest(t, env, http.MethodGet, "/admin", cookie)
	if root.Code != http.StatusSeeOther || root.Header().Get("Location") != "admin/users" {
		t.Fatalf("/admin = %d %q, want 303 admin/users", root.Code, root.Header().Get("Location"))
	}

	// Unknown admin paths are 404.
	if rec := doRequest(t, env, http.MethodGet, "/admin/nope", cookie); rec.Code != http.StatusNotFound {
		t.Fatalf("/admin/nope = %d, want 404", rec.Code)
	}
}

func TestAdminAssets(t *testing.T) {
	env := newTestEnv(t)

	rec := doRequest(t, env, http.MethodGet, "/admin/assets/admin.css", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("admin.css = %d, want 200", rec.Code)
	}
	if contentType := rec.Header().Get("Content-Type"); !strings.HasPrefix(contentType, "text/css") {
		t.Fatalf("admin.css content type = %q", contentType)
	}

	js := doRequest(t, env, http.MethodGet, "/admin/assets/users.js", nil)
	if js.Code != http.StatusOK || !strings.HasPrefix(js.Header().Get("Content-Type"), "text/javascript") {
		t.Fatalf("users.js = %d %q", js.Code, js.Header().Get("Content-Type"))
	}

	// The shared script derives the API base from the page URL, not from "/".
	shared := doRequest(t, env, http.MethodGet, "/admin/assets/admin.js", nil)
	if !strings.Contains(shared.Body.String(), "../api/admin/") {
		t.Fatal("admin.js does not derive a relative API base")
	}

	if unknown := doRequest(t, env, http.MethodGet, "/admin/assets/secret.txt", nil); unknown.Code != http.StatusNotFound {
		t.Fatalf("unknown asset = %d, want 404", unknown.Code)
	}
}

func itoa(value int64) string {
	return strconv.FormatInt(value, 10)
}
