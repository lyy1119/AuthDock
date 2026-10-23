package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lyy1119/AuthDock/internal/store"
)

// nativeLogin performs a portal login and returns the JSON body, the way a
// native client would use it.
func nativeLogin(t *testing.T, env *gatewayEnv, username, password string) portalSessionResponse {
	t.Helper()
	payload, err := json.Marshal(map[string]string{"username": username, "password": password})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "http://"+gatewayDomainName+"/api/login", bytes.NewReader(payload))
	req.Host = gatewayDomainName
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("portal login = %d, body = %s", rec.Code, rec.Body.String())
	}
	var body portalSessionResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return body
}

// TestPortalLoginReturnsABearerToken covers the native client flow: JSON in,
// token out, no cookie jar needed.
func TestPortalLoginReturnsABearerToken(t *testing.T) {
	env := newGatewayEnv(t, false)
	upstream, record := newUpstream(t, "svc")
	env.gate(t, "svc", upstream.Listener.Addr().String(), "svc", "", nil)

	body := nativeLogin(t, env, "alice", alicePassword)
	if body.Token == "" {
		t.Fatal("the portal login returned no token")
	}
	if body.User == nil || body.User.Username != "alice" {
		t.Fatalf("unexpected user: %+v", body.User)
	}

	// The token authenticates a proxied request without any cookie.
	req := httptest.NewRequest(http.MethodGet, "http://svc."+gatewayDomainName+"/week", nil)
	req.Host = "svc." + gatewayDomainName
	req.Header.Set("Authorization", "Bearer "+body.Token)
	rec := httptest.NewRecorder()
	env.handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("bearer request = %d, body = %s", rec.Code, rec.Body.String())
	}
	if path, _, _ := record.last(); path != "/week?" {
		t.Fatalf("upstream path = %q", path)
	}

	// The portal session endpoint accepts it too.
	sessionReq := httptest.NewRequest(http.MethodGet, "http://"+gatewayDomainName+"/api/session", nil)
	sessionReq.Host = gatewayDomainName
	sessionReq.Header.Set("Authorization", "Bearer "+body.Token)
	sessionRec := httptest.NewRecorder()
	env.handler.ServeHTTP(sessionRec, sessionReq)
	if sessionRec.Code != http.StatusOK {
		t.Fatalf("/api/session with a bearer token = %d", sessionRec.Code)
	}
	if !strings.Contains(sessionRec.Body.String(), "alice") {
		t.Fatalf("session body = %s", sessionRec.Body.String())
	}
}

func TestPortalBearerLogoutRevokesTheToken(t *testing.T) {
	env := newGatewayEnv(t, false)
	upstream, _ := newUpstream(t, "svc")
	env.gate(t, "svc", upstream.Listener.Addr().String(), "svc", "", nil)

	token := nativeLogin(t, env, "alice", alicePassword).Token

	logoutReq := httptest.NewRequest(http.MethodPost, "http://"+gatewayDomainName+"/api/logout", nil)
	logoutReq.Host = gatewayDomainName
	logoutReq.Header.Set("Authorization", "Bearer "+token)
	logoutRec := httptest.NewRecorder()
	env.handler.ServeHTTP(logoutRec, logoutReq)
	if logoutRec.Code != http.StatusOK {
		t.Fatalf("logout = %d", logoutRec.Code)
	}

	req := httptest.NewRequest(http.MethodGet, "http://svc."+gatewayDomainName+"/", nil)
	req.Host = "svc." + gatewayDomainName
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	env.handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("request after logout = %d, want 302 back to the portal", rec.Code)
	}
}

func TestBearerTokensDoNotCrossScopes(t *testing.T) {
	env := newGatewayEnv(t, false)

	portalToken := nativeLogin(t, env, "alice", alicePassword).Token
	adminToken := adminLoginToken(t, env)

	// A gateway token is worthless at the management API.
	adminReq := httptest.NewRequest(http.MethodGet, "/api/admin/users", nil)
	adminReq.Header.Set("Authorization", "Bearer "+portalToken)
	adminRec := httptest.NewRecorder()
	env.admin.ServeHTTP(adminRec, adminReq)
	if adminRec.Code != http.StatusUnauthorized {
		t.Fatalf("gateway token at the management API = %d, want 401", adminRec.Code)
	}

	// An admin token is worthless at the gateway, which keeps the ports apart.
	upstream, _ := newUpstream(t, "svc")
	env.gate(t, "svc", upstream.Listener.Addr().String(), "svc", "", nil)
	gateReq := httptest.NewRequest(http.MethodGet, "http://svc."+gatewayDomainName+"/", nil)
	gateReq.Host = "svc." + gatewayDomainName
	gateReq.Header.Set("Authorization", "Bearer "+adminToken)
	gateRec := httptest.NewRecorder()
	env.handler.ServeHTTP(gateRec, gateReq)
	if gateRec.Code != http.StatusFound {
		t.Fatalf("admin token at the gateway = %d, want 302", gateRec.Code)
	}

	// The admin token does work for the management API.
	okReq := httptest.NewRequest(http.MethodGet, "/api/admin/users", nil)
	okReq.Header.Set("Authorization", "Bearer "+adminToken)
	okRec := httptest.NewRecorder()
	env.admin.ServeHTTP(okRec, okReq)
	if okRec.Code != http.StatusOK {
		t.Fatalf("admin token at the management API = %d, body = %s", okRec.Code, okRec.Body.String())
	}
}

func TestBearerTokenFromAdminLogin(t *testing.T) {
	env := newGatewayEnv(t, false)
	token := adminLoginToken(t, env)
	if token == "" {
		t.Fatal("the management login returned no token")
	}

	req := httptest.NewRequest(http.MethodGet, "/api/auth/session", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	env.admin.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("session with an admin bearer token = %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), store.RoleAdmin) {
		t.Fatalf("session body = %s", rec.Body.String())
	}
}

// adminLoginToken signs in at the management API and returns its token.
func adminLoginToken(t *testing.T, env *gatewayEnv) string {
	t.Helper()
	payload, _ := json.Marshal(map[string]string{"username": "boss", "password": "bosspass12"})
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8080/api/auth/login", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.admin.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("admin login = %d, body = %s", rec.Code, rec.Body.String())
	}
	var body loginResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return body.Token
}
