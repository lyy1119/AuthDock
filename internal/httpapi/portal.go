package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/lyy1119/AuthDock/internal/store"
)

// The portal is the login page end users see. It is served by the gateway for
// the apex host, and can also run on its own listener (-portal-addr) for
// debugging. Either way it refuses to answer unless the Host matches the
// gateway domain configured in the system settings.

type portalSessionResponse struct {
	OK         bool         `json:"ok"`
	User       *userPayload `json:"user,omitempty"`
	ExpiresAt  string       `json:"expires_at,omitempty"`
	Domain     string       `json:"domain,omitempty"`
	RedirectTo string       `json:"redirect_to,omitempty"`
}

type portalLoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	// ReturnTo is where the browser should go after a successful login; it is
	// validated against the gateway domain before it is echoed back.
	ReturnTo string `json:"return_to"`
}

// portalGuard enforces the gateway domain check for the portal-only listener.
func (s *server) portalGuard(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		domain, err := s.store.Setting(r.Context(), store.SettingsKeyGatewayDomain)
		if err != nil {
			s.logger.Error("read gateway domain", "err", err)
			s.refusePortal(w, r, "cannot read the gateway domain from the database")
			return
		}
		domain = strings.ToLower(strings.TrimSpace(domain))

		if !s.noDNCheck {
			if domain == "" {
				s.refusePortal(w, r, "the gateway domain is not configured in the system settings")
				return
			}
			if host := requestHost(r); host != domain {
				s.refusePortal(w, r, fmt.Sprintf("host %q does not match the gateway domain %q", host, domain))
				return
			}
		}
		next(w, withGatewayDomain(r, domain))
	}
}

// requestHost returns the host the browser used, preferring X-Forwarded-Host so
// the check still works behind a reverse proxy.
func requestHost(r *http.Request) string {
	host := r.Host
	if forwarded := r.Header.Get("X-Forwarded-Host"); forwarded != "" {
		host = strings.TrimSpace(strings.Split(forwarded, ",")[0])
	}
	if withoutPort, _, err := net.SplitHostPort(host); err == nil {
		host = withoutPort
	}
	return strings.ToLower(strings.TrimSuffix(host, "."))
}

// refusePortal drops the connection without serving any page. A mismatched Host
// (or a missing gateway domain) must not reveal the login form at all.
func (s *server) refusePortal(w http.ResponseWriter, r *http.Request, reason string) {
	s.logger.Warn("gateway refused a connection",
		"host", requestHost(r), "remote", r.RemoteAddr, "reason", reason)

	if hijacker, ok := w.(http.Hijacker); ok {
		if conn, _, err := hijacker.Hijack(); err == nil {
			_ = conn.Close()
			return
		}
	}
	// Fallback for writers that cannot be hijacked (HTTP/2, tests).
	http.Error(w, "connection refused: "+reason, http.StatusMisdirectedRequest)
}

// handlePortalPage serves the user login page.
func (s *server) handlePortalPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		s.writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "该页面只接受 GET 请求")
		return
	}
	if r.URL.Path != "/" && r.URL.Path != "/login" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(s.portalPage)
}

// handlePortalLogin authenticates any account (user or admin): this is the front
// door for the people the pedestal serves, not for its operators.
func (s *server) handlePortalLogin(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxAdminBody)

	var req portalLoginRequest
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid_request",
			"请求体必须是 JSON，且只包含 username、password 与可选的 return_to")
		return
	}

	req.Username = strings.TrimSpace(req.Username)
	now := s.now()

	if allowed, retryAfter := s.limiter.Allow(req.Username, now); !allowed {
		seconds := int(retryAfter.Seconds() + 0.5)
		w.Header().Set("Retry-After", strconv.Itoa(seconds))
		s.writeError(w, http.StatusTooManyRequests, "too_many_attempts",
			fmt.Sprintf("登录尝试过于频繁，请 %d 秒后再试", seconds))
		return
	}

	if message := validateLoginRequest(loginRequest{Username: req.Username, Password: req.Password}); message != "" {
		s.writeError(w, http.StatusBadRequest, "invalid_request", message)
		return
	}

	user, err := s.store.GetUserByUsername(r.Context(), req.Username)
	if err != nil {
		if errors.Is(err, store.ErrUserNotFound) {
			s.store.VerifyDummy(req.Password)
			s.limiter.Fail(req.Username, now)
			s.logger.Warn("portal login failed", "username", req.Username,
				"reason", "unknown_username", "remote", r.RemoteAddr)
			s.writeError(w, http.StatusUnauthorized, "invalid_credentials", "用户名或密码错误")
			return
		}
		s.internalError(w, "portal login lookup", err)
		return
	}

	if err := s.store.VerifyPassword(user, req.Password); err != nil {
		s.limiter.Fail(req.Username, now)
		s.logger.Warn("portal login failed", "username", req.Username,
			"reason", "wrong_password", "remote", r.RemoteAddr)
		s.writeError(w, http.StatusUnauthorized, "invalid_credentials", "用户名或密码错误")
		return
	}

	s.limiter.Reset(req.Username)

	// The portal is for the people the pedestal serves. Administrators belong to
	// the management area, which is a different listener and a different session.
	if user.IsAdmin() {
		s.logger.Warn("portal login rejected", "username", user.Username, "reason", "admin_account",
			"remote", r.RemoteAddr)
		s.writeError(w, http.StatusForbidden, "user_only", "管理员账号请在管理端登录，此页面只接受普通账号")
		return
	}

	token, session, err := s.sessions.Create(ScopeGateway, user.Username, user.Role, now)
	if err != nil {
		s.internalError(w, "create portal session", err)
		return
	}

	domain := gatewayDomainFrom(r)
	s.setGatewayCookie(w, r, domain, token, session.ExpiresAt)
	s.logger.Info("portal login succeeded", "username", user.Username, "role", user.Role,
		"remote", r.RemoteAddr)

	s.writeJSON(w, http.StatusOK, portalSessionResponse{
		OK:         true,
		User:       &userPayload{Username: user.Username, Role: user.Role},
		ExpiresAt:  session.ExpiresAt.UTC().Format(time.RFC3339),
		Domain:     domain,
		RedirectTo: validateReturnTo(req.ReturnTo, domain),
	})
}

// handlePortalLogout drops the gateway session cookie.
func (s *server) handlePortalLogout(w http.ResponseWriter, r *http.Request) {
	domain := gatewayDomainFrom(r)

	for _, name := range []string{gatewayCookieSecureName, gatewayCookiePlainName} {
		if cookie, err := r.Cookie(name); err == nil {
			s.sessions.Delete(ScopeGateway, cookie.Value)
		}
	}

	s.clearGatewayCookie(w, r, domain)
	s.writeJSON(w, http.StatusOK, adminOKResponse{OK: true})
}

// handlePortalSession reports the session the portal visitors hold.
func (s *server) handlePortalSession(w http.ResponseWriter, r *http.Request) {
	domain := gatewayDomainFrom(r)

	session, ok := s.gatewaySession(r)
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthenticated", "尚未登录或会话已过期")
		return
	}

	s.writeJSON(w, http.StatusOK, portalSessionResponse{
		OK:        true,
		User:      &userPayload{Username: session.Username, Role: session.Role},
		ExpiresAt: session.ExpiresAt.UTC().Format(time.RFC3339),
		Domain:    domain,
	})
}
