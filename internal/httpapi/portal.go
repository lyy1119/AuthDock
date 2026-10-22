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

// The user portal is the login page end users see. It listens on its own
// address (-portal-addr) and refuses to serve anything unless the Host it is
// reached through matches the gateway domain configured in the system settings.

type portalSessionResponse struct {
	OK        bool         `json:"ok"`
	User      *userPayload `json:"user,omitempty"`
	ExpiresAt string       `json:"expires_at,omitempty"`
	Domain    string       `json:"domain,omitempty"`
}

// portalGuard enforces the gateway domain check before any other handling.
func (s *server) portalGuard(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.noDNCheck {
			next(w, r)
			return
		}

		domain, err := s.store.Setting(r.Context(), store.SettingsKeyGatewayDomain)
		if err != nil {
			s.logger.Error("read gateway domain", "err", err)
			s.refusePortal(w, r, "cannot read the gateway domain from the database")
			return
		}
		domain = strings.ToLower(strings.TrimSpace(domain))
		if domain == "" {
			s.refusePortal(w, r, "the gateway domain is not configured in the system settings")
			return
		}

		host := requestHost(r)
		if host != domain {
			s.refusePortal(w, r, fmt.Sprintf("host %q does not match the gateway domain %q", host, domain))
			return
		}
		next(w, r)
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
	s.logger.Warn("portal refused a connection",
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

// handlePortalPage serves the user login page. Only "/" and "/login" are pages;
// everything else under this handler is a 404.
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

// handlePortalLogin authenticates any account (user or admin): this is the
// front door for the people the SSO pedestal serves, not for its operators.
func (s *server) handlePortalLogin(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxAdminBody)

	var req loginRequest
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid_request", "请求体必须是 JSON，且只包含 username 与 password 字段")
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

	if message := validateLoginRequest(req); message != "" {
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

	token, session, err := s.sessions.Create(user.Username, user.Role, now)
	if err != nil {
		s.internalError(w, "create portal session", err)
		return
	}
	s.setSessionCookie(w, r, token, session.ExpiresAt)
	s.logger.Info("portal login succeeded", "username", user.Username, "role", user.Role,
		"remote", r.RemoteAddr)

	s.writeJSON(w, http.StatusOK, portalSessionResponse{
		OK:        true,
		User:      &userPayload{Username: user.Username, Role: user.Role},
		ExpiresAt: session.ExpiresAt.UTC().Format(time.RFC3339),
	})
}
