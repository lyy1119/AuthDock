package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/lyy1119/AuthDock/internal/passwd"
	"github.com/lyy1119/AuthDock/internal/store"
)

// maxLoginBody caps the request body accepted by the login endpoint.
const maxLoginBody = 4 << 10

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type userPayload struct {
	Username string `json:"username"`
	Role     string `json:"role"`
}

type loginResponse struct {
	OK        bool         `json:"ok"`
	User      *userPayload `json:"user,omitempty"`
	ExpiresAt string       `json:"expires_at,omitempty"`
	// Token is the access token, for clients that cannot keep a cookie (native
	// apps). Send it back as "Authorization: Bearer <token>".
	Token string `json:"token,omitempty"`
	// RefreshToken is exchanged at POST /api/auth/token for a fresh pair.
	RefreshToken     string `json:"refresh_token,omitempty"`
	RefreshExpiresAt string `json:"refresh_expires_at,omitempty"`
}

type tokenPairResponse struct {
	OK               bool   `json:"ok"`
	Token            string `json:"token"`
	ExpiresAt        string `json:"expires_at"`
	RefreshToken     string `json:"refresh_token"`
	RefreshExpiresAt string `json:"refresh_expires_at"`
}

type sessionResponse struct {
	OK        bool         `json:"ok"`
	User      *userPayload `json:"user,omitempty"`
	ExpiresAt string       `json:"expires_at,omitempty"`
}

type logoutResponse struct {
	OK bool `json:"ok"`
}

type errorResponse struct {
	OK      bool   `json:"ok"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

// handleLogin authenticates an administrator.
//
// Only accounts with the admin role may sign in; a valid non-admin account gets
// 403 instead of a session. Failures are counted per username and eventually
// answered with 429.
func (s *server) handleLogin(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBody)

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
		seconds := int(math.Ceil(retryAfter.Seconds()))
		w.Header().Set("Retry-After", strconv.Itoa(seconds))
		s.writeError(w, http.StatusTooManyRequests, "too_many_attempts",
			fmt.Sprintf("登录尝试过于频繁，请 %d 秒后再试", seconds))
		s.logger.Warn("login throttled", "username", req.Username, "remote", r.RemoteAddr)
		return
	}

	if message := validateLoginRequest(req); message != "" {
		s.writeError(w, http.StatusBadRequest, "invalid_request", message)
		return
	}

	user, err := s.store.GetUserByUsername(r.Context(), req.Username)
	if err != nil {
		if errors.Is(err, store.ErrUserNotFound) {
			// Spend the same Argon2id work as a real check so the response time
			// does not reveal whether the username exists.
			s.store.VerifyDummy(req.Password)
			s.limiter.Fail(req.Username, now)
			s.logger.Warn("login failed", "username", req.Username, "reason", "unknown_username", "remote", r.RemoteAddr)
			s.writeError(w, http.StatusUnauthorized, "invalid_credentials", "用户名或密码错误")
			return
		}
		s.logger.Error("login lookup failed", "err", err)
		s.writeError(w, http.StatusInternalServerError, "internal_error", "服务器内部错误")
		return
	}

	if err := s.store.VerifyPassword(user, req.Password); err != nil {
		s.limiter.Fail(req.Username, now)
		s.logger.Warn("login failed", "username", req.Username, "reason", "wrong_password", "remote", r.RemoteAddr)
		s.writeError(w, http.StatusUnauthorized, "invalid_credentials", "用户名或密码错误")
		return
	}

	s.limiter.Reset(req.Username)

	// The password was correct, so telling the account owner that the role is
	// insufficient leaks nothing they do not already know.
	if !user.IsAdmin() {
		s.logger.Warn("login rejected", "username", user.Username, "role", user.Role, "remote", r.RemoteAddr)
		s.writeError(w, http.StatusForbidden, "admin_only", "该账号不是管理员，仅 admin 角色可以登录管理后台")
		return
	}

	issued, err := s.sessions.Issue(ScopeAdmin, user.Username, user.Role, now)
	if err != nil {
		s.logger.Error("create session", "err", err)
		s.writeError(w, http.StatusInternalServerError, "internal_error", "服务器内部错误")
		return
	}
	s.setSessionCookie(w, r, issued.Access, issued.AccessExpiry)
	s.logger.Info("login succeeded", "username", user.Username, "role", user.Role, "remote", r.RemoteAddr)

	s.writeJSON(w, http.StatusOK, loginResponse{
		OK:               true,
		User:             &userPayload{Username: user.Username, Role: user.Role},
		ExpiresAt:        issued.AccessExpiry.UTC().Format(time.RFC3339),
		Token:            issued.Access,
		RefreshToken:     issued.Refresh,
		RefreshExpiresAt: issued.RefreshExpiry.UTC().Format(time.RFC3339),
	})
}

// handleLogout drops the session token, if the request carries one.
func (s *server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(SessionCookieName); err == nil {
		s.sessions.Delete(ScopeAdmin, cookie.Value)
	}
	if token := bearerToken(r); token != "" {
		s.sessions.Delete(ScopeAdmin, token)
	}
	s.clearSessionCookie(w)
	s.writeJSON(w, http.StatusOK, logoutResponse{OK: true})
}

// handleSession reports the current administrator session.
func (s *server) handleSession(w http.ResponseWriter, r *http.Request) {
	session, ok := s.currentSession(r)
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthenticated", "尚未登录或会话已过期")
		return
	}
	s.writeJSON(w, http.StatusOK, sessionResponse{
		OK:        true,
		User:      &userPayload{Username: session.Username, Role: session.Role},
		ExpiresAt: session.ExpiresAt.UTC().Format(time.RFC3339),
	})
}

// validateLoginRequest returns a user facing message for an unusable request, or
// an empty string when the request may proceed.
func validateLoginRequest(req loginRequest) string {
	if req.Username == "" {
		return "用户名不能为空"
	}
	if err := passwd.ValidateUsername(req.Username); err != nil {
		if strings.Contains(err.Error(), "1-20") {
			return fmt.Sprintf("用户名长度必须在 1 到 %d 个字符之间", passwd.MaxUsernameLen)
		}
		return "用户名只能包含字母、数字、下划线、连字符和点"
	}
	if req.Password == "" {
		return "密码不能为空"
	}
	if len(req.Password) > passwd.MaxPasswordLen {
		return fmt.Sprintf("密码长度不能超过 %d 字节", passwd.MaxPasswordLen)
	}
	return ""
}
