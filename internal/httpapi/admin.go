package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/lyy1119/AuthDock/internal/passwd"
	"github.com/lyy1119/AuthDock/internal/store"
)

// maxAdminBody caps the request body of the admin API.
const maxAdminBody = 8 << 10

type adminUser struct {
	ID        int64  `json:"id"`
	Username  string `json:"username"`
	Role      string `json:"role"`
	CreatedAt string `json:"created_at"`
	Self      bool   `json:"self"`
}

type adminUserListResponse struct {
	OK    bool        `json:"ok"`
	Users []adminUser `json:"users"`
}

type adminUserResponse struct {
	OK        bool      `json:"ok"`
	User      adminUser `json:"user"`
	LoggedOut bool      `json:"logged_out,omitempty"`
}

type adminRule struct {
	ID        int64  `json:"id"`
	UserID    int64  `json:"user_id"`
	Username  string `json:"username"`
	Subdomain string `json:"subdomain"`
	Path      string `json:"path"`
	Upstream  string `json:"upstream"`
}

type adminRuleResponse struct {
	OK   bool      `json:"ok"`
	Rule adminRule `json:"rule"`
}

type adminUserRules struct {
	ID       int64       `json:"id"`
	Username string      `json:"username"`
	Role     string      `json:"role"`
	Rules    []adminRule `json:"rules"`
}

type adminGatewayResponse struct {
	OK            bool             `json:"ok"`
	GatewayDomain string           `json:"gateway_domain"`
	Users         []adminUserRules `json:"users"`
}

type adminSettings struct {
	GatewayDomain string `json:"gateway_domain"`
}

type adminSettingsResponse struct {
	OK       bool          `json:"ok"`
	Settings adminSettings `json:"settings"`
}

type adminOKResponse struct {
	OK bool `json:"ok"`
}

// requireAdmin wraps JSON endpoints: the caller must hold a session whose
// account still exists and still has the admin role in the database, so role
// changes take effect immediately instead of at the next login.
func (s *server) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, ok := s.currentSession(r)
		if !ok {
			s.writeError(w, http.StatusUnauthorized, "unauthenticated", "尚未登录或会话已过期")
			return
		}
		user, err := s.store.GetUserByUsername(r.Context(), session.Username)
		if err != nil {
			s.writeError(w, http.StatusUnauthorized, "unauthenticated", "会话对应的账号不存在")
			return
		}
		if !user.IsAdmin() {
			s.writeError(w, http.StatusForbidden, "admin_only", "需要管理员权限")
			return
		}
		next(w, r)
	}
}

// requireAdminPage is the page variant: unauthenticated visitors are redirected
// to the login page instead of receiving JSON.
func (s *server) requireAdminPage(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, ok := s.currentSession(r)
		if ok {
			user, err := s.store.GetUserByUsername(r.Context(), session.Username)
			ok = err == nil && user.IsAdmin()
		}
		if !ok {
			s.redirectRelative(w, "../login")
			return
		}
		next(w, r)
	}
}

func (s *server) methodNotAllowed(w http.ResponseWriter, allow string) {
	w.Header().Set("Allow", allow)
	s.writeError(w, http.StatusMethodNotAllowed, "method_not_allowed",
		fmt.Sprintf("该接口只接受 %s 请求", allow))
}

func (s *server) decodeAdminJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxAdminBody)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid_request", "请求体不是合法的 JSON")
		return false
	}
	return true
}

func (s *server) adminUserDTO(user store.User, session Session) adminUser {
	return adminUser{
		ID:        user.ID,
		Username:  user.Username,
		Role:      user.Role,
		CreatedAt: user.CreatedAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
		Self:      user.Username == session.Username,
	}
}

func (s *server) handleAdminUsers(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.listAdminUsers(w, r)
	case http.MethodPost:
		s.createAdminUser(w, r)
	default:
		s.methodNotAllowed(w, "GET, POST")
	}
}

func (s *server) listAdminUsers(w http.ResponseWriter, r *http.Request) {
	session, _ := s.currentSession(r)

	users, err := s.store.ListUsers(r.Context())
	if err != nil {
		s.logger.Error("list users", "err", err)
		s.writeError(w, http.StatusInternalServerError, "internal_error", "服务器内部错误")
		return
	}
	out := make([]adminUser, 0, len(users))
	for _, user := range users {
		out = append(out, s.adminUserDTO(user, session))
	}
	s.writeJSON(w, http.StatusOK, adminUserListResponse{OK: true, Users: out})
}

func (s *server) createAdminUser(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}
	if !s.decodeAdminJSON(w, r, &body) {
		return
	}
	if body.Role == "" {
		body.Role = store.RoleUser
	}
	if body.Role != store.RoleUser && body.Role != store.RoleAdmin {
		s.writeError(w, http.StatusBadRequest, "invalid_request", "身份只能是 user 或 admin")
		return
	}
	if err := passwd.ValidateUsername(body.Username); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid_request", "用户名只能包含字母、数字、下划线、连字符和点，长度 1-20")
		return
	}
	if err := passwd.ValidateNewPassword(body.Password); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid_request",
			fmt.Sprintf("密码长度必须在 %d 到 %d 个字节之间", passwd.MinPasswordLen, passwd.MaxPasswordLen))
		return
	}

	user, err := s.store.CreateUser(r.Context(), body.Username, body.Password, body.Role)
	switch {
	case err == nil:
	case errors.Is(err, store.ErrUserExists):
		s.writeError(w, http.StatusConflict, "username_taken", "该用户名已存在")
		return
	case errors.Is(err, passwd.ErrInvalidUsername), errors.Is(err, passwd.ErrInvalidPassword):
		s.writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	default:
		s.logger.Error("create user", "err", err)
		s.writeError(w, http.StatusInternalServerError, "internal_error", "服务器内部错误")
		return
	}

	session, _ := s.currentSession(r)
	s.logger.Info("admin created user", "username", user.Username, "role", user.Role, "by", session.Username)
	s.writeJSON(w, http.StatusCreated, adminUserResponse{OK: true, User: s.adminUserDTO(*user, session)})
}

func (s *server) handleAdminUser(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		s.writeError(w, http.StatusBadRequest, "invalid_request", "用户 id 不合法")
		return
	}
	switch r.Method {
	case http.MethodPatch:
		s.updateAdminUser(w, r, id)
	case http.MethodDelete:
		s.deleteAdminUser(w, r, id)
	default:
		s.methodNotAllowed(w, "PATCH, DELETE")
	}
}

func (s *server) updateAdminUser(w http.ResponseWriter, r *http.Request, id int64) {
	var body struct {
		Role     string `json:"role"`
		Password string `json:"password"`
	}
	if !s.decodeAdminJSON(w, r, &body) {
		return
	}
	session, _ := s.currentSession(r)

	target, err := s.store.GetUserByID(r.Context(), id)
	if errors.Is(err, store.ErrUserNotFound) {
		s.writeError(w, http.StatusNotFound, "not_found", "用户不存在")
		return
	}
	if err != nil {
		s.logger.Error("look up user", "err", err)
		s.writeError(w, http.StatusInternalServerError, "internal_error", "服务器内部错误")
		return
	}

	roleChanged := false
	if body.Role != "" && body.Role != target.Role {
		if body.Role != store.RoleUser && body.Role != store.RoleAdmin {
			s.writeError(w, http.StatusBadRequest, "invalid_request", "身份只能是 user 或 admin")
			return
		}
		if target.IsAdmin() && body.Role == store.RoleUser {
			admins, err := s.store.CountAdmins(r.Context())
			if err != nil {
				s.logger.Error("count admins", "err", err)
				s.writeError(w, http.StatusInternalServerError, "internal_error", "服务器内部错误")
				return
			}
			if admins <= 1 {
				s.writeError(w, http.StatusConflict, "last_admin", "至少需要保留一个管理员账号")
				return
			}
		}
		if _, err := s.store.UpdateUserRole(r.Context(), id, body.Role); err != nil {
			s.logger.Error("update role", "err", err)
			s.writeError(w, http.StatusInternalServerError, "internal_error", "服务器内部错误")
			return
		}
		roleChanged = true
	}

	if body.Password != "" {
		if _, err := s.store.SetUserPassword(r.Context(), id, body.Password); err != nil {
			if errors.Is(err, passwd.ErrInvalidPassword) {
				s.writeError(w, http.StatusBadRequest, "invalid_request",
					fmt.Sprintf("密码长度必须在 %d 到 %d 个字节之间", passwd.MinPasswordLen, passwd.MaxPasswordLen))
				return
			}
			s.logger.Error("update password", "err", err)
			s.writeError(w, http.StatusInternalServerError, "internal_error", "服务器内部错误")
			return
		}
	}

	updated, err := s.store.GetUserByID(r.Context(), id)
	if err != nil {
		s.logger.Error("reload user", "err", err)
		s.writeError(w, http.StatusInternalServerError, "internal_error", "服务器内部错误")
		return
	}

	response := adminUserResponse{OK: true, User: s.adminUserDTO(*updated, session)}

	// Demoting the signed-in account ends its own admin session.
	if roleChanged && updated.Username == session.Username && !updated.IsAdmin() {
		if cookie, err := r.Cookie(SessionCookieName); err == nil {
			s.sessions.Delete(cookie.Value)
		}
		s.clearSessionCookie(w)
		response.LoggedOut = true
	}

	s.logger.Info("admin updated user", "username", updated.Username, "role", updated.Role,
		"password_reset", body.Password != "", "by", session.Username)
	s.writeJSON(w, http.StatusOK, response)
}

func (s *server) deleteAdminUser(w http.ResponseWriter, r *http.Request, id int64) {
	session, _ := s.currentSession(r)

	target, err := s.store.GetUserByID(r.Context(), id)
	if errors.Is(err, store.ErrUserNotFound) {
		s.writeError(w, http.StatusNotFound, "not_found", "用户不存在")
		return
	}
	if err != nil {
		s.logger.Error("look up user", "err", err)
		s.writeError(w, http.StatusInternalServerError, "internal_error", "服务器内部错误")
		return
	}
	if target.Username == session.Username {
		s.writeError(w, http.StatusConflict, "self_delete", "不能删除当前登录的账号")
		return
	}
	if target.IsAdmin() {
		admins, err := s.store.CountAdmins(r.Context())
		if err != nil {
			s.logger.Error("count admins", "err", err)
			s.writeError(w, http.StatusInternalServerError, "internal_error", "服务器内部错误")
			return
		}
		if admins <= 1 {
			s.writeError(w, http.StatusConflict, "last_admin", "至少需要保留一个管理员账号")
			return
		}
	}

	if err := s.store.DeleteUser(r.Context(), id); err != nil {
		s.logger.Error("delete user", "err", err)
		s.writeError(w, http.StatusInternalServerError, "internal_error", "服务器内部错误")
		return
	}
	s.logger.Info("admin deleted user", "username", target.Username, "by", session.Username)
	s.writeJSON(w, http.StatusOK, adminOKResponse{OK: true})
}

func (s *server) handleAdminSettings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		domain, err := s.store.Setting(r.Context(), store.SettingsKeyGatewayDomain)
		if err != nil {
			s.logger.Error("read gateway domain", "err", err)
			s.writeError(w, http.StatusInternalServerError, "internal_error", "服务器内部错误")
			return
		}
		s.writeJSON(w, http.StatusOK, adminSettingsResponse{OK: true, Settings: adminSettings{GatewayDomain: domain}})

	case http.MethodPut:
		var body adminSettings
		if !s.decodeAdminJSON(w, r, &body) {
			return
		}
		if err := store.ValidateGatewayDomain(body.GatewayDomain); err != nil {
			s.writeError(w, http.StatusBadRequest, "invalid_request", "网关域名必须是裸域名，例如 gw.example.net")
			return
		}
		if err := s.store.SetSetting(r.Context(), store.SettingsKeyGatewayDomain, body.GatewayDomain); err != nil {
			s.logger.Error("write gateway domain", "err", err)
			s.writeError(w, http.StatusInternalServerError, "internal_error", "服务器内部错误")
			return
		}
		session, _ := s.currentSession(r)
		s.logger.Info("admin saved gateway domain", "domain", body.GatewayDomain, "by", session.Username)
		s.writeJSON(w, http.StatusOK, adminSettingsResponse{OK: true, Settings: adminSettings{GatewayDomain: body.GatewayDomain}})

	default:
		s.methodNotAllowed(w, "GET, PUT")
	}
}

func (s *server) handleAdminGateway(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.methodNotAllowed(w, "GET")
		return
	}
	ctx := r.Context()

	domain, err := s.store.Setting(ctx, store.SettingsKeyGatewayDomain)
	if err != nil {
		s.logger.Error("read gateway domain", "err", err)
		s.writeError(w, http.StatusInternalServerError, "internal_error", "服务器内部错误")
		return
	}
	users, err := s.store.ListUsers(ctx)
	if err != nil {
		s.logger.Error("list users", "err", err)
		s.writeError(w, http.StatusInternalServerError, "internal_error", "服务器内部错误")
		return
	}
	rules, err := s.store.ListGatewayRules(ctx)
	if err != nil {
		s.logger.Error("list gateway rules", "err", err)
		s.writeError(w, http.StatusInternalServerError, "internal_error", "服务器内部错误")
		return
	}

	byUser := make(map[int64][]adminRule, len(users))
	for _, rule := range rules {
		byUser[rule.UserID] = append(byUser[rule.UserID], toAdminRule(rule))
	}
	out := make([]adminUserRules, 0, len(users))
	for _, user := range users {
		userRules := byUser[user.ID]
		if userRules == nil {
			userRules = []adminRule{}
		}
		out = append(out, adminUserRules{ID: user.ID, Username: user.Username, Role: user.Role, Rules: userRules})
	}
	s.writeJSON(w, http.StatusOK, adminGatewayResponse{OK: true, GatewayDomain: domain, Users: out})
}

func (s *server) handleAdminRules(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		var body struct {
			UserID    int64  `json:"user_id"`
			Subdomain string `json:"subdomain"`
			Path      string `json:"path"`
			Upstream  string `json:"upstream"`
		}
		if !s.decodeAdminJSON(w, r, &body) {
			return
		}
		if body.Path == "" {
			body.Path = "*"
		}
		if message := validateRuleInput(body.Subdomain, body.Path, body.Upstream); message != "" {
			s.writeError(w, http.StatusBadRequest, "invalid_request", message)
			return
		}
		rule, err := s.store.CreateGatewayRule(r.Context(), body.UserID, body.Subdomain, body.Path, body.Upstream)
		switch {
		case err == nil:
		case errors.Is(err, store.ErrUserNotFound):
			s.writeError(w, http.StatusNotFound, "not_found", "用户不存在")
			return
		default:
			s.logger.Error("create gateway rule", "err", err)
			s.writeError(w, http.StatusInternalServerError, "internal_error", "服务器内部错误")
			return
		}
		session, _ := s.currentSession(r)
		s.logger.Info("admin created gateway rule", "subdomain", rule.Subdomain, "user", rule.Username, "by", session.Username)
		s.writeJSON(w, http.StatusCreated, adminRuleResponse{OK: true, Rule: toAdminRule(*rule)})

	default:
		s.methodNotAllowed(w, "POST")
	}
}

func (s *server) handleAdminRule(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		s.writeError(w, http.StatusBadRequest, "invalid_request", "规则 id 不合法")
		return
	}
	switch r.Method {
	case http.MethodPatch:
		var body struct {
			Subdomain string `json:"subdomain"`
			Path      string `json:"path"`
			Upstream  string `json:"upstream"`
		}
		if !s.decodeAdminJSON(w, r, &body) {
			return
		}
		if body.Path == "" {
			body.Path = "*"
		}
		if message := validateRuleInput(body.Subdomain, body.Path, body.Upstream); message != "" {
			s.writeError(w, http.StatusBadRequest, "invalid_request", message)
			return
		}
		rule, err := s.store.UpdateGatewayRule(r.Context(), id, body.Subdomain, body.Path, body.Upstream)
		if errors.Is(err, store.ErrRuleNotFound) {
			s.writeError(w, http.StatusNotFound, "not_found", "规则不存在")
			return
		}
		if err != nil {
			s.logger.Error("update gateway rule", "err", err)
			s.writeError(w, http.StatusInternalServerError, "internal_error", "服务器内部错误")
			return
		}
		s.writeJSON(w, http.StatusOK, adminRuleResponse{OK: true, Rule: toAdminRule(*rule)})

	case http.MethodDelete:
		err := s.store.DeleteGatewayRule(r.Context(), id)
		if errors.Is(err, store.ErrRuleNotFound) {
			s.writeError(w, http.StatusNotFound, "not_found", "规则不存在")
			return
		}
		if err != nil {
			s.logger.Error("delete gateway rule", "err", err)
			s.writeError(w, http.StatusInternalServerError, "internal_error", "服务器内部错误")
			return
		}
		s.writeJSON(w, http.StatusOK, adminOKResponse{OK: true})

	default:
		s.methodNotAllowed(w, "PATCH, DELETE")
	}
}

func validateRuleInput(subdomain, path, upstream string) string {
	if err := store.ValidateSubdomain(subdomain); err != nil {
		return "目标子域名不合法：只能包含字母、数字、连字符，或使用 * 通配"
	}
	if err := store.ValidatePath(path); err != nil {
		return "目标路径必须以 / 开头，或使用 * 通配"
	}
	if err := store.ValidateUpstream(upstream); err != nil {
		return "源地址必须是完整的 http(s) URL，且不能包含账号密码"
	}
	return ""
}

func toAdminRule(rule store.GatewayRule) adminRule {
	return adminRule{
		ID:        rule.ID,
		UserID:    rule.UserID,
		Username:  rule.Username,
		Subdomain: rule.Subdomain,
		Path:      rule.Path,
		Upstream:  rule.Upstream,
	}
}
