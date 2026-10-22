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

type adminGate struct {
	ID       int64  `json:"id"`
	Name     string `json:"name"`
	From     string `json:"from"`
	ToPrefix string `json:"to_prefix"`
	ToSuffix string `json:"to_suffix"`
	// UserID is null for a gate available to every account.
	UserID    *int64 `json:"user_id"`
	Username  string `json:"username"`
	CreatedAt string `json:"created_at"`
}

type adminGateListResponse struct {
	OK            bool        `json:"ok"`
	GatewayDomain string      `json:"gateway_domain"`
	Gates         []adminGate `json:"gates"`
}

type adminGateResponse struct {
	OK   bool      `json:"ok"`
	Gate adminGate `json:"gate"`
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

func adminGateDTO(gate store.Gate) adminGate {
	return adminGate{
		ID:        gate.ID,
		Name:      gate.Name,
		From:      gate.From,
		ToPrefix:  gate.ToPrefix,
		ToSuffix:  gate.ToSuffix,
		UserID:    gate.UserID,
		Username:  gate.Username,
		CreatedAt: gate.CreatedAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
	}
}

func (s *server) internalError(w http.ResponseWriter, message string, err error) {
	s.logger.Error(message, "err", err)
	s.writeError(w, http.StatusInternalServerError, "internal_error", "服务器内部错误")
}

// ── users ──────────────────────────────────────────────────────────────

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
		s.internalError(w, "list users", err)
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
		s.internalError(w, "create user", err)
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
		s.internalError(w, "look up user", err)
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
				s.internalError(w, "count admins", err)
				return
			}
			if admins <= 1 {
				s.writeError(w, http.StatusConflict, "last_admin", "至少需要保留一个管理员账号")
				return
			}
		}
		if _, err := s.store.UpdateUserRole(r.Context(), id, body.Role); err != nil {
			s.internalError(w, "update role", err)
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
			s.internalError(w, "update password", err)
			return
		}
	}

	updated, err := s.store.GetUserByID(r.Context(), id)
	if err != nil {
		s.internalError(w, "reload user", err)
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
		s.internalError(w, "look up user", err)
		return
	}
	if target.Username == session.Username {
		s.writeError(w, http.StatusConflict, "self_delete", "不能删除当前登录的账号")
		return
	}
	if target.IsAdmin() {
		admins, err := s.store.CountAdmins(r.Context())
		if err != nil {
			s.internalError(w, "count admins", err)
			return
		}
		if admins <= 1 {
			s.writeError(w, http.StatusConflict, "last_admin", "至少需要保留一个管理员账号")
			return
		}
	}

	if err := s.store.DeleteUser(r.Context(), id); err != nil {
		s.internalError(w, "delete user", err)
		return
	}
	s.logger.Info("admin deleted user", "username", target.Username, "by", session.Username)
	s.writeJSON(w, http.StatusOK, adminOKResponse{OK: true})
}

// ── settings ───────────────────────────────────────────────────────────

func (s *server) handleAdminSettings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		domain, err := s.store.Setting(r.Context(), store.SettingsKeyGatewayDomain)
		if err != nil {
			s.internalError(w, "read gateway domain", err)
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
			s.internalError(w, "write gateway domain", err)
			return
		}
		session, _ := s.currentSession(r)
		s.logger.Info("admin saved gateway domain", "domain", body.GatewayDomain, "by", session.Username)
		s.writeJSON(w, http.StatusOK, adminSettingsResponse{OK: true, Settings: adminSettings{GatewayDomain: body.GatewayDomain}})

	default:
		s.methodNotAllowed(w, "GET, PUT")
	}
}

// ── gates ──────────────────────────────────────────────────────────────

func (s *server) handleAdminGates(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.listAdminGates(w, r)
	case http.MethodPost:
		s.createAdminGate(w, r)
	default:
		s.methodNotAllowed(w, "GET, POST")
	}
}

func (s *server) listAdminGates(w http.ResponseWriter, r *http.Request) {
	domain, err := s.store.Setting(r.Context(), store.SettingsKeyGatewayDomain)
	if err != nil {
		s.internalError(w, "read gateway domain", err)
		return
	}
	gates, err := s.store.ListGates(r.Context())
	if err != nil {
		s.internalError(w, "list gates", err)
		return
	}
	out := make([]adminGate, 0, len(gates))
	for _, gate := range gates {
		out = append(out, adminGateDTO(gate))
	}
	s.writeJSON(w, http.StatusOK, adminGateListResponse{OK: true, GatewayDomain: domain, Gates: out})
}

func (s *server) createAdminGate(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name     string `json:"name"`
		From     string `json:"from"`
		ToPrefix string `json:"to_prefix"`
		ToSuffix string `json:"to_suffix"`
		UserID   *int64 `json:"user_id"`
	}
	if !s.decodeAdminJSON(w, r, &body) {
		return
	}
	if message := validateGateInput(body.Name, body.From, body.ToPrefix, body.ToSuffix); message != "" {
		s.writeError(w, http.StatusBadRequest, "invalid_request", message)
		return
	}

	gate, err := s.store.CreateGate(r.Context(), body.Name, body.From, body.ToPrefix, body.ToSuffix, body.UserID)
	switch {
	case err == nil:
	case errors.Is(err, store.ErrGateExists):
		s.writeError(w, http.StatusConflict, "gate_exists", "该子域名与路径前缀已被其他网关占用")
		return
	case errors.Is(err, store.ErrUserNotFound):
		s.writeError(w, http.StatusNotFound, "not_found", "指定的用户不存在")
		return
	default:
		s.internalError(w, "create gate", err)
		return
	}

	session, _ := s.currentSession(r)
	s.logger.Info("admin created gate", "name", gate.Name, "prefix", gate.ToPrefix,
		"suffix", gate.ToSuffix, "from", gate.From, "by", session.Username)
	s.writeJSON(w, http.StatusCreated, adminGateResponse{OK: true, Gate: adminGateDTO(*gate)})
}

func (s *server) handleAdminGate(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		s.writeError(w, http.StatusBadRequest, "invalid_request", "网关 id 不合法")
		return
	}
	switch r.Method {
	case http.MethodPatch:
		var body struct {
			Name     string `json:"name"`
			From     string `json:"from"`
			ToPrefix string `json:"to_prefix"`
			ToSuffix string `json:"to_suffix"`
			UserID   *int64 `json:"user_id"`
		}
		if !s.decodeAdminJSON(w, r, &body) {
			return
		}
		if message := validateGateInput(body.Name, body.From, body.ToPrefix, body.ToSuffix); message != "" {
			s.writeError(w, http.StatusBadRequest, "invalid_request", message)
			return
		}
		gate, err := s.store.UpdateGate(r.Context(), id, body.Name, body.From, body.ToPrefix, body.ToSuffix, body.UserID)
		if errors.Is(err, store.ErrGateNotFound) {
			s.writeError(w, http.StatusNotFound, "not_found", "网关不存在")
			return
		}
		if errors.Is(err, store.ErrGateExists) {
			s.writeError(w, http.StatusConflict, "gate_exists", "该子域名与路径前缀已被其他网关占用")
			return
		}
		if errors.Is(err, store.ErrUserNotFound) {
			s.writeError(w, http.StatusNotFound, "not_found", "指定的用户不存在")
			return
		}
		if err != nil {
			s.internalError(w, "update gate", err)
			return
		}
		session, _ := s.currentSession(r)
		s.logger.Info("admin updated gate", "name", gate.Name, "prefix", gate.ToPrefix, "by", session.Username)
		s.writeJSON(w, http.StatusOK, adminGateResponse{OK: true, Gate: adminGateDTO(*gate)})

	case http.MethodDelete:
		err := s.store.DeleteGate(r.Context(), id)
		if errors.Is(err, store.ErrGateNotFound) {
			s.writeError(w, http.StatusNotFound, "not_found", "网关不存在")
			return
		}
		if err != nil {
			s.internalError(w, "delete gate", err)
			return
		}
		session, _ := s.currentSession(r)
		s.logger.Info("admin deleted gate", "id", id, "by", session.Username)
		s.writeJSON(w, http.StatusOK, adminOKResponse{OK: true})

	default:
		s.methodNotAllowed(w, "PATCH, DELETE")
	}
}

// validateGateInput turns the store validators into user facing messages.
func validateGateInput(name, from, toPrefix, toSuffix string) string {
	if err := store.ValidateGateName(name); err != nil {
		return "名称不能为空，最多 50 个字符"
	}
	if err := store.ValidateGateFrom(from); err != nil {
		return "源地址格式不正确，例如 10.0.0.1:1234 或 http://10.0.0.1:1234"
	}
	if _, err := store.NormalizeGateToPrefix(toPrefix); err != nil {
		return "目标子域名只能包含字母、数字和连字符，或使用 * 通配"
	}
	if _, err := store.NormalizeGateToSuffix(toSuffix); err != nil {
		return "目标路径前缀不能包含空格，最长 255 个字符"
	}
	return ""
}
