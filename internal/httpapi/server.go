// Package httpapi exposes the AuthDock HTTP surface: the login page and the
// admin authentication API.
package httpapi

import (
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"time"

	"github.com/lyy1119/AuthDock/internal/store"
)

//go:embed templates/*.html
var templateFS embed.FS

// DefaultSessionTTL is how long an admin stays signed in.
const DefaultSessionTTL = 12 * time.Hour

// Options configures New. Store is required; everything else falls back to a
// sensible default.
type Options struct {
	Store    *store.Store
	Sessions *SessionStore
	Limiter  *AttemptLimiter
	Logger   *slog.Logger
	Now      func() time.Time
}

type server struct {
	store    *store.Store
	sessions *SessionStore
	limiter  *AttemptLimiter
	logger   *slog.Logger
	now      func() time.Time

	loginPage []byte
	adminTmpl *template.Template
}

// New builds the AuthDock handler with all routes mounted.
func New(opts Options) http.Handler {
	if opts.Store == nil {
		panic("httpapi: Options.Store is required")
	}

	s := &server{
		store:    opts.Store,
		sessions: opts.Sessions,
		limiter:  opts.Limiter,
		logger:   opts.Logger,
		now:      opts.Now,
	}
	if s.sessions == nil {
		s.sessions = NewSessionStore(DefaultSessionTTL)
	}
	if s.limiter == nil {
		s.limiter = NewAttemptLimiter(5, time.Minute, 15*time.Minute)
	}
	if s.logger == nil {
		s.logger = slog.Default()
	}
	if s.now == nil {
		s.now = time.Now
	}

	loginPage, err := templateFS.ReadFile("templates/login.html")
	if err != nil {
		panic("httpapi: read embedded login page: " + err.Error())
	}
	s.loginPage = loginPage

	adminTmpl, err := template.ParseFS(templateFS, "templates/admin.html")
	if err != nil {
		panic("httpapi: parse embedded admin page: " + err.Error())
	}
	s.adminTmpl = adminTmpl

	mux := http.NewServeMux()
	mux.HandleFunc("/api/auth/login", s.onlyMethod(http.MethodPost, s.handleLogin))
	mux.HandleFunc("/api/auth/logout", s.onlyMethod(http.MethodPost, s.handleLogout))
	mux.HandleFunc("/api/auth/session", s.onlyMethod(http.MethodGet, s.handleSession))
	mux.HandleFunc("/api/", s.handleUnknownAPI)
	mux.HandleFunc("/healthz", s.onlyMethod(http.MethodGet, s.handleHealth))
	mux.HandleFunc("/login", s.onlyMethod(http.MethodGet, s.handleLoginPage))
	mux.HandleFunc("/", s.handleIndex)

	return securityHeaders(mux)
}

// onlyMethod wraps a handler so that a request with another HTTP method is
// answered with 405 instead of falling through to the catch-all route.
func (s *server) onlyMethod(method string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != method && !(method == http.MethodGet && r.Method == http.MethodHead) {
			w.Header().Set("Allow", method)
			s.writeError(w, http.StatusMethodNotAllowed, "method_not_allowed",
				fmt.Sprintf("该接口只接受 %s 请求", method))
			return
		}
		next(w, r)
	}
}

// redirectRelative answers with a 303 whose Location is a relative reference.
// http.Redirect cannot be used here: it resolves relative targets against the
// request path, which is the path the *server* sees. Reverse proxies that mount
// the app under a prefix (code-server serves it at /proxy/<port>/, for example)
// usually strip that prefix, so the browser must resolve the target itself
// against the URL it actually requested.
func (s *server) redirectRelative(w http.ResponseWriter, target string) {
	w.Header().Set("Location", target)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusSeeOther)
	_, _ = w.Write([]byte("redirecting to " + target + "\n"))
}

func (s *server) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.currentSession(r); ok {
		s.redirectRelative(w, "./")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(s.loginPage)
}

// handleIndex serves the admin area placeholder. The real admin UI is not
// designed yet, so this only proves the session works.
func (s *server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET")
		s.writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "该页面只接受 GET 请求")
		return
	}
	session, ok := s.currentSession(r)
	if !ok {
		s.redirectRelative(w, "login")
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := s.adminTmpl.Execute(w, map[string]any{"Username": session.Username}); err != nil {
		s.logger.Error("render admin page", "err", err)
	}
}

func (s *server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("ok\n"))
}

func (s *server) handleUnknownAPI(w http.ResponseWriter, _ *http.Request) {
	s.writeError(w, http.StatusNotFound, "not_found", "unknown endpoint")
}

// currentSession resolves the session token carried by the request.
func (s *server) currentSession(r *http.Request) (Session, bool) {
	cookie, err := r.Cookie(SessionCookieName)
	if err != nil {
		return Session{}, false
	}
	return s.sessions.Get(cookie.Value, s.now())
}

func (s *server) setSessionCookie(w http.ResponseWriter, r *http.Request, token string, expires time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    token,
		Path:     "/",
		Expires:  expires,
		MaxAge:   int(s.sessions.TTL().Seconds()),
		HttpOnly: true,
		Secure:   isSecureRequest(r),
		SameSite: http.SameSiteStrictMode,
	})
}

func (s *server) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
}

// isSecureRequest reports whether the browser reached us over TLS. A reverse
// proxy terminating TLS should forward X-Forwarded-Proto.
func isSecureRequest(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	return r.Header.Get("X-Forwarded-Proto") == "https"
}

func (s *server) writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		s.logger.Error("write json response", "err", err)
	}
}

// writeError sends the uniform error envelope used by every API endpoint.
func (s *server) writeError(w http.ResponseWriter, status int, code, message string) {
	s.writeJSON(w, status, errorResponse{OK: false, Code: code, Message: message})
}

// securityHeaders applies conservative defaults to every response.
//
// The login page uses an inline script and stylesheet, so the policy allows
// 'unsafe-inline' for scripts and styles. The page reflects no request data and
// the app is meant to be self-hosted on a trusted origin.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy",
			"default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "+
				"connect-src 'self'; img-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}
