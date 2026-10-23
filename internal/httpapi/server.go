// Package httpapi exposes the AuthDock HTTP surface: the login page, the
// admin-only authentication API and the management pages.
package httpapi

import (
	_ "embed" // for the //go:embed directive below
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/lyy1119/AuthDock/internal/store"
	"github.com/lyy1119/AuthDock/internal/webui"
)

//go:embed templates/login.html
var loginTemplate string

//go:embed templates/portal.html
var portalTemplate string

// DefaultSessionTTL is how long an admin stays signed in.
const DefaultSessionTTL = 12 * time.Hour

// Options configures New. Store is required; everything else falls back to a
// sensible default.
type Options struct {
	Store    *store.Store
	Sessions Sessions
	Limiter  *AttemptLimiter
	Logger   *slog.Logger
	Now      func() time.Time

	// NoDNCheck disables the gateway domain check on the user portal. It exists
	// for local debugging (the -no-dn-check flag) and must not be used in
	// production.
	NoDNCheck bool
}

type server struct {
	store    *store.Store
	sessions Sessions
	limiter  *AttemptLimiter
	logger   *slog.Logger
	now      func() time.Time

	loginPage  string
	portalPage string
	noDNCheck  bool

	// transportInsecure is the lazily built transport for https upstreams whose
	// certificate the gateway cannot verify.
	transportOnce     sync.Once
	transportInsecure *http.Transport
}

// New builds the management handler with all admin routes mounted.
func New(opts Options) http.Handler {
	s := newServer(opts)

	mux := http.NewServeMux()

	// Authentication.
	mux.HandleFunc("/api/auth/login", s.onlyMethod(http.MethodPost, s.handleLogin))
	mux.HandleFunc("/api/auth/logout", s.onlyMethod(http.MethodPost, s.handleLogout))
	mux.HandleFunc("/api/auth/session", s.onlyMethod(http.MethodGet, s.handleSession))

	// Management API.
	mux.HandleFunc("/api/admin/users", s.requireAdmin(s.handleAdminUsers))
	mux.HandleFunc("/api/admin/users/{id}", s.requireAdmin(s.handleAdminUser))
	mux.HandleFunc("/api/admin/settings", s.requireAdmin(s.handleAdminSettings))
	mux.HandleFunc("/api/admin/gates", s.requireAdmin(s.handleAdminGates))
	mux.HandleFunc("/api/admin/gates/{id}", s.requireAdmin(s.handleAdminGate))

	mux.HandleFunc("/api/", s.handleUnknownAPI)

	// Pages: the login form is served by this package, the management UI is the
	// embedded React bundle.
	mux.HandleFunc("/healthz", s.onlyMethod(http.MethodGet, s.handleHealth))
	mux.HandleFunc("/login", s.onlyMethod(http.MethodGet, s.handleLoginPage))
	mux.HandleFunc("/admin", s.handleAdminRoot)
	mux.Handle("/admin/", s.adminUI())
	mux.HandleFunc("/", s.handleIndex)

	return securityHeaders(mux)
}

// NewPortal builds the handler for the user facing portal. It is served on its
// own address (see -portal-addr) and only answers requests whose Host matches
// the gateway domain from the system settings.
func NewPortal(opts Options) http.Handler {
	s := newServer(opts)

	mux := http.NewServeMux()
	mux.HandleFunc("/", s.portalGuard(s.handlePortalPage))
	mux.HandleFunc("/login", s.portalGuard(s.handlePortalPage))
	mux.HandleFunc("/api/login", s.portalGuard(s.onlyMethod(http.MethodPost, s.handlePortalLogin)))
	mux.HandleFunc("/api/logout", s.portalGuard(s.onlyMethod(http.MethodPost, s.handlePortalLogout)))
	mux.HandleFunc("/api/session", s.portalGuard(s.onlyMethod(http.MethodGet, s.handlePortalSession)))
	mux.HandleFunc("/api/", s.portalGuard(s.handleUnknownAPI))
	mux.HandleFunc("/healthz", s.portalGuard(s.onlyMethod(http.MethodGet, s.handleHealth)))

	return securityHeaders(mux)
}

// newServer builds the shared state of a handler.
func newServer(opts Options) *server {
	if opts.Store == nil {
		panic("httpapi: Options.Store is required")
	}

	s := &server{
		store:     opts.Store,
		sessions:  opts.Sessions,
		limiter:   opts.Limiter,
		logger:    opts.Logger,
		now:       opts.Now,
		noDNCheck: opts.NoDNCheck,
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

	s.loginPage = loginTemplate
	s.portalPage = portalTemplate

	return s
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

// adminAuthorized reports whether the request holds a session whose account
// still exists and still has the admin role.
func (s *server) adminAuthorized(r *http.Request) bool {
	session, ok := s.currentSession(r)
	if !ok {
		return false
	}
	user, err := s.store.GetUserByUsername(r.Context(), session.Username)
	if err != nil {
		return false
	}
	return user.IsAdmin()
}

func (s *server) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	if s.adminAuthorized(r) {
		s.redirectRelative(w, "admin/")
		return
	}
	s.writeStandalonePage(w, r, s.loginPage)
}

// pageTheme resolves the colour scheme for a server rendered page.
func (s *server) pageTheme(r *http.Request) string {
	theme, err := s.store.Setting(r.Context(), store.SettingsKeyTheme)
	if err != nil {
		return store.DefaultTheme
	}
	normalized, err := store.NormalizeTheme(theme)
	if err != nil {
		return store.DefaultTheme
	}
	return normalized
}

// writeStandalonePage renders one of the self contained pages with the current
// colour scheme. "auto" is left to the CSS media query, so the page follows the
// operating system without any script.
func (s *server) writeStandalonePage(w http.ResponseWriter, r *http.Request, template string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = io.WriteString(w, strings.ReplaceAll(template, "{{THEME}}", s.pageTheme(r)))
}

// handleIndex sends visitors to the management area or the login page.
func (s *server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		s.methodNotAllowed(w, "GET")
		return
	}
	if !s.adminAuthorized(r) {
		s.redirectRelative(w, "login")
		return
	}
	s.redirectRelative(w, "admin/")
}

// handleAdminRoot serves the bare /admin path.
func (s *server) handleAdminRoot(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		s.methodNotAllowed(w, "GET")
		return
	}
	if !s.adminAuthorized(r) {
		s.redirectRelative(w, "login")
		return
	}
	s.redirectRelative(w, "admin/")
}

// adminUI serves the embedded single-page app under /admin/.
//
// Hashed assets are public: they carry no data and the browser needs them
// before it can ask for anything else. Everything else is the app shell, which
// requires an admin session.
func (s *server) adminUI() http.Handler {
	spa := http.StripPrefix("/admin", webui.Handler())

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			s.methodNotAllowed(w, "GET, HEAD")
			return
		}
		if !strings.HasPrefix(r.URL.Path, "/admin/assets/") && !s.adminAuthorized(r) {
			s.redirectRelative(w, "../login")
			return
		}
		spa.ServeHTTP(w, r)
	})
}

func (s *server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("ok\n"))
}

func (s *server) handleUnknownAPI(w http.ResponseWriter, _ *http.Request) {
	s.writeError(w, http.StatusNotFound, "not_found", "unknown endpoint")
}

// bearerToken returns the token of an "Authorization: Bearer <token>" header.
// Native clients use this instead of the browser cookie.
func bearerToken(r *http.Request) string {
	const prefix = "bearer "
	header := r.Header.Get("Authorization")
	if len(header) <= len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return ""
	}
	return strings.TrimSpace(header[len(prefix):])
}

// sessionFor resolves a session from one of the cookies or from a bearer token,
// always within the given scope.
func (s *server) sessionFor(r *http.Request, scope SessionScope, cookieNames ...string) (Session, bool) {
	for _, name := range cookieNames {
		cookie, err := r.Cookie(name)
		if err != nil {
			continue
		}
		if session, ok := s.sessions.Get(scope, cookie.Value, s.now()); ok {
			return session, true
		}
	}
	if token := bearerToken(r); token != "" {
		if session, ok := s.sessions.Get(scope, token, s.now()); ok {
			return session, true
		}
	}
	return Session{}, false
}

// currentSession resolves the management session. Only the management cookie
// (or a management bearer token) and the admin scope are accepted: a portal
// session must never unlock /admin.
func (s *server) currentSession(r *http.Request) (Session, bool) {
	return s.sessionFor(r, ScopeAdmin, SessionCookieName)
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
// Pages use inline scripts and stylesheets, so the policy allows
// 'unsafe-inline' for scripts and styles. Pages reflect no request data and the
// app is meant to be self-hosted on a trusted origin.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy",
			"default-src 'none'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "+
				"img-src 'self' data:; font-src 'self' data:; connect-src 'self'; "+
				"form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}
