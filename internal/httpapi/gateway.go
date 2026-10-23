package httpapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/lyy1119/AuthDock/internal/store"
)

// The gateway is what sits behind Caddy: Caddy terminates TLS and forwards
// plain HTTP here, and this handler decides, per request, whether it is the
// login portal (apex host) or a published service (subdomain).

const (
	// gatewayCookieSecureName carries the session on HTTPS.
	gatewayCookieSecureName = "__Secure-gateway_session"
	// gatewayCookiePlainName is the fallback used over plain HTTP, because
	// browsers drop a __Secure- cookie that is not sent over TLS.
	gatewayCookiePlainName = "gateway_session"
)

// gatewayOwnedCookies lists the cookie names AuthDock owns. They are stripped
// before a request goes upstream and any upstream attempt to set them is
// dropped, so a published service can neither read nor overwrite the session.
var gatewayOwnedCookies = map[string]bool{
	gatewayCookieSecureName: true,
	gatewayCookiePlainName:  true,
	SessionCookieName:       true,
}

type gatewayDomainKey struct{}

// withGatewayDomain records the configured gateway domain on the request.
func withGatewayDomain(r *http.Request, domain string) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), gatewayDomainKey{}, domain))
}

func gatewayDomainFrom(r *http.Request) string {
	domain, _ := r.Context().Value(gatewayDomainKey{}).(string)
	return domain
}

// NewGateway builds the handler that Caddy proxies to. It serves the login
// portal when the Host is the gateway domain itself and forwards published
// services for every subdomain of it.
func NewGateway(opts Options) http.Handler {
	s := newServer(opts)
	return securityHeaders(http.HandlerFunc(s.serveGateway))
}

func (s *server) serveGateway(w http.ResponseWriter, r *http.Request) {
	domain, err := s.store.Setting(r.Context(), store.SettingsKeyGatewayDomain)
	if err != nil {
		s.logger.Error("read gateway domain", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	domain = strings.ToLower(strings.TrimSpace(domain))
	host := requestHost(r)

	// Debug mode: any host is accepted, and any path that is not a portal path is
	// treated as a gate lookup so the proxy can be exercised without DNS.
	if s.noDNCheck {
		if isPortalPath(r.URL.Path) {
			s.servePortalRoutes(w, r, domain)
			return
		}
		s.serveGatedRequest(w, r, firstLabel(host), domain)
		return
	}

	if domain == "" {
		s.refusePortal(w, r, "the gateway domain is not configured in the system settings")
		return
	}

	switch {
	case host == domain:
		s.servePortalRoutes(w, r, domain)
	case strings.HasSuffix(host, "."+domain):
		s.serveGatedRequest(w, r, firstLabel(host), domain)
	default:
		s.refusePortal(w, r, fmt.Sprintf("host %q is not part of the gateway domain %q", host, domain))
	}
}

func isPortalPath(path string) bool {
	switch path {
	case "/", "/login", "/api/login", "/api/logout", "/api/session":
		return true
	}
	return false
}

func firstLabel(host string) string {
	if index := strings.IndexByte(host, '.'); index >= 0 {
		return host[:index]
	}
	return host
}

// servePortalRoutes answers the login portal: the page itself plus the session
// endpoints.
func (s *server) servePortalRoutes(w http.ResponseWriter, r *http.Request, domain string) {
	r = withGatewayDomain(r, domain)

	switch r.URL.Path {
	case "/", "/login":
		s.handlePortalPage(w, r)
	case "/api/login":
		s.onlyMethod(http.MethodPost, s.handlePortalLogin)(w, r)
	case "/api/logout":
		s.onlyMethod(http.MethodPost, s.handlePortalLogout)(w, r)
	case "/api/session":
		s.onlyMethod(http.MethodGet, s.handleSession)(w, r)
	default:
		http.NotFound(w, r)
	}
}

// serveGatedRequest authenticates the visitor and forwards to the upstream the
// signed-in account routes to. Two accounts may publish the same public address
// and still reach different upstreams.
func (s *server) serveGatedRequest(w http.ResponseWriter, r *http.Request, prefix, domain string) {
	session, ok := s.gatewaySession(r)
	if !ok {
		s.redirectToLogin(w, r, domain)
		return
	}

	user, err := s.store.GetUserByUsername(r.Context(), session.Username)
	if err != nil {
		// The account vanished (or the database is unreachable): force a login.
		s.clearGatewayCookie(w, r, domain)
		s.redirectToLogin(w, r, domain)
		return
	}

	candidates, err := s.store.GatesForRoute(r.Context(), prefix)
	if err != nil {
		s.logger.Error("resolve gate", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	gate, rest, found, matchedAny := chooseGate(candidates, r.URL.Path, user.ID)
	switch {
	case found:
		s.logger.Info("gateway forwarding", "gate", gate.Name, "user", user.Username,
			"host", requestHost(r), "path", r.URL.Path, "upstream", gate.From)
		s.proxyGate(w, r, *gate, rest)
	case matchedAny:
		// The address exists but belongs to another account.
		http.Error(w, "403 forbidden: this address is not available to your account", http.StatusForbidden)
	default:
		http.NotFound(w, r)
	}
}

// chooseGate picks the gate for this visitor: an account scoped gate wins over a
// global one, and the store already ordered candidates by specificity.
func chooseGate(candidates []store.Gate, path string, userID int64) (gate *store.Gate, rest string, found, matchedAny bool) {
	var globalGate *store.Gate
	var globalRest string

	for i := range candidates {
		candidate := &candidates[i]
		candidateRest, ok := candidate.MatchPath(path)
		if !ok {
			continue
		}
		matchedAny = true

		if candidate.UserID == nil {
			if globalGate == nil {
				globalGate, globalRest = candidate, candidateRest
			}
			continue
		}
		if *candidate.UserID == userID {
			return candidate, candidateRest, true, true
		}
	}
	if globalGate != nil {
		return globalGate, globalRest, true, matchedAny
	}
	return nil, "", false, matchedAny
}

// gatewaySession resolves the session carried by the request at the gateway.
func (s *server) gatewaySession(r *http.Request) (Session, bool) {
	return s.currentSession(r)
}

func (s *server) setGatewayCookie(w http.ResponseWriter, r *http.Request, domain, token string, expires time.Time) {
	secure := isSecureRequest(r)
	name := gatewayCookiePlainName
	if secure {
		name = gatewayCookieSecureName
	}
	cookie := &http.Cookie{
		Name:     name,
		Value:    token,
		Path:     "/",
		Expires:  expires,
		MaxAge:   int(s.sessions.TTL().Seconds()),
		HttpOnly: true,
		Secure:   secure,
		// Lax rather than Strict: a Strict cookie would make a visitor arriving
		// from an external link look signed out on the first request.
		SameSite: http.SameSiteLaxMode,
	}
	if domain != "" {
		// Sharing the cookie with subdomains is what makes per account routing
		// work: the app host must be able to see the session.
		cookie.Domain = domain
	}
	http.SetCookie(w, cookie)
}

func (s *server) clearGatewayCookie(w http.ResponseWriter, r *http.Request, domain string) {
	secure := isSecureRequest(r)
	for _, name := range []string{gatewayCookieSecureName, gatewayCookiePlainName} {
		cookie := &http.Cookie{
			Name:     name,
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			HttpOnly: true,
			Secure:   secure,
			SameSite: http.SameSiteLaxMode,
		}
		if domain != "" {
			cookie.Domain = domain
		}
		http.SetCookie(w, cookie)
	}
}

// redirectToLogin sends the visitor to the portal, remembering where they were.
func (s *server) redirectToLogin(w http.ResponseWriter, r *http.Request, domain string) {
	loginHost := domain
	if loginHost == "" {
		loginHost = requestHost(r)
	}
	target := fmt.Sprintf("%s://%s/login?return_to=%s",
		requestProto(r), loginHost, url.QueryEscape(originalURL(r)))
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, target, http.StatusFound)
}

func requestProto(r *http.Request) string {
	if forwarded := r.Header.Get("X-Forwarded-Proto"); forwarded != "" {
		return strings.TrimSpace(strings.Split(forwarded, ",")[0])
	}
	if r.TLS != nil {
		return "https"
	}
	return "http"
}

// originalURL is the address the browser asked for, used as return_to.
func originalURL(r *http.Request) string {
	return requestProto(r) + "://" + r.Host + r.URL.RequestURI()
}

// validateReturnTo only accepts addresses inside the gateway domain, which keeps
// the login page from becoming an open redirect.
func validateReturnTo(raw, domain string) string {
	if raw == "" || domain == "" {
		return ""
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" {
		return ""
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return ""
	}
	if parsed.User != nil {
		return ""
	}
	host := strings.ToLower(parsed.Hostname())
	if host != domain && !strings.HasSuffix(host, "."+domain) {
		return ""
	}
	return parsed.String()
}

// ── proxying ────────────────────────────────────────────────────────────

// proxyGate forwards the request upstream with AuthDock's cookies removed.
func (s *server) proxyGate(w http.ResponseWriter, r *http.Request, gate store.Gate, rest string) {
	upstream, err := upstreamURL(gate.From)
	if err != nil {
		s.logger.Error("bad upstream address", "gate", gate.Name, "from", gate.From, "err", err)
		http.Error(w, "502 bad gateway: invalid upstream address", http.StatusBadGateway)
		return
	}

	rest, restEscaped := splitEscapedRest(gate, r)
	publicBase := fmt.Sprintf("%s://%s", requestProto(r), r.Host)

	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme = upstream.Scheme
			pr.Out.URL.Host = upstream.Host
			pr.Out.Host = upstream.Host
			// Keep the upstream's own base path, then the forwarded remainder.
			joined, escaped := joinUpstreamPath(upstream.Path, rest, restEscaped)
			pr.Out.URL.Path = joined
			pr.Out.URL.RawPath = escaped
			pr.SetXForwarded()
			stripOwnCookies(pr.Out.Header)
		},
		ModifyResponse: func(resp *http.Response) error {
			dropOwnSetCookies(resp)
			rewriteLocation(resp, upstream, publicBase)
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			s.logger.Warn("gateway upstream failed", "gate", gate.Name, "upstream", gate.From, "err", err)
			http.Error(w, "502 bad gateway", http.StatusBadGateway)
		},
	}
	proxy.ServeHTTP(w, r)
}

// upstreamURL normalises the stored address into a URL; a bare host:port means
// plain http.
func upstreamURL(from string) (*url.URL, error) {
	candidate := from
	if !strings.Contains(candidate, "://") {
		candidate = "http://" + candidate
	}
	parsed, err := url.Parse(candidate)
	if err != nil {
		return nil, err
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, errors.New("unsupported scheme")
	}
	if parsed.Host == "" {
		return nil, errors.New("missing host")
	}
	return parsed, nil
}

// splitEscapedRest trims the public path prefix from both the decoded and the
// escaped path so percent-encoding survives the hop.
func splitEscapedRest(gate store.Gate, r *http.Request) (rest, restEscaped string) {
	prefix := gate.RoutePrefix()
	if prefix == "" {
		return r.URL.Path, r.URL.EscapedPath()
	}
	prefixEscaped := (&url.URL{Path: prefix}).EscapedPath()

	path := r.URL.Path
	escaped := r.URL.EscapedPath()
	switch {
	case path == prefix:
		return "/", "/"
	case strings.HasPrefix(path, prefix+"/"):
		return strings.TrimPrefix(path, prefix), strings.TrimPrefix(escaped, prefixEscaped)
	}
	return "/", "/"
}

// joinUpstreamPath builds the upstream path from its own base path and the
// remainder of the public path. The escaped form is only kept when it really
// differs, otherwise Go re-encodes the decoded path.
func joinUpstreamPath(upstreamBase, rest, restEscaped string) (string, string) {
	base := strings.TrimSuffix(upstreamBase, "/")
	joined := base + "/" + strings.TrimPrefix(rest, "/")
	escaped := strings.TrimSuffix((&url.URL{Path: base}).EscapedPath(), "/") + "/" +
		strings.TrimPrefix(restEscaped, "/")
	if (&url.URL{Path: joined}).EscapedPath() == escaped {
		return joined, ""
	}
	return joined, escaped
}

// stripOwnCookies removes AuthDock's cookies from a request bound for an
// upstream service.
func stripOwnCookies(header http.Header) {
	values := header.Values("Cookie")
	if len(values) == 0 {
		return
	}

	kept := make([]string, 0, 8)
	for _, value := range values {
		for _, part := range strings.Split(value, ";") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			name := part
			if index := strings.IndexByte(part, '='); index >= 0 {
				name = part[:index]
			}
			if gatewayOwnedCookies[strings.TrimSpace(name)] {
				continue
			}
			kept = append(kept, part)
		}
	}

	header.Del("Cookie")
	if len(kept) > 0 {
		header.Set("Cookie", strings.Join(kept, "; "))
	}
}

// dropOwnSetCookies discards upstream attempts to set AuthDock's cookie names.
func dropOwnSetCookies(resp *http.Response) {
	values := resp.Header.Values("Set-Cookie")
	if len(values) == 0 {
		return
	}

	kept := make([]string, 0, len(values))
	for _, value := range values {
		name := value
		if index := strings.IndexByte(name, '='); index >= 0 {
			name = name[:index]
		}
		if gatewayOwnedCookies[strings.TrimSpace(name)] {
			continue
		}
		kept = append(kept, value)
	}

	resp.Header.Del("Set-Cookie")
	for _, value := range kept {
		resp.Header.Add("Set-Cookie", value)
	}
}

// rewriteLocation points upstream redirects back at the public address instead of
// leaking the internal one.
func rewriteLocation(resp *http.Response, upstream *url.URL, publicBase string) {
	location := resp.Header.Get("Location")
	if location == "" {
		return
	}
	parsed, err := url.Parse(location)
	if err != nil || parsed.Host == "" || parsed.Host != upstream.Host {
		return
	}
	public, err := url.Parse(publicBase)
	if err != nil {
		return
	}
	parsed.Scheme, parsed.Host = public.Scheme, public.Host
	resp.Header.Set("Location", parsed.String())
}
