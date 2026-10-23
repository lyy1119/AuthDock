package httpapi

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
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

// errUpstreamRedirectLoop reports an upstream redirect that cannot end well:
// either the browser is sent back to the address it just asked for (an endless
// bounce) or a plain HTTP request is answered with "use HTTPS" for the same
// address (a loop as well, because the gateway keeps speaking HTTP upstream).
var errUpstreamRedirectLoop = errors.New("httpapi: upstream redirect loop")

// pageThemeCSS is the shared palette of the gateway's own small pages. It mirrors
// the portal so the two look like one product in light and dark mode.
const pageThemeCSS = "body{margin:0;min-height:100vh;display:grid;place-items:center;padding:1.5rem;" +
	"font-family:system-ui,-apple-system,'PingFang SC','Microsoft YaHei',sans-serif;background:var(--bg);color:var(--text)}" +
	":root{--bg:#eef3f7;--card:#fff;--border:#e0e8ee;--text:#16232b;--muted:#6b7c88;--accent:#2f6fa8;--panel:#f4f8fb}" +
	":root[data-theme='dark']{--bg:#121820;--card:#1a2129;--border:#2a343d;--text:#e7edf3;--muted:#93a3b0;--accent:#5b9bd5;--panel:#172029}" +
	"@media (prefers-color-scheme: dark){:root[data-theme='auto']{--bg:#121820;--card:#1a2129;--border:#2a343d;" +
	"--text:#e7edf3;--muted:#93a3b0;--accent:#5b9bd5;--panel:#172029}}"

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
		// The portal reports the gateway session, never the management one.
		s.onlyMethod(http.MethodGet, s.handlePortalSession)(w, r)
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
	if !found {
		// Whether the address belongs to another account or to nobody is
		// deliberately indistinguishable to the visitor: telling them "this
		// belongs to someone else" would disclose the routes of other accounts.
		if matchedAny {
			s.logger.Warn("gateway address belongs to another account",
				"host", requestHost(r), "path", r.URL.Path, "user", user.Username)
		} else {
			s.logger.Warn("gateway address has no gate",
				"host", requestHost(r), "path", r.URL.Path, "user", user.Username)
		}
		s.writeNoRoutePage(w, r, domain, user)
		return
	}

	s.logger.Info("gateway forwarding", "gate", gate.Name, "user", user.Username,
		"host", requestHost(r), "path", r.URL.Path, "upstream", gate.From)
	s.proxyGate(w, r, *gate, rest)
}

// writeNoRoutePage is the single answer for "this address does not resolve for
// you": the same page and status whether the address belongs to another account
// or to nobody, so visitors cannot enumerate the routes of other accounts. It
// offers a way back to the portal, which lists what this account can reach.
func (s *server) writeNoRoutePage(w http.ResponseWriter, r *http.Request, domain string, user *store.User) {
	portalURL := fmt.Sprintf("%s://%s/", requestProto(r), domain)
	account := "(未登录)"
	if user != nil {
		account = user.Username
	}

	body := "<!DOCTYPE html><html lang=\"zh-CN\" data-theme=\"" + s.pageTheme(r) + "\"><head><meta charset=\"utf-8\">" +
		"<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">" +
		"<title>这个地址暂时不可用</title><style>" +
		pageThemeCSS +
		"main{width:min(100%,34rem);padding:1.75rem;background:var(--card);border:1px solid var(--border);border-radius:14px}" +
		"h1{margin:0 0 .6rem;font-size:1.15rem}p{margin:.4rem 0;line-height:1.7}" +
		".muted{color:var(--muted);font-size:.9rem}" +
		".actions{margin-top:1.2rem;display:flex;gap:.6rem;flex-wrap:wrap}" +
		".button{display:inline-block;padding:.55rem 1.1rem;font-size:.95rem;font-weight:600;text-decoration:none;" +
		"color:#fff;background:var(--accent);border-radius:9px}" +
		".button.ghost{color:var(--accent);background:transparent;border:1px solid var(--accent)}" +
		"code{background:var(--panel);padding:.1rem .35rem;border-radius:4px}</style></head><body><main>" +
		"<h1>这个地址暂时不可用</h1>" +
		"<p>当前账号 <code>" + html.EscapeString(account) + "</code> 没有通往 " +
		"<code>" + html.EscapeString(requestAuthority(r)+r.URL.RequestURI()) + "</code> 的网关。</p>" +
		"<p class=\"muted\">如果你认为这不应该发生，请联系管理员为你的账号添加对应的网关规则。</p>" +
		"<div class=\"actions\">" +
		"<a class=\"button\" href=\"" + html.EscapeString(portalURL) + "\">返回登录状态页</a>" +
		"<a class=\"button ghost\" href=\"" + html.EscapeString(portalURL+"login") + "\">换一个账号登录</a>" +
		"</div></main></body></html>"

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNotFound)
	_, _ = io.WriteString(w, body)
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

// gatewaySession resolves the gateway session from its cookie or from a bearer
// token, always in the gateway scope, so an administrator signed in at the
// management port is still anonymous here.
func (s *server) gatewaySession(r *http.Request) (Session, bool) {
	return s.sessionFor(r, ScopeGateway, gatewayCookieSecureName, gatewayCookiePlainName)
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

// returnToCookie remembers where an unauthenticated visitor was heading. The
// query parameter alone is fragile: a proxy may drop it and a page restored from
// a tab may lose it. The cookie keeps the bounce working.
const returnToCookieName = "gateway_return_to"

func (s *server) setReturnToCookie(w http.ResponseWriter, r *http.Request, domain, target string) {
	if target == "" {
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     returnToCookieName,
		Value:    target,
		Path:     "/",
		Domain:   domain,
		MaxAge:   600,
		HttpOnly: true,
		Secure:   isSecureRequest(r),
		SameSite: http.SameSiteLaxMode,
	})
}

func (s *server) clearReturnToCookie(w http.ResponseWriter, r *http.Request, domain string) {
	cookie := &http.Cookie{
		Name:     returnToCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   isSecureRequest(r),
		SameSite: http.SameSiteLaxMode,
	}
	if domain != "" {
		cookie.Domain = domain
	}
	http.SetCookie(w, cookie)
}

func (s *server) returnToCookie(r *http.Request) string {
	cookie, err := r.Cookie(returnToCookieName)
	if err != nil {
		return ""
	}
	return cookie.Value
}

// redirectToLogin sends the visitor to the portal, remembering where they were.
func (s *server) redirectToLogin(w http.ResponseWriter, r *http.Request, domain string) {
	loginHost := domain
	if loginHost == "" {
		loginHost = requestHost(r)
	}
	target := originalURL(r)
	s.setReturnToCookie(w, r, domain, target)

	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, fmt.Sprintf("%s://%s/login?return_to=%s",
		requestProto(r), loginHost, url.QueryEscape(target)), http.StatusFound)
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
	return requestProto(r) + "://" + requestAuthority(r) + r.URL.RequestURI()
}

// requestAuthority is the host[:port] the browser used. A reverse proxy may have
// rewritten Host to its upstream address, so X-Forwarded-Host wins when present;
// unlike requestHost it keeps the port, because it is used in URLs.
func requestAuthority(r *http.Request) string {
	if forwarded := r.Header.Get("X-Forwarded-Host"); forwarded != "" {
		return strings.TrimSpace(strings.Split(forwarded, ",")[0])
	}
	return r.Host
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
	publicBase := fmt.Sprintf("%s://%s", requestProto(r), requestAuthority(r))
	publicURL := publicBase + r.URL.RequestURI()

	hostMode, insecure := s.upstreamOptions(r)
	var transport http.RoundTripper
	if insecure {
		transport = s.insecureTransport()
	}

	proxy := &httputil.ReverseProxy{
		Transport: transport,
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme = upstream.Scheme
			pr.Out.URL.Host = upstream.Host
			if hostMode == store.UpstreamHostPreserve {
				// Opt-in: forward the public Host, for an upstream that picks its
				// virtual host from this header.
				pr.Out.Host = requestAuthority(r)
			} else {
				// Default: the address we dial. Most application servers validate
				// the Host they are reached by and reject a foreign one.
				pr.Out.Host = upstream.Host
			}
			// Keep the upstream's own base path, then the forwarded remainder.
			joined, escaped := joinUpstreamPath(upstream.Path, rest, restEscaped)
			pr.Out.URL.Path = joined
			pr.Out.URL.RawPath = escaped
			pr.SetXForwarded()
			stripOwnCookies(pr.Out.Header)
		},
		ModifyResponse: func(resp *http.Response) error {
			dropOwnSetCookies(resp)
			if redirectsNowhere(resp, publicURL) {
				resp.Body.Close()
				return errUpstreamRedirectLoop
			}
			rewriteLocation(resp, upstream, publicBase)
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			if errors.Is(err, errUpstreamRedirectLoop) {
				s.logger.Warn("gateway upstream redirects to itself",
					"gate", gate.Name, "upstream", gate.From, "public", publicURL)
				s.writeRedirectLoopPage(w, r, gate, publicURL)
				return
			}
			s.logger.Warn("gateway upstream failed", "gate", gate.Name, "upstream", gate.From, "err", err)
			http.Error(w, "502 bad gateway: "+err.Error(), http.StatusBadGateway)
		},
	}
	proxy.ServeHTTP(w, r)
}

// upstreamOptions loads the two settings that shape how the gateway talks to an
// upstream service.
func (s *server) upstreamOptions(r *http.Request) (hostMode string, insecure bool) {
	ctx := r.Context()

	hostMode, _ = s.store.Setting(ctx, store.SettingsKeyUpstreamHost)
	if normalized, err := store.NormalizeUpstreamHost(hostMode); err == nil {
		hostMode = normalized
	} else {
		hostMode = store.DefaultUpstreamHost
	}

	value, err := s.store.Setting(ctx, store.SettingsKeyUpstreamInsecure)
	return hostMode, err == nil && value == "1"
}

// insecureTransport is the cached transport used for https upstreams with a
// certificate the gateway cannot verify (Caddy "tls internal", self signed).
func (s *server) insecureTransport() http.RoundTripper {
	s.transportOnce.Do(func() {
		s.transportInsecure = &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   10 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          64,
			MaxIdleConnsPerHost:   8,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: time.Second,
			TLSClientConfig:       &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // opt-in for internal CAs
		}
	})
	return s.transportInsecure
}

// redirectsNowhere reports a redirect that would loop. Two shapes are caught:
//
//   - the target is the address the visitor just asked for, so the browser
//     bounces straight back into the gateway;
//   - a plain HTTP request is answered with an HTTPS redirect for the same host
//     and path, which is an HTTP-only port answering an HTTPS-only service. The
//     gateway would keep speaking HTTP, so this loops too.
func redirectsNowhere(resp *http.Response, publicURL string) bool {
	if resp.StatusCode < 300 || resp.StatusCode >= 400 {
		return false
	}
	location := resp.Header.Get("Location")
	if location == "" || resp.Request == nil {
		return false
	}
	target, err := url.Parse(location)
	if err != nil {
		return false
	}
	resolved := resp.Request.URL.ResolveReference(target)
	requested := resp.Request.URL

	if resolved.Scheme == "https" && requested.Scheme == "http" &&
		strings.EqualFold(resolved.Host, requested.Host) &&
		resolved.EscapedPath() == requested.EscapedPath() {
		return true
	}

	public, err := url.Parse(publicURL)
	if err != nil {
		return false
	}
	return strings.EqualFold(resolved.Host, public.Host) &&
		resolved.EscapedPath() == public.EscapedPath() &&
		resolved.RawQuery == public.RawQuery
}

// writeRedirectLoopPage explains the loop instead of letting the browser spin.
func (s *server) writeRedirectLoopPage(w http.ResponseWriter, r *http.Request, gate store.Gate, publicURL string) {
	body := "<!DOCTYPE html><html lang=\"zh-CN\" data-theme=\"" + s.pageTheme(r) + "\"><head><meta charset=\"utf-8\">" +
		"<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">" +
		"<title>上游重定向形成循环</title><style>" +
		pageThemeCSS +
		"main{width:min(100%,38rem);padding:1.75rem;background:var(--card);border:1px solid var(--border);border-radius:14px}" +
		"h1{margin:0 0 .6rem;font-size:1.15rem}p,li{line-height:1.7}.muted{color:var(--muted);font-size:.9rem}" +
		"code{background:var(--panel);padding:.1rem .35rem;border-radius:4px}</style></head><body><main>" +
		"<h1>上游把请求重定向回了同一个地址</h1>" +
		"<p>网关把请求转发给 <code>" + html.EscapeString(gate.From) + "</code> 时，上游返回了一个指向 " +
		"<code>" + html.EscapeString(publicURL) + "</code> 的重定向，浏览器会一直循环下去。</p>" +
		"<p class=\"muted\">最常见的原因是：上游服务（例如另一个 Caddy）只提供 HTTPS，" +
		"而网关是用 HTTP 访问它的，于是上游把 HTTP 强制跳转到 HTTPS。</p>" +
		"<p>解决办法（任选其一）：</p><ul>" +
		"<li>把这条网关的源地址改成 <code>https://…</code> 形式；</li>" +
		"<li>如果上游用的是自签或内部 CA 证书（Caddy 的 <code>tls internal</code>），" +
		"到「系统设置」里打开「跳过上游 HTTPS 证书校验」；</li>" +
		"<li>或者让上游在这个端口上直接提供 HTTP 服务。</li></ul>" +
		"<p class=\"muted\">网关：<code>" + html.EscapeString(gate.Name) + "</code>　源：<code>" +
		html.EscapeString(gate.From) + "</code></p>" +
		"</main></body></html>"

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusBadGateway)
	_, _ = io.WriteString(w, body)
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
