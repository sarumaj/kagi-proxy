package endpoints

import (
	"bytes"
	"context"
	"crypto/x509"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/sarumaj/kagi-proxy/pkg/api/templates"
	"github.com/sarumaj/kagi-proxy/pkg/common"
	"github.com/sarumaj/kagi-proxy/pkg/common/web"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/net/html"
)

type (
	// ProxyState preserves the state of the proxy handler.
	ProxyState struct {
		// RetryConfig is the configuration for retrying requests.
		RetryConfig web.RetryConfig
		// SessionCreatedAt is the time the session was created.
		SessionCreatedAt time.Time
		// SessionId is the session ID.
		SessionId string
	}
)

// forwardedHeaders are the hop metadata headers added by this proxy and by the
// platform routing layer in front of it (Heroku's router, in the reference
// deployment). Forwarding them upstream advertises that the request travelled
// through an intermediary and leaks the client address, so they are dropped.
var forwardedHeaders = []string{
	"Connect-Time",
	"Forwarded",
	"Total-Route-Time",
	"Via",
	"X-Client-Ip",
	"X-Forwarded-Host",
	"X-Forwarded-Port",
	"X-Forwarded-Proto",
	"X-Forwarded-Server",
	"X-Real-Ip",
	"X-Request-Id",
	"X-Request-Start",
}

// proxyCookies are cookie names owned by the proxy itself. They carry no meaning
// for the target host and identify the request as proxied, so they are removed
// from the outgoing Cookie header.
var proxyCookies = []string{"proxy_session"}

// rewriteURLHeader maps the host of an absolute-URL request header (Referer,
// Origin) from the proxy domain onto the corresponding target host, leaving the
// scheme, path and query intact. A header that is absent, empty or unparsable is
// left untouched rather than replaced with a synthesised value.
func rewriteURLHeader(req *http.Request, name string) {
	value := req.Header.Get(name)
	if len(value) == 0 {
		return
	}

	parsed, err := url.Parse(value)
	if err != nil || len(parsed.Host) == 0 {
		common.Logger().Debug("Dropping unparsable URL header", zap.String("header", name), zap.String("value", value))
		req.Header.Del(name)
		return
	}

	targetHost := common.ConfigProxyTargetHosts().Get(parsed.Hostname(), "")
	if targetHost == "NXDOMAIN" {
		// The header points somewhere the proxy does not serve. Forwarding a
		// third-party origin verbatim is correct; a browser would do the same.
		return
	}

	parsed.Host = targetHost
	req.Header.Set(name, parsed.String())
	common.Logger().Debug("Rewrote URL header", zap.String("header", name), zap.String("value", parsed.String()))
}

// stripProxyCookies rebuilds the outgoing Cookie header without the proxy's own
// cookies. Request cookies carry no attributes, so the expiry trick that works on
// Set-Cookie only appends a second copy of the cookie here.
func stripProxyCookies(req *http.Request) {
	cookies := req.Cookies()
	req.Header.Del("Cookie")
	for _, cookie := range cookies {
		if slices.Contains(proxyCookies, cookie.Name) {
			common.Logger().Debug("Removing proxy cookie from request", zap.String("name", cookie.Name))
			continue
		}

		req.AddCookie(&http.Cookie{Name: cookie.Name, Value: cookie.Value})
	}
}

// Director is a function that modifies the request before it is sent.
// It injects a session token into the request if it is not already present.
// It also modifies the request to use the target host specified in the
// targetHostConfig.
func (p ProxyState) Director(req *http.Request) {
	// Modify the request to use the target host
	req.URL.Scheme = "https"
	common.Logger().Debug("Modifying request from director", zap.String("url", req.URL.String()))
	targetHost := common.ConfigProxyTargetHosts().Get(req.Host, "kagi.com")
	req.URL.Host, req.Host = targetHost, targetHost

	// Fix trailing quote in URL path
	pattern := regexp.MustCompile(`^(.*)(?:\/)?(?:"|%22)$`)
	if pattern.MatchString(req.URL.Path) {
		req.URL.Path = pattern.ReplaceAllString(req.URL.Path, "$1")
		common.Logger().Debug("Modified request URL path to remove trailing quote", zap.String("newPath", req.URL.Path))
	}

	// Rewrite the Referer and Origin headers so that they carry the target host
	// instead of the proxy host. Both are absolute URLs, not bare host names, and a
	// header the browser did not send must stay absent: browsers omit Origin on
	// top-level navigations, so synthesising one marks the request as non-browser.
	rewriteURLHeader(req, "Referer")
	rewriteURLHeader(req, "Origin")

	// Strip the hop metadata added by this proxy and by the platform in front of it.
	// X-Forwarded-For is set to nil rather than deleted: httputil.ReverseProxy treats a
	// nil entry as "do not append the client IP" (golang/go#38079), while a plain Del
	// would let it re-add the header after the director returns.
	req.Header["X-Forwarded-For"] = nil
	for _, header := range forwardedHeaders {
		req.Header.Del(header)
	}

	// Cookies scoped to the proxy itself must never reach the target host.
	stripProxyCookies(req)

	// Apply form data rules
	for _, rule := range common.ConfigProxyGuardPolicy().Override {
		if ok, err := rule.PatchForm(req); err != nil {
			common.Logger().Error("Failed to apply form data rule", zap.Reflect("rule", rule), zap.Error(err))
		} else {
			common.Logger().Debug("Applying form data rule", zap.Reflect("rule", rule), zap.Bool("patched", ok))
		}
	}

	common.Logger().Debug("Proxying request", zap.String("url", req.URL.String()))

	// Verify the session token
	common.Logger().Debug("Checking for session token in request query", zap.String("url", req.URL.String()))
	token := req.URL.Query().Get("token")
	if len(token) > 0 && common.CTEqual(token, common.ConfigSessionToken()) {
		common.Logger().Debug("Session token found in request query", zap.String("sessionToken", token))
		return
	}

	cookie, err := req.Cookie("kagi_session")
	common.Logger().Debug("Checking for session token in request cookie", zap.Error(err), zap.Reflect("cookie", cookie))
	switch {
	case err != nil, cookie == nil, len(cookie.Value) == 0,
		cookie.Domain != targetHost && cookie.Domain != "."+targetHost && len(cookie.Domain) != 0:

	default:
		common.Logger().Debug("Session token found in request cookie", zap.String("sessionToken", cookie.Value))
		return
	}

	common.Logger().Debug("Session cookie not found in request")

	// Establish a session
	req.AddCookie(&http.Cookie{
		Name:     "kagi_session",
		Value:    common.ConfigSessionToken(),
		Expires:  time.Now().Add(time.Hour),
		Path:     "/",
		Domain:   targetHost,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	common.Logger().Debug("Session token added to request",
		zap.String("sessionToken", common.ConfigSessionToken()),
		zap.Reflect("cookies", req.Cookies()))
}

// ErrorHandler is a function that handles errors that occur during the proxying process.
func (ProxyState) ErrorHandler(w http.ResponseWriter, r *http.Request, err error) {
	if err == nil {
		return
	}

	// Check if the client has already disconnected
	if err == context.Canceled {
		common.Logger().Warn("Client disconnected", zap.String("url", r.URL.String()), zap.Error(err))
		return
	}

	common.Logger().Error("Proxy error", zap.Error(err), zap.String("url", r.URL.String()))

	if len(w.Header().Get("Content-Type")) > 0 {
		common.Logger().Warn("Headers already sent, cannot modify response")
		return
	}

	nonce, _ := common.GetNonce()
	web.SetContentSecurityHeaders(w, nonce)
	w.Header().Set("Content-Type", gin.MIMEHTML)
	w.Header().Set("Retry-After", "30")
	w.WriteHeader(http.StatusServiceUnavailable)

	common.FatalOnError("Failed to execute error template", templates.HTMLTemplates().ExecuteTemplate(w, "error.html", map[string]any{
		"csp":   w.Header().Get("Content-Security-Policy"),
		"code":  http.StatusServiceUnavailable,
		"error": html.EscapeString(err.Error()),
		"nonce": nonce,
	}))
}

// ModifyResponse is a function that modifies the response before it is sent.
// It injects a script that proxies requests to the target hosts specified in
// the targetHostConfig.
func (p ProxyState) ModifyResponse(resp *http.Response) error {
	// Remove original CORS headers
	resp.Header.Del("Access-Control-Allow-Origin")
	resp.Header.Del("Access-Control-Allow-Credentials")
	resp.Header.Del("Access-Control-Allow-Methods")
	resp.Header.Del("Access-Control-Allow-Headers")
	resp.Header.Del("Access-Control-Expose-Headers")
	resp.Header.Del("Access-Control-Max-Age")

	// Remove Permissions-Policy header to disable privacy-related features
	resp.Header.Del("Permissions-Policy")

	// Re-scope the cookies issued by the target host onto the proxy domain. A browser
	// silently discards a Set-Cookie whose Domain does not match the host it is talking
	// to, so without this every cookie kagi.com sets is lost and the upstream sees an
	// unconvincing client that never carries its own state back.
	web.RewriteSetCookieDomains(resp)

	// Ignore non-HTML content
	if contentType := resp.Header.Get("Content-Type"); resp.Body == nil || !strings.Contains(contentType, gin.MIMEHTML) {
		return nil
	}

	defer resp.Body.Close()

	// Support decompression of the response
	if err := web.DecompressResponseBody(resp); err != nil {
		common.Logger().Error("Failed to decompress response body", zap.Error(err))
		return err
	}

	// Hash the proxy user to allow authentication over session link with the proxy_token query parameter
	hash, err := bcrypt.GenerateFromPassword([]byte(common.ConfigProxyUser()), 12)
	if err != nil {
		common.Logger().Error("Failed to hash proxy user", zap.Error(err))
		return err
	}

	// Generate the proxy script
	var script bytes.Buffer
	if err := templates.TextTemplates().ExecuteTemplate(&script, "proxy.js", map[string]any{
		"forbidden_elements": common.ConfigProxyGuardPolicy().Override.JsSelectors(),
		"forbidden_paths":    common.ConfigProxyGuardPolicy().Deny.RegexList(),
		"host_map":           common.ConfigProxyTargetHosts().Reverse(),
		"proxy_token":        common.B64URLNoPadding.EncodeToString(hash),
		"retry_config":       p.RetryConfig,
	}); err != nil {
		return err
	}

	// Modify the Content-Security-Policy header
	if csp := resp.Header.Get("Content-Security-Policy"); len(csp) > 0 {
		resp.Header.Set("Content-Security-Policy", web.ModifyCSP(csp, script.Bytes()))
	}

	// Inject the proxy script into the response body
	injected, err := web.InjectJsScript(resp, &script)
	if err != nil {
		common.Logger().Error("Failed to inject proxy script", zap.Error(err))
		return err
	}
	common.Logger().Debug("Proxy script injected", zap.Bool("injected", injected))

	// Re-compress the response body and attribute for the new content length
	if err := web.CompressResponseBody(resp); err != nil {
		common.Logger().Error("Failed to compress response body", zap.Error(err))
		return err
	}

	return nil
}

// Proxy is an endpoint handler that proxies requests to the kagi.com and *.kagi.com servers.
// It also injects a session token into the request if it is not already present.
// It applies custom reverse proxy with mutation observer, CSP handling, and response compression.
func Proxy() gin.HandlerFunc {
	// Root CAs are required for the proxy to establish a secure connection to the target host
	rootCAs, err := x509.SystemCertPool()
	if err != nil {
		common.Logger().Warn("Failed to load system root CAs", zap.Error(err))
		rootCAs = x509.NewCertPool()
	}

	retryConfig := web.RetryConfig{
		MaxRetries: 3,
		RetryDelay: time.Second,
		RetryCodes: []int{http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout},
	}

	reverseProxy := &httputil.ReverseProxy{
		Transport: &web.RetryTransport{
			Config: retryConfig,
			// The upstream connection must be indistinguishable from a browser's at both
			// layers: a Chrome-shaped TLS ClientHello, and HTTP/2 rather than the HTTP/1.1
			// that Go otherwise falls back to whenever TLSClientConfig is set.
			RoundTripper: web.NewBrowserTransport(rootCAs),
		},
		ErrorLog: log.New(io.Discard, "", 0), // Prevent log flooding
	}

	return func(ctx *gin.Context) {
		proxyState := &ProxyState{RetryConfig: retryConfig}

		session := sessions.Default(ctx)
		proxyState.SessionCreatedAt = time.Unix(common.QuickGet[int64](session, "created_at"), 0)
		proxyState.SessionId = common.QuickGet[string](session, "session_id")

		// Either Director or Rewrite must be set
		reverseProxy.Director = proxyState.Director
		reverseProxy.ErrorHandler = proxyState.ErrorHandler
		reverseProxy.ModifyResponse = proxyState.ModifyResponse

		// Serve the request
		reverseProxy.ServeHTTP(ctx.Writer, ctx.Request)
	}
}
