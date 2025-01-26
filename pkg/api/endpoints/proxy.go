package endpoints

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
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
	case err != nil, cookie == nil, len(cookie.Value) == 0, common.CTEqual(cookie.Value, common.ConfigSessionToken()),
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

	if err := templates.HTMLTemplates().ExecuteTemplate(w, "error.html", map[string]any{
		"csp":   w.Header().Get("Content-Security-Policy"),
		"code":  http.StatusServiceUnavailable,
		"error": html.EscapeString(err.Error()),
		"nonce": nonce,
	}); err != nil {
		common.Logger().Fatal("Failed to execute error template", zap.Error(err))
	}
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
			Config:       retryConfig,
			RoundTripper: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: rootCAs}},
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
