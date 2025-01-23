package api

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/klauspost/compress/zstd"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/net/html"

	"github.com/sarumaj/kagi-proxy/pkg/common"
)

type Proxy struct {
	SessionCreatedAt time.Time
	SessionId        string
}

// Director is a function that modifies the request before it is sent.
// It injects a session token into the request if it is not already present.
// It also modifies the request to use the target host specified in the
// targetHostConfig.
func (Proxy) Director(req *http.Request) {
	// Modify the request to use the target host
	req.URL.Scheme = "https"
	common.Logger().Debug("Modifying request from director", zap.String("url", req.URL.String()))
	targetHost := common.ConfigProxyTargetHosts().Get(req.Host, "kagi.com")
	req.URL.Host, req.Host = targetHost, targetHost

	common.Logger().Debug("Proxying request", zap.String("url", req.URL.String()))
	if ValidateProxySession(req) {
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
func (Proxy) ErrorHandler(w http.ResponseWriter, r *http.Request, err error) {
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
	SetContentSecurityHeaders(w, nonce)
	w.Header().Set("Content-Type", gin.MIMEHTML)
	w.Header().Set("Retry-After", "30")
	w.WriteHeader(http.StatusServiceUnavailable)

	if err := HTMLTemplates().ExecuteTemplate(w, "error.html", map[string]any{
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
func (p Proxy) ModifyResponse(resp *http.Response) error {
	// Remove any existing CORS headers from origin
	resp.Header.Del("Access-Control-Allow-Origin")
	resp.Header.Del("Access-Control-Allow-Credentials")
	resp.Header.Del("Access-Control-Allow-Methods")
	resp.Header.Del("Access-Control-Allow-Headers")
	resp.Header.Del("Access-Control-Expose-Headers")
	resp.Header.Set("Permissions-Policy", "accelerometer=(), camera=(), geolocation=(), "+
		"gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()")

	// Ignore non-HTML content
	if contentType := resp.Header.Get("Content-Type"); resp.Body == nil || !strings.Contains(contentType, gin.MIMEHTML) {
		return nil
	}

	contentEncoding := strings.ToLower(resp.Header.Get("Content-Encoding"))
	common.Logger().Debug("Modifying response", zap.String("contentEncoding", contentEncoding))

	// Support decompression of the response
	var reader io.ReadCloser
	var err error
	switch contentEncoding {
	case "gzip":
		reader, err = gzip.NewReader(resp.Body)

	case "deflate":
		reader = flate.NewReader(resp.Body)

	case "br":
		reader = common.Closer(brotli.NewReader(resp.Body))

	case "zstd":
		reader, err = common.CloserWrap(zstd.NewReader(resp.Body))

	case "", "identity":
		reader = resp.Body

	default:
		common.Logger().Warn("Unknown content encoding", zap.String("encoding", contentEncoding))
		return fmt.Errorf("unknown content encoding: %s", contentEncoding)
	}

	if err != nil {
		common.Logger().Error("Failed to decompress response", zap.Error(err))
		return err
	}

	defer reader.Close()

	// Eat up the response body
	var body []byte
	if body, err = io.ReadAll(reader); err != nil {
		return err
	}

	// Extract the thread list from the response body
	threadListPattern := regexp.MustCompile(`thread_list\.json.(\[.*\])`)
	threadListPatternMatches := threadListPattern.FindSubmatch(body)

	var threads []Thread
	if len(threadListPatternMatches) > 1 {
		if err := json.Unmarshal(threadListPatternMatches[1], &threads); err != nil {
			common.Logger().Error("Failed to unmarshal thread list", zap.Error(err))
		} else {
			common.Logger().Debug("Discovered threads", zap.Int("threads", len(threads)))
		}
	}

	// Create volatile rules for threads created before the session
	var rules common.Ruleset
	seen := make(map[string]bool)
	for _, thread := range threads {
		// Track the tread in the session map
		if _, ok := SessionMap.Get(thread.ID); !ok {
			ttl := thread.ExpiresAt.Sub(thread.CreatedAt)
			if ttl < 0 {
				ttl = time.Hour * 24 * 7
			}

			// Whoever sees it first, owns it
			SessionMap.Set(thread.ID, ThreadInfo{
				ID:        thread.ID,
				CreatedAt: thread.CreatedAt,
				ExpiresAt: thread.ExpiresAt,
				SessionId: p.SessionId,
			}, ttl)
		}

		// Add rules for threads created before the session
		if thread.CreatedAt.Before(p.SessionCreatedAt) || thread.ExpiresAt.Before(p.SessionCreatedAt) {
			common.Logger().Debug("Thread created before session", zap.String("thread", thread.ID))
			rules = append(rules, common.Rule{Path: "/assistant/" + thread.ID, PathType: common.Prefix})
			seen[thread.ID] = true
		}
	}

	// Add rules for threads owned by someone else
	for _, item := range SessionMap.GetAll() {
		if threadInfo, ok := item.Value.(ThreadInfo); ok && threadInfo.SessionId != p.SessionId {
			for _, thread := range threads {
				if thread.ID == threadInfo.ID && !seen[thread.ID] {
					common.Logger().Debug("Thread owned by someone else",
						zap.String("thread", thread.ID),
						zap.String("owner", threadInfo.SessionId))
					rules = append(rules, common.Rule{Path: "/assistant/" + thread.ID, PathType: common.Prefix})
				}
			}
		}
	}

	if len(rules) > 0 {
		SessionMap.Set(p.SessionId, SessionInfo{
			SessionId: p.SessionId,
			CreatedAt: p.SessionCreatedAt,
			Rules:     rules,
		}, time.Hour*24*7)
		common.Logger().Debug("Session rules added", zap.Int("rules", len(rules)))
	}

	// Hash the proxy user to allow authentication over session link with the proxy_token query parameter
	hash, err := bcrypt.GenerateFromPassword([]byte(common.ConfigProxyUser()), 12)
	if err != nil {
		common.Logger().Error("Failed to hash proxy user", zap.Error(err))
		return err
	}

	// Generate the proxy script
	var script bytes.Buffer
	if err := TextTemplates().ExecuteTemplate(&script, "proxy.js", map[string]any{
		"forbidden_paths": append(
			common.ConfigProxyGuardRules(),
			common.QuickGet[SessionInfo](SessionMap, p.SessionId).Rules...,
		).RegexList(),
		"host_map":    common.ConfigProxyTargetHosts(),
		"proxy_token": common.B64URLNoPadding.EncodeToString(hash),
	}); err != nil {
		return err
	}

	// Modify the Content-Security-Policy header
	if csp := resp.Header.Get("Content-Security-Policy"); len(csp) > 0 {
		resp.Header.Set("Content-Security-Policy", modifyCSP(csp, script.Bytes()))
	}

	// Inject the proxy script into the response body
	reader = common.Closer(strings.NewReader(strings.Replace(
		string(body),
		"<head>",
		"<head>\n\t\t<script>"+script.String()+"</script>",
		1,
	)))

	// Re-compress the response body and attribute for the new content length
	var compressedContent bytes.Buffer
	var writer io.WriteCloser
	switch contentEncoding {
	case "gzip":
		writer = gzip.NewWriter(&compressedContent)

	case "deflate":
		writer, err = flate.NewWriter(&compressedContent, flate.BestSpeed)

	case "br":
		writer = brotli.NewWriter(&compressedContent)

	case "zstd":
		writer, err = zstd.NewWriter(&compressedContent)

	default:
		writer = common.Closer(&compressedContent)

	}

	if err != nil {
		return err
	}

	if _, err := io.Copy(writer, reader); err != nil {
		return err
	}

	_ = writer.Close()

	resp.Body = common.Closer(&compressedContent)
	resp.ContentLength = int64(compressedContent.Len())
	resp.Header.Set("Content-Length", strconv.Itoa(compressedContent.Len()))
	resp.TransferEncoding = nil // Remove chunked encoding since content length is known
	return nil
}

// modifyCSP modifies the Content-Security-Policy header to allow the proxy script.
// Furthermore, it whitelists the target hosts specified in the targetHostConfig.
func modifyCSP(csp string, scripts ...[]byte) string {
	// Generate hashes for the inline scripts
	hashes := make([]string, 0, len(scripts))
	for _, script := range scripts {
		hasher := sha256.New()
		_, _ = hasher.Write(script)
		hashes = append(hashes, "'sha256-"+base64.StdEncoding.EncodeToString(hasher.Sum(nil))+"'")
	}

	// Split the directives
	directives := strings.Split(csp, ";")
	modified := make([]string, 0, len(directives))

	// Helper to extend the directive values with the proxy domains
	extendDirective := func(directiveValues []string) (values []string) {
		for _, value := range directiveValues {
			values = append(values, value)

			// If value matches any of our target hosts, add corresponding proxy domain
			common.Logger().Debug("Checking for target host in directive value", zap.String("value", value))
			for proxyDomain, targetHost := range common.ConfigProxyTargetHosts() {
				if strings.Contains(value, targetHost) {
					if newValue := strings.ReplaceAll(value, targetHost, proxyDomain); newValue != value {
						values = append(values, newValue)
					}
				}
			}
		}

		return
	}

	// Flag whether the script-src directive is present
	scriptSrcFound := false

	// Iterate over the directives
	for _, directive := range directives {
		directive = strings.TrimSpace(directive)
		if directive == "" {
			continue
		}

		parts := strings.Fields(directive)
		if len(parts) < 1 {
			continue
		}

		directiveName := parts[0]
		directiveValues := parts[1:]

		switch directiveName {
		case "script-src", "script-src-elem":
			scriptSrcFound = true
			// include hashes and 'unsafe-inline' in script-src directive
			newValues := append(hashes, extendDirective(directiveValues)...)
			if !strings.Contains(strings.Join(newValues, " "), "'unsafe-inline'") {
				newValues = append(newValues, "'unsafe-inline'")
			}
			directiveValues = newValues

		case "default-src", "style-src", "img-src", "connect-src", "font-src",
			"frame-src", "media-src", "object-src", "manifest-src", "frame-ancestors":
			directiveValues = extendDirective(directiveValues)

		}

		// Rebuild the directive
		if len(directiveValues) > 0 {
			modified = append(modified, directiveName+" "+strings.Join(directiveValues, " "))
		} else {
			modified = append(modified, directiveName)
		}
	}

	if !scriptSrcFound { // Add script-src directive if it is missing
		modified = append(modified, strings.Join([]string{"script-src", strings.Join(hashes, " "), "'unsafe-inline'"}, " "))
	}

	return strings.Join(modified, "; ")
}

// ProxyPass is a middleware that proxies requests to the kagi.com and *.kagi.com servers.
// It also injects a session token into the request if it is not already present.
// It applies custom reverse proxy with mutation observer, CSP handling, and response compression.
func ProxyPass() gin.HandlerFunc {
	rootCAs, err := x509.SystemCertPool()
	if err != nil {
		common.Logger().Warn("Failed to load system root CAs", zap.Error(err))
		rootCAs = x509.NewCertPool()
	}

	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: rootCAs}}
	nopLogger := log.New(io.Discard, "", 0) // Disable logging
	reverseProxy := &httputil.ReverseProxy{
		Transport: transport,
		ErrorLog:  nopLogger, // Disable logging
	}
	proxy := &Proxy{}

	return func(ctx *gin.Context) {
		session := sessions.Default(ctx)
		proxy.SessionCreatedAt = time.Unix(common.QuickGet[int64](session, "created_at"), 0)
		proxy.SessionId = common.QuickGet[string](session, "session_id")

		// Either Director or Rewrite must be set
		reverseProxy.Director = proxy.Director
		reverseProxy.ErrorHandler = proxy.ErrorHandler
		reverseProxy.ModifyResponse = proxy.ModifyResponse

		reverseProxy.ServeHTTP(ctx.Writer, ctx.Request)
	}
}

// ValidateProxySession checks if the user is authenticated.
// It checks for a session token in the request query and cookie.
// It returns true if the session token is found and valid.
func ValidateProxySession(req *http.Request) bool {
	common.Logger().Debug("Checking for session token in request query", zap.String("url", req.URL.String()))
	targetHost := common.ConfigProxyTargetHosts().Get(req.Host, "kagi.com")

	token := req.URL.Query().Get("token")
	if len(token) > 0 && common.CTEqual(token, common.ConfigSessionToken()) {
		common.Logger().Debug("Session token found in request query", zap.String("sessionToken", token))
		return true
	}

	cookie, err := req.Cookie("kagi_session")
	common.Logger().Debug("Checking for session token in request cookie", zap.Error(err), zap.Reflect("cookie", cookie))
	switch {
	case err != nil, cookie == nil, len(cookie.Value) == 0, common.CTEqual(cookie.Value, common.ConfigSessionToken()),
		cookie.Domain != targetHost && cookie.Domain != "."+targetHost && len(cookie.Domain) != 0:

		return false
	}

	common.Logger().Debug("Session token found in request cookie", zap.String("sessionToken", cookie.Value))
	return true
}
