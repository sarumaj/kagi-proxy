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
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"strconv"
	"strings"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/gin-gonic/gin"
	"github.com/icholy/replace"
	"github.com/klauspost/compress/zstd"
	"go.uber.org/zap"
	"golang.org/x/net/html"

	"github.com/sarumaj/kagi-proxy/pkg/common"
)

// Director is a function that modifies the request before it is sent.
// It injects a session token into the request if it is not already present.
// It also modifies the request to use the target host specified in the
// targetHostConfig.
func Director(req *http.Request) {
	req.URL.Scheme = "https"
	targetHost := common.ConfigProxyTargetHosts().Get(req.Host, "kagi.com")
	req.URL.Host, req.Host = targetHost, targetHost

	common.Logger().Debug("Proxying request", zap.String("url", req.URL.String()))
	if ValidateProxySession(req) {
		return
	}

	common.Logger().Debug("Session cookie not found in request")

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
func ErrorHandler(w http.ResponseWriter, r *http.Request, err error) {
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

	nonce, err := GetNonce()
	if err != nil {
		common.Logger().Error("Failed to generate nonce", zap.Error(err))
	}

	SetContentSecurityHeaders(w, nonce)
	w.Header().Set("Content-Type", gin.MIMEHTML)
	w.Header().Set("Retry-After", "30")
	w.WriteHeader(http.StatusServiceUnavailable)

	if err := HTMLTemplates().ExecuteTemplate(w, "error.html", map[string]any{
		"error": html.EscapeString(err.Error()),
		"code":  http.StatusServiceUnavailable,
		"nonce": nonce,
	}); err != nil {
		common.Logger().Error("Failed to execute error template", zap.Error(err))
	}
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

	directives := strings.Split(csp, ";")
	modified := make([]string, 0, len(directives))

	// Helper to extend the directive values with the proxy domains
	extendDirective := func(directiveValues []string) (values []string) {
		for _, value := range directiveValues {
			values = append(values, value)

			// If value matches any of our target hosts, add corresponding proxy domain
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

	// Check if the script-src directive is present
	scriptSrcFound := false
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

	if !scriptSrcFound {
		modified = append(modified, strings.Join([]string{"script-src", strings.Join(hashes, " "), "'unsafe-inline'"}, " "))
	}

	return strings.Join(modified, "; ")
}

// ModifyResponse is a function that modifies the response before it is sent.
// It injects a script that proxies requests to the target hosts specified in
// the targetHostConfig.
func ModifyResponse(resp *http.Response) error {
	var script bytes.Buffer
	if err := TextTemplates().ExecuteTemplate(&script, "proxy.js", map[string]any{
		"host_map": common.ConfigProxyTargetHosts(),
	}); err != nil {
		return err
	}

	if csp := resp.Header.Get("Content-Security-Policy"); len(csp) > 0 {
		resp.Header.Set("Content-Security-Policy", modifyCSP(csp, script.Bytes()))
	}

	if contentType := resp.Header.Get("Content-Type"); resp.Body == nil || !strings.Contains(contentType, gin.MIMEHTML) {
		return nil
	}

	contentEncoding := strings.ToLower(resp.Header.Get("Content-Encoding"))
	common.Logger().Debug("Modifying response", zap.String("contentEncoding", contentEncoding))

	// Setup decompression
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

	// Chain the transformers
	reader = common.Closer(replace.Chain(reader, replace.String(`<head>`, "<head>\n\t\t<script>"+script.String()+"</script>")))

	// Compress the modified content
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
	resp.TransferEncoding = nil // Remove chunked encoding since we know the content length

	return nil
}

// ProxyPass is a middleware that proxies requests to the kagi.com and *.kagi.com servers.
func ProxyPass() gin.HandlerFunc {
	rootCAs, err := x509.SystemCertPool()
	if err != nil {
		common.Logger().Warn("Failed to load system root CAs", zap.Error(err))
		rootCAs = x509.NewCertPool()
	}

	proxy := &httputil.ReverseProxy{
		Transport:      &http.Transport{TLSClientConfig: &tls.Config{RootCAs: rootCAs}},
		ErrorLog:       log.New(io.Discard, "", 0),
		Director:       Director,
		ModifyResponse: ModifyResponse,
		ErrorHandler:   ErrorHandler,
	}

	return func(ctx *gin.Context) { proxy.ServeHTTP(ctx.Writer, ctx.Request) }
}

// ValidateProxySession checks if the user is authenticated.
func ValidateProxySession(req *http.Request) bool {
	targetHost := common.ConfigProxyTargetHosts().Get(req.Host, "kagi.com")

	token := req.URL.Query().Get("token")
	if len(token) > 0 && CTEqual(token, common.ConfigSessionToken()) {
		common.Logger().Debug("Session token found in request query", zap.String("sessionToken", token))
		return true
	}

	cookie, err := req.Cookie("kagi_session")
	common.Logger().Debug("Checking for session token in request cookie", zap.Error(err), zap.Reflect("cookie", cookie))
	switch {
	case err != nil, cookie == nil, len(cookie.Value) == 0, CTEqual(cookie.Value, common.ConfigSessionToken()),
		cookie.Domain != targetHost && cookie.Domain != "."+targetHost && len(cookie.Domain) != 0:

		return false
	}

	common.Logger().Debug("Session token found in request cookie", zap.String("sessionToken", cookie.Value))
	return true
}
