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

	"golang.org/x/net/html"

	"github.com/andybalholm/brotli"
	"github.com/gin-gonic/gin"
	"github.com/icholy/replace"
	"github.com/klauspost/compress/zstd"
	"go.uber.org/zap"

	"github.com/sarumaj/kagi/pkg/common"
)

// sessionProxy is a reverse proxy that injects a session token into requests
// and modifies the response to include a script that proxies requests to the
// target hosts.
type sessionProxy struct {
	SessionToken string
	TargetHosts  targetHostConfig
	*httputil.ReverseProxy
}

// Director is a function that modifies the request before it is sent.
// It injects a session token into the request if it is not already present.
// It also modifies the request to use the target host specified in the
// targetHostConfig.
func (p sessionProxy) Director(req *http.Request) {
	req.URL.Scheme = "https"
	targetHost := p.TargetHosts.Get(req.Host, "kagi.com")
	req.URL.Host, req.Host = targetHost, targetHost

	common.Logger.Debug("Proxying request", zap.String("url", req.URL.String()))

	switch cookie, err := req.Cookie("kagi_session"); {

	case len(req.URL.Query().Get("token")) > 0:
		common.Logger.Debug("Session token found in query string", zap.String("token", req.URL.Query().Get("token")))
		return // Skip session cookie injection if token is present in query string

	case err == nil &&
		cookie != nil &&
		len(cookie.Value) > 0 &&
		(cookie.Domain == targetHost || cookie.Domain == "."+targetHost || len(cookie.Domain) == 0):

		common.Logger.Debug("Session cookie found in request", zap.Reflect("cookie", cookie))
		return // Skip session cookie injection if session cookie is already present

	default:
		common.Logger.Debug("Session cookie not found in request")

	}

	req.AddCookie(&http.Cookie{
		Name:     "kagi_session",
		Value:    p.SessionToken,
		Expires:  time.Now().Add(time.Hour),
		Path:     "/",
		Domain:   targetHost,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	common.Logger.Debug("Session token added to request", zap.String("sessionToken", p.SessionToken), zap.Reflect("cookies", req.Cookies()))
}

// ErrorHandler is a function that handles errors that occur during the proxying process.
func (p sessionProxy) ErrorHandler(w http.ResponseWriter, r *http.Request, err error) {
	if err == nil {
		return
	}

	// Check if the client has already disconnected
	if err == context.Canceled {
		common.Logger.Warn("Client disconnected", zap.String("url", r.URL.String()), zap.Error(err))
		return
	}

	common.Logger.Error("Proxy error", zap.Error(err), zap.String("url", r.URL.String()))

	if len(w.Header().Get("Content-Type")) > 0 {
		common.Logger.Warn("Headers already sent, cannot modify response")
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Retry-After", "30")
	w.WriteHeader(http.StatusServiceUnavailable)

	if err := HTMLTemplates().ExecuteTemplate(w, "error.html", map[string]any{
		"error": html.EscapeString(err.Error()),
	}); err != nil {
		common.Logger.Error("Failed to execute error template", zap.Error(err))
	}
}

// modifyCSP modifies the Content-Security-Policy header to allow the proxy script.
// Furthermore, it whitelists the target hosts specified in the targetHostConfig.
func (p sessionProxy) modifyCSP(csp string, scripts ...[]byte) string {
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
			for proxyDomain, targetHost := range p.TargetHosts {
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
		modified = append(modified, fmt.Sprintf("script-src %s 'unsafe-inline'", strings.Join(hashes, " ")))
	}

	return strings.Join(modified, "; ")
}

// ModifyResponse is a function that modifies the response before it is sent.
// It injects a script that proxies requests to the target hosts specified in
// the targetHostConfig.
func (p sessionProxy) ModifyResponse(resp *http.Response) error {
	var script bytes.Buffer
	if err := TextTemplates().ExecuteTemplate(&script, "proxy.js", map[string]any{
		"host_map": p.TargetHosts,
	}); err != nil {
		return err
	}

	if csp := resp.Header.Get("Content-Security-Policy"); len(csp) > 0 {
		resp.Header.Set("Content-Security-Policy", p.modifyCSP(csp, script.Bytes()))
	}

	if contentType := resp.Header.Get("Content-Type"); resp.Body == nil || !strings.Contains(contentType, gin.MIMEHTML) {
		return nil
	}

	contentEncoding := strings.ToLower(resp.Header.Get("Content-Encoding"))

	// Setup decompression
	var reader io.Reader = resp.Body
	switch contentEncoding {
	case "gzip":
		common.Logger.Debug("Decoding gzip response")
		gzReader, err := gzip.NewReader(resp.Body)
		if err != nil {
			common.Logger.Error("Failed to create gzip reader", zap.Error(err))
			return err
		}
		defer gzReader.Close()
		reader = gzReader

	case "deflate":
		common.Logger.Debug("Decoding deflate response")
		reader = flate.NewReader(resp.Body)
		defer reader.(io.Closer).Close()

	case "br":
		common.Logger.Debug("Decoding brotli response")
		reader = brotli.NewReader(resp.Body)

	case "zstd":
		common.Logger.Debug("Decoding zstd response")
		zstdReader, err := zstd.NewReader(resp.Body)
		if err != nil {
			common.Logger.Error("Failed to create zstd reader", zap.Error(err))
			return err
		}
		defer zstdReader.Close()
		reader = zstdReader

	case "", "identity":
		// No transformation needed

	default:
		common.Logger.Warn("Unknown content encoding", zap.String("encoding", contentEncoding))
		return fmt.Errorf("unknown content encoding: %s", contentEncoding)
	}

	// Inject the proxy script into the head tag
	reader = replace.Chain(reader, replace.String(`<head>`, "<head>\n\t\t<script>"+script.String()+"</script>"))

	// Compress the modified content
	var compressedContent bytes.Buffer
	switch contentEncoding {
	case "gzip":
		gzWriter := gzip.NewWriter(&compressedContent)
		if _, err := io.Copy(gzWriter, reader); err != nil {
			return err
		}
		_ = gzWriter.Close()

	case "deflate":
		flateWriter, err := flate.NewWriter(&compressedContent, flate.BestSpeed)
		if err != nil {
			return err
		}
		if _, err := io.Copy(flateWriter, reader); err != nil {
			return err
		}
		_ = flateWriter.Close()

	case "br":
		brWriter := brotli.NewWriter(&compressedContent)
		if _, err := io.Copy(brWriter, reader); err != nil {
			return err
		}
		_ = brWriter.Close()

	case "zstd":
		zstdWriter, err := zstd.NewWriter(&compressedContent)
		if err != nil {
			return err
		}
		if _, err := io.Copy(zstdWriter, reader); err != nil {
			return err
		}
		_ = zstdWriter.Close()

	default:
		if _, err := io.Copy(&compressedContent, reader); err != nil {
			return err
		}

	}

	resp.Body = io.NopCloser(&compressedContent)
	resp.ContentLength = int64(compressedContent.Len())
	resp.Header.Set("Content-Length", strconv.Itoa(compressedContent.Len()))
	resp.TransferEncoding = nil // Remove chunked encoding since we know the content length

	return nil
}

// targetHostConfig is a map that maps proxy host names to target hosts.
type targetHostConfig map[string]string

// Get returns the target host for the given proxy host.
func (t targetHostConfig) Get(host, def string) string {
	if targetHost, ok := t[host]; ok {
		return targetHost
	}

	for hostPort, targetHost := range t {
		if strings.Split(hostPort, ":")[0] == host {
			return targetHost
		}
	}

	common.Logger.Warn("Target host not found", zap.String("host", host), zap.Reflect("targetHosts", t))

	if len(def) > 0 {
		return def
	}

	return "NXDOMAIN"
}

// ProxyPass is a middleware that proxies requests to the kagi.com and *.kagi.com servers.
func ProxyPass(targetHostConfig map[string]string, sessionToken string) gin.HandlerFunc {
	rootCAs, err := x509.SystemCertPool()
	if err != nil {
		common.Logger.Warn("Failed to load system root CAs", zap.Error(err))
		rootCAs = x509.NewCertPool()
	}

	proxy := &sessionProxy{
		SessionToken: sessionToken,
		ReverseProxy: &httputil.ReverseProxy{},
		TargetHosts:  targetHostConfig,
	}
	proxy.Transport = &http.Transport{TLSClientConfig: &tls.Config{RootCAs: rootCAs}}
	proxy.ErrorLog = log.New(io.Discard, "", 0)
	proxy.ReverseProxy.Director = proxy.Director
	proxy.ReverseProxy.ModifyResponse = proxy.ModifyResponse
	proxy.ReverseProxy.ErrorHandler = proxy.ErrorHandler

	return func(ctx *gin.Context) { proxy.ServeHTTP(ctx.Writer, ctx.Request) }
}
