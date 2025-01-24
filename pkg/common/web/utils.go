package web

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/andybalholm/brotli"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/klauspost/compress/zstd"
	"github.com/sarumaj/kagi-proxy/pkg/common"
	"go.uber.org/zap"
	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
)

// CompressResponseBody compresses the response body using the appropriate compression algorithm.
func CompressResponseBody(resp *http.Response) error {
	var compressedContent bytes.Buffer
	var writer io.WriteCloser
	var err error
	switch contentEncoding := strings.ToLower(resp.Header.Get("Content-Encoding")); contentEncoding {
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

	if _, err := io.Copy(writer, resp.Body); err != nil {
		return err
	}

	_ = writer.Close()
	resp.Body = common.Closer(&compressedContent)
	resp.ContentLength = int64(compressedContent.Len())
	resp.Header.Set("Content-Length", strconv.Itoa(compressedContent.Len()))
	resp.TransferEncoding = nil // Remove chunked encoding since content length is known
	return nil
}

// DecompressResponseBody decompresses the response body using the appropriate decompression algorithm.
func DecompressResponseBody(resp *http.Response) error {
	var reader io.ReadCloser
	var err error
	switch contentEncoding := strings.ToLower(resp.Header.Get("Content-Encoding")); contentEncoding {
	case "gzip":
		reader, err = gzip.NewReader(resp.Body)

	case "deflate":
		reader = flate.NewReader(resp.Body)

	case "br":
		reader = common.Closer(brotli.NewReader(resp.Body))

	case "zstd":
		reader, err = common.CloserWrap(zstd.NewReader(resp.Body))

	case "", "identity":
		return nil

	default:
		return fmt.Errorf("unknown content encoding: %s", contentEncoding)
	}

	if err != nil {
		return err
	}

	resp.Body = reader
	return nil
}

// InjectJsScript injects a JavaScript script into the HTML response body.
// It injects the script after the <head> tag or before the </body> tag.
// The location of the script is determined by the first occurrence of the <head> or </body> tag.
func InjectJsScript(response *http.Response, data io.Reader) (bool, error) {
	var buffer bytes.Buffer
	tokenizer := html.NewTokenizer(response.Body)
	tokenInjected := false

	inject := func() {
		_, _ = buffer.WriteString(html.Token{
			Type: html.StartTagToken,
			Data: atom.Script.String(),
			Attr: []html.Attribute{
				{Key: "type", Val: "text/javascript"},
			},
		}.String())
		_, _ = buffer.ReadFrom(data)
		_, _ = buffer.WriteString(html.Token{
			Type: html.EndTagToken,
			Data: atom.Script.String(),
		}.String())
		tokenInjected = true
	}

	for {
		tokenType := tokenizer.Next()
		if tokenType == html.ErrorToken {
			err := tokenizer.Err()
			if err == io.EOF {
				break
			}

			return false, err
		}

		token := tokenizer.Token()
		if !tokenInjected {
			switch {
			case tokenType == html.StartTagToken && token.DataAtom == atom.Head:
				_, _ = buffer.WriteString(token.String())
				inject()
				continue

			case tokenType == html.EndTagToken && token.DataAtom == atom.Body:
				inject()
				_, _ = buffer.WriteString(token.String())
				tokenInjected = true
				continue
			}
		}

		_, _ = buffer.Write(tokenizer.Raw())
	}

	response.Body = common.Closer(&buffer)
	return tokenInjected, nil
}

// ModifyCSP modifies the Content-Security-Policy header to allow the proxy scripts.
// Furthermore, it whitelists the target hosts specified in ConfigProxyTargetHosts.
func ModifyCSP(csp string, scripts ...[]byte) string {
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

// SessionSave saves the session and handles any errors that occur.
// If an error occurs, it displays an error page and aborts the request.
// It returns true if the session is saved successfully.
func SessionSave(session sessions.Session, ctx *gin.Context) (success bool) {
	if err := session.Save(); err != nil {
		common.Logger().Error("failed to save session", zap.Error(err))
		nonce, _ := common.GetNonce()
		SetContentSecurityHeaders(ctx.Writer, nonce)
		ctx.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"code":  http.StatusInternalServerError,
			"csp":   ctx.Writer.Header().Get("Content-Security-Policy"),
			"error": html.EscapeString(err.Error()),
			"nonce": nonce,
		})
		ctx.Abort()
	}

	return !ctx.IsAborted()
}

// SetContentSecurityHeaders sets the Content-Security-Policy, X-Frame-Options, and X-Content-Type-Options headers.
// It uses the nonce to set the script-src and style-src directives.
func SetContentSecurityHeaders(w http.ResponseWriter, nonce string) {
	w.Header().Set("Content-Security-Policy", strings.Join([]string{
		"default-src 'none'",
		"script-src 'self' 'nonce-" + nonce + "'",
		"style-src 'self' 'nonce-" + nonce + "'",
		"img-src 'self' data:",
		"connect-src 'self'",
		"form-action 'self'",
		"base-uri 'none'",
		"font-src 'self'",
		"manifest-src 'self'",
		"object-src 'none'",
		"child-src 'none'",
		"worker-src 'none'",
		"upgrade-insecure-requests",
	}, "; "))
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-Content-Type-Options", "nosniff")
}
