package api

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httputil"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sarumaj/kagi/pkg/common"
	"go.uber.org/zap"
)

// ProxyPass is a middleware that proxies requests to the kagi.com server.
func ProxyPass(sessionToken string) gin.HandlerFunc {
	rootCAs, err := x509.SystemCertPool()
	if err != nil {
		common.Logger.Warn("Failed to load system root CAs", zap.Error(err))
		rootCAs = x509.NewCertPool()
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:    rootCAs,
			ServerName: "kagi.com",
		},
	}

	director := func(req *http.Request) {
		req.URL.Scheme = "https"
		req.URL.Host = "kagi.com"
		req.Host = "kagi.com"

		common.Logger.Debug("Proxying request", zap.String("url", req.URL.String()))

		sessionEstablished := req.URL.Query().Has("token")
		if !sessionEstablished {
			cookie, err := req.Cookie("kagi_session")
			sessionEstablished = err == nil && cookie != nil && cookie.Value != "" && cookie.Expires.After(time.Now())
		}

		common.Logger.Debug("Session established", zap.Bool("sessionEstablished", sessionEstablished))

		if sessionEstablished {
			return
		}

		req.AddCookie(&http.Cookie{
			Name:     "kagi_session",
			Value:    sessionToken,
			Expires:  time.Now().Add(time.Hour),
			Path:     "/",
			Domain:   "kagi.com",
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		})

		common.Logger.Debug("Session token added to request", zap.String("sessionToken", sessionToken), zap.Reflect("cookies", req.Cookies()))
	}

	proxy := &httputil.ReverseProxy{
		Transport: transport,
		Director:  director,
	}

	return func(ctx *gin.Context) { proxy.ServeHTTP(ctx.Writer, ctx.Request) }
}
