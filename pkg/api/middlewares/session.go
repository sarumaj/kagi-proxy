package middlewares

import (
	"net/http"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/sarumaj/kagi-proxy/pkg/common"
)

// Session is a middleware that manages the session.
// It sets the session cookie with the domain and secret.
// If the domain is empty, it will log a fatal error.
// If the secret is at least 64 bytes, it setup an AES-GCM encryption.
func Session() gin.HandlerFunc {
	domain := common.ConfigProxyTargetHosts().Base()
	if len(domain) == 0 {
		common.Logger().Fatal("domain is required")
	}

	hashKey, blockKey := common.MakeKeyPair([]byte(common.ConfigSessionToken()))
	store := cookie.NewStore(hashKey, blockKey)
	store.Options(sessions.Options{
		Domain: domain, // Required to support wildcard subdomains
		Path:   "/",
		// 0: session cookie until the browser is closed, -1: delete the cookie, math.MaxInt32: 68 years
		MaxAge:   int(common.ConfigProxySessionDuration().Seconds()),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	return sessions.Sessions("proxy_session", store)
}
