package middlewares

import (
	"net/http"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sarumaj/kagi-proxy/pkg/common"
	"github.com/sarumaj/kagi-proxy/pkg/common/web"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

// BasicAuth is a middleware that checks if the user is authenticated.
// It skips authentication for the paths in ConfigProxyGuardPolicy().WhiteList.
// It seeks the proxy_token query parameter to authenticate the user.
// Otherwise, it seeks the user session.
// If the user is not authenticated, it redirects to the login page.
func BasicAuth() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		if common.ConfigProxyPublicDomains().Contains(ctx.Request.Host) ||
			common.ConfigProxyGuardPolicy().Allow.Evaluate(ctx.Request, common.Deny) == common.Allow {

			common.Logger().Debug("Skipping basic auth authentication",
				zap.String("url", ctx.Request.URL.String()),
				zap.String("host", ctx.Request.Host))
			ctx.Next()
			return
		}

		// Seek the proxy_token query parameter
		session := sessions.Default(ctx)
		if token := ctx.Query("proxy_token"); len(token) > 0 {
			common.Logger().Debug("User provided token", zap.String("token", token))
			if hash, err := common.B64URLNoPadding.DecodeString(token); err != nil {
				common.Logger().Error("failed to decode token", zap.Error(err))
			} else if err := bcrypt.CompareHashAndPassword(hash, []byte(common.ConfigProxyUser())); err != nil {
				common.Logger().Error("hash mismatched", zap.Error(err))
			} else {
				common.Logger().Debug("User authenticated with token")

				// Establish or overwrite the user session
				session.Set("user", common.ConfigProxyUser())
				sessionId, _ := uuid.NewRandom()
				session.Set("session_id", sessionId.String())
				session.Set("created_at", time.Now().Unix())
				if !web.SessionSave(session, ctx) {
					return
				}

				// Dispose the proxy_token query parameter
				q := ctx.Request.URL.Query()
				q.Del("proxy_token")
				ctx.Request.URL.RawQuery = q.Encode()

				ctx.Next()
				return
			}
		}

		// Seek the user session
		if user := session.Get("user"); user == nil {
			common.Logger().Debug("User not authenticated")
			session.Set("redirect_url", ctx.Request.URL.String())
			if !web.SessionSave(session, ctx) {
				return
			}

			ctx.Redirect(http.StatusSeeOther, common.ConfigProxyRedirectLoginURL())
			ctx.Abort()
			return
		}

		common.Logger().Debug("User authenticated with session")
		ctx.Next()
	}
}

// ProxyGuard is a middleware that checks if the request is allowed.
// It evaluates ABAC rules to authorize the request.
// It uses the ConfigProxyGuardPolicy().BlackList for evaluation.
func ProxyGuard() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		if common.ConfigProxyPublicDomains().Contains(ctx.Request.Host) ||
			common.ConfigProxyGuardPolicy().Deny.Evaluate(ctx.Request, common.Allow) == common.Allow {

			common.Logger().Debug("Skipping guard policy",
				zap.String("url", ctx.Request.URL.String()),
				zap.String("host", ctx.Request.Host))
			ctx.Next()
			return
		}

		common.Logger().Debug("Request denied", zap.String("url", ctx.Request.URL.String()))
		nonce, _ := common.GetNonce()
		web.SetContentSecurityHeaders(ctx.Writer, nonce)
		ctx.HTML(http.StatusForbidden, "error.html", gin.H{
			"code":  http.StatusForbidden,
			"csp":   ctx.Writer.Header().Get("Content-Security-Policy"),
			"error": nil,
			"nonce": nonce,
		})
		ctx.Abort()
	}
}
