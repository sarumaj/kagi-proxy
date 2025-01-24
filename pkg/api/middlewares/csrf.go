package middlewares

import (
	"net/http"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/sarumaj/kagi-proxy/pkg/common"
	"github.com/sarumaj/kagi-proxy/pkg/common/web"
	csrf "github.com/utrack/gin-csrf"
)

// CSRF is a middleware that checks if the CSRF token is valid.
func CSRF() gin.HandlerFunc {
	return csrf.Middleware(csrf.Options{
		Secret: common.ConfigProxySessionSecret(),
		ErrorFunc: func(ctx *gin.Context) {
			session := sessions.Default(ctx)
			session.AddFlash("Invalid CSRF token")
			if !web.SessionSave(session, ctx) {
				return
			}

			common.Logger().Debug("Invalid CSRF token")
			ctx.Redirect(http.StatusSeeOther, ctx.Request.URL.Path)
			ctx.Abort()
		},
	})
}
