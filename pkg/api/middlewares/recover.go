package middlewares

import (
	"fmt"
	"html"
	"net/http"

	ginzap "github.com/gin-contrib/zap"
	"github.com/gin-gonic/gin"
	"github.com/sarumaj/kagi-proxy/pkg/common"
	"github.com/sarumaj/kagi-proxy/pkg/common/web"
)

// Recover is a middleware that recovers from panics.
// It logs the error and returns a 500 Internal Server Error.
func Recover() gin.HandlerFunc {
	return ginzap.CustomRecoveryWithZap(common.Logger(), true, func(ctx *gin.Context, err any) {
		nonce, _ := common.GetNonce()
		web.SetContentSecurityHeaders(ctx.Writer, nonce)
		ctx.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"error": html.EscapeString(fmt.Errorf("%v", err).Error()),
			"code":  http.StatusInternalServerError,
			"nonce": nonce,
		})
	})
}
