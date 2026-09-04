package endpoints

import (
	"net/http"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/sarumaj/kagi-proxy/pkg/common"
	"github.com/sarumaj/kagi-proxy/pkg/common/web"
)

// SignOutPath is the proxy's own route that ends the proxy session. It overrides the
// target host's logout so that a user cannot terminate the shared kagi.com session.
const SignOutPath = "/logout"

// SignOut is a handler that logs out the user.
func SignOut(ctx *gin.Context) {
	session := sessions.Default(ctx)
	session.Clear()
	if !web.SessionSave(session, ctx) {
		return
	}

	ctx.Redirect(http.StatusFound, common.ConfigProxyRedirectLoginURL())
}
