package middlewares

import (
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/sarumaj/kagi-proxy/pkg/common"
	"github.com/sarumaj/kagi-proxy/pkg/common/web"
	"go.uber.org/zap"
)

// ThreadGuard keeps the assistant threads of one proxy session out of reach of the others.
//
// All of them live in the single kagi.com account the proxy shares, so the target host
// serves every thread to every user of the proxy. The proxy therefore keeps the mapping
// itself: a thread is claimed by the session that first opens it, which is the session
// that created it, and any later request carrying that id from a different session is
// answered with the error page rather than forwarded.
func ThreadGuard() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		if !common.ConfigProxyPrivateThreads() || common.ConfigProxyPublicDomains().Contains(ctx.Request.Host) {
			ctx.Next()
			return
		}

		session := sessions.Default(ctx)
		sessionID := common.QuickGet[string](session, "session_id")
		if len(sessionID) == 0 {
			// The request either skipped authentication through an allow rule, or travels on
			// a session minted before the proxy issued session ids. Neither can own a thread,
			// so there is nothing to scope.
			ctx.Next()
			return
		}

		registry := common.Threads()
		registry.Restore(sessionID, common.SessionThreads(session))

		// A thread id anywhere in the path is enough to reach the thread, so the API routes
		// behind the page are covered by the same claim as the page itself.
		for _, threadID := range common.ThreadIDsInPath(ctx.Request.URL.Path) {
			if owner, ok := registry.Owner(threadID); ok && owner != sessionID {
				common.Logger().Info("Denying access to a thread owned by another session",
					zap.String("thread", threadID),
					zap.String("url", ctx.Request.URL.String()))

				forbid(ctx)
				return
			}
		}

		// Only a page route claims a thread. An API call carrying an id the registry does not
		// know must not mint ownership, or replaying one request would be enough to take a
		// thread over before its owner ever loads the page.
		threadID, ok := common.ThreadIDFromPath(ctx.Request.URL.Path)
		if !ok {
			ctx.Next()
			return
		}

		if !registry.Claim(threadID, sessionID) {
			forbid(ctx)
			return
		}

		if common.SessionAddThread(session, threadID) && !web.SessionSave(session, ctx) {
			return
		}

		ctx.Next()
	}
}
