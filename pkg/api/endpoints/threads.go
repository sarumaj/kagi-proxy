package endpoints

import (
	"net/http"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/sarumaj/kagi-proxy/pkg/common"
	"github.com/sarumaj/kagi-proxy/pkg/common/web"
	"go.uber.org/zap"
)

// ThreadClaimPath is the proxy's own route the injected script reports new threads to.
const ThreadClaimPath = "/proxy/threads"

// ClaimThread registers an assistant thread with the calling session.
//
// The assistant creates a thread client side and swaps the new URL in with
// history.pushState, so the proxy never sees a request for it and the injected script
// would go on hiding the thread as somebody else's until the next full page load. The
// script reports the id here instead. Claiming stays first-come: the request can only
// register a thread nobody else holds, which is the one the caller has just created.
//
// The body has to be JSON, so a cross-origin caller needs a preflight the CORS middleware
// refuses, and the session cookie the claim is scoped to is SameSite=Lax to begin with.
func ClaimThread(ctx *gin.Context) {
	session := sessions.Default(ctx)
	sessionID := common.QuickGet[string](session, "session_id")
	if len(sessionID) == 0 {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "no session"})
		return
	}

	var request struct {
		ThreadID string `json:"thread_id" binding:"required"`
	}
	if err := ctx.ShouldBindJSON(&request); err != nil {
		common.Logger().Debug("Failed to bind thread claim", zap.Error(err))
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	threadID, ok := common.NormalizeThreadID(request.ThreadID)
	if !ok {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid thread id"})
		return
	}

	registry := common.Threads()
	registry.Restore(sessionID, common.SessionThreads(session))

	if !registry.Claim(threadID, sessionID) {
		common.Logger().Info("Refusing to claim a thread owned by another session",
			zap.String("thread", threadID))

		ctx.JSON(http.StatusForbidden, gin.H{"error": "thread belongs to another session"})
		return
	}

	if common.SessionAddThread(session, threadID) && !web.SessionSave(session, ctx) {
		return
	}

	ctx.JSON(http.StatusOK, gin.H{"threads": common.SessionThreads(session)})
}
