package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"golang.org/x/time/rate"

	"github.com/sarumaj/kagi/pkg/common"
)

// Rate is a middleware that limits the request rate.
func Rate(rps float64, burst int) gin.HandlerFunc {
	limiter := rate.NewLimiter(rate.Limit(rps), burst)

	return func(ctx *gin.Context) {
		if err := limiter.WaitN(ctx, 1); err != nil {
			common.Logger.Warn("Rate limit exceeded", zap.Error(err))
			ctx.AbortWithStatus(http.StatusTooManyRequests)
			return
		}

		ctx.Next()
	}
}
