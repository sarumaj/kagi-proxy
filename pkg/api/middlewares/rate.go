package middlewares

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/sarumaj/kagi-proxy/pkg/common"
	"go.uber.org/zap"
	"golang.org/x/time/rate"
)

// Rate is a middleware that limits the request rate.
// It uses the token bucket algorithm to limit the request rate.
// rps is the rate per second.
// burst is the maximum number of requests that can be made at once.
// It tries to wait for a token before processing the request.
// If the rate limit is exceeded, it returns 429 Too Many Requests.
func Rate(rps float64, burst int) gin.HandlerFunc {
	limiter := rate.NewLimiter(rate.Limit(rps), burst)

	return func(ctx *gin.Context) {
		if err := limiter.WaitN(ctx, 1); err != nil {
			common.Logger().Warn("Rate limit exceeded", zap.Error(err))
			ctx.AbortWithStatus(http.StatusTooManyRequests)
			return
		}

		ctx.Next()
	}
}
