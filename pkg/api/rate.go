package api

import (
	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
)

// Rate is a middleware that limits the request rate.
func Rate(rps float64, burst int) gin.HandlerFunc {
	limiter := rate.NewLimiter(rate.Limit(rps), burst)

	return func(ctx *gin.Context) {
		_ = limiter.WaitN(ctx, 1)
		ctx.Next()
	}
}
