package middlewares

import (
	"net/http"
	"time"

	ginzap "github.com/gin-contrib/zap"
	"github.com/gin-gonic/gin"
	"github.com/sarumaj/kagi-proxy/pkg/common"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Logger is a middleware that logs the request and response headers.
func Logger() gin.HandlerFunc {
	return ginzap.GinzapWithConfig(common.Logger(), &ginzap.Config{
		TimeFormat:   time.RFC3339,
		UTC:          true,
		DefaultLevel: zapcore.DebugLevel,
		Context: func(ctx *gin.Context) []zapcore.Field {
			requestHeaders := make(http.Header)
			for key, value := range ctx.Request.Header {
				requestHeaders[key] = value
			}
			ctx.Next()
			return []zapcore.Field{
				zap.Any("request_headers", requestHeaders),
				zap.Any("response_headers", ctx.Writer.Header()),
			}
		},
	})
}
