package middlewares

import (
	"net/http"
	"time"

	ginzap "github.com/gin-contrib/zap"
	"github.com/gin-gonic/gin"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/sarumaj/kagi-proxy/pkg/common"
	"github.com/sarumaj/kagi-proxy/pkg/common/web"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Logger is a middleware that logs the request and response headers.
func Logger() gin.HandlerFunc {
	geoLocationCache, err := lru.New[string, *web.LookupResponse](1000)
	common.FatalOnError("Failed to create a cache", err)

	return ginzap.GinzapWithConfig(common.Logger(), &ginzap.Config{
		TimeFormat:   time.RFC3339,
		UTC:          true,
		DefaultLevel: zapcore.DebugLevel,
		Context: func(ctx *gin.Context) []zapcore.Field {
			clientIP := ctx.ClientIP()
			geoData, ok := geoLocationCache.Get(clientIP)
			if !ok {
				geoData, err = web.LookupIP(clientIP)
				if err != nil {
					common.Logger().Error("Failed to lookup IP", zap.Error(err))
				} else {
					geoLocationCache.Add(clientIP, geoData)
				}
			}

			requestHeaders := make(http.Header)
			for key, value := range ctx.Request.Header {
				requestHeaders[key] = value
			}

			ctx.Next()

			return []zapcore.Field{
				zap.Any("request_headers", requestHeaders),
				zap.Any("response_headers", ctx.Writer.Header()),
				zap.Any("geo_data", geoData),
			}
		},
	})
}
