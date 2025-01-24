package middlewares

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/sarumaj/kagi-proxy/pkg/common"
	"go.uber.org/zap"
)

func CORS() gin.HandlerFunc {
	config := cors.Config{}
	config.AllowCredentials = true
	config.AllowBrowserExtensions = true
	config.AddAllowHeaders("X-Requested-With", "Content-Type", "Authorization", "Origin", "Accept")
	config.AllowOriginFunc = func(origin string) bool {
		parsed, err := url.Parse(origin)
		if err != nil {
			return false
		}

		if parsed.Hostname() == "localhost" {
			return true
		}

		hostname := parsed.Hostname()
		for targetDomain, proxyDomain := range common.ConfigProxyTargetHosts() {
			switch {
			case hostname == targetDomain,
				hostname == proxyDomain,
				strings.HasSuffix(hostname, "."+targetDomain),
				strings.HasSuffix(hostname, "."+proxyDomain):

				return true
			}
		}

		return false
	}
	config.AddExposeHeaders("Location", "Content-Disposition")
	config.AllowMethods = []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions}
	if err := config.Validate(); err != nil {
		common.Logger().Fatal("Invalid CORS configuration", zap.Error(err))
	}

	return cors.New(config)
}
