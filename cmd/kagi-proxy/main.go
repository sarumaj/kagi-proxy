package main

import (
	"flag"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	ginzap "github.com/gin-contrib/zap"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/sarumaj/kagi-proxy/pkg/api"
	"github.com/sarumaj/kagi-proxy/pkg/common"
)

var (
	environ []string

	limitRPS           = flag.Float64("limit-rps", 90, "requests per second for rate limiting")
	limitBurst         = flag.Uint("limit-burst", 12, "burst size for rate limiting")
	port               = flag.Uint("port", common.Getenv[uint]("PORT", 8080), "port to listen on")
	sessionToken       = flag.String("session-token", common.Getenv[string]("KAGI_SESSION_TOKEN", ""), "session token for the Kagi website")
	proxySessionSecret = flag.String("proxy-session-secret", common.Getenv[string]("PROXY_SESSION_SECRET", "test"), "cookie encryption secret for the proxy session")
	proxyOTPSecret     = flag.String("proxy-otp-secret", common.Getenv[string]("PROXY_OTP_SECRET", "test"), "OTP encryption secret for the proxy session")
	proxyUser          = flag.String("proxy-user", common.Getenv[string]("PROXY_USER", "user"), "proxy user")
	proxyPass          = flag.String("proxy-pass", common.Getenv[string]("PROXY_PASS", "pass"), "proxy user password")
	proxyHost          = flag.String("proxy-host", common.Getenv[string]("PROXY_HOST", "kagi.com"), "proxy domain")
)

func main() {
	flag.Parse()
	gin.SetMode(gin.ReleaseMode)

	defer func() { _ = common.Logger().Sync() }()

	// Log the server start.
	common.Logger().Info("Starting server",
		zap.Uintp("port", port),
		zap.Float64p("limitRPS", limitRPS),
		zap.Uintp("limitBurst", limitBurst),
		zap.Stringp("sessionToken", sessionToken),
		zap.Stringp("proxySessionSecret", proxySessionSecret),
		zap.Stringp("proxyOTPSecret", proxyOTPSecret),
		zap.Stringp("proxyUser", proxyUser),
		zap.Stringp("proxyPass", proxyPass),
		zap.Stringp("proxyHost", proxyHost),
	)

	common.ConfigureProxy(
		common.WithCsrfSecret(*proxySessionSecret),
		common.WithSessionToken(*sessionToken),
		common.WithProxyUser(*proxyUser),
		common.WithProxyPass(*proxyPass),
		common.WithProxyOTPSecret(*proxyOTPSecret),
		common.WithProxyTargetHosts(map[string]string{
			*proxyHost:                "kagi.com",
			"translate." + *proxyHost: "translate.kagi.com",
			"assets." + *proxyHost:    "assets.kagi.com",
			"status." + *proxyHost:    "status.kagi.com",
		}),
		common.WithProxyGuardRules(common.Ruleset{
			common.Rule{Path: "/settings", PathType: common.Exact, Query: url.Values{"p": {"billing"}}},
			common.Rule{Path: "/settings", PathType: common.Exact, Query: url.Values{"p": {"gift"}}},
			common.Rule{Path: "/settings", PathType: common.Exact, Query: url.Values{"p": {"user_details"}}},
			common.Rule{Path: "/settings", PathType: common.Exact, Query: url.Values{"p": {"api"}, "generate": {"1"}}},
			common.Rule{Path: "/api/user_token", PathType: common.Prefix},
		}),
		common.WithProxyRedirectLoginURL("/signin"),
	)

	environ = os.Environ()
	slices.Sort(environ)
	common.Logger().Debug("Environment variables", zap.Strings("environ", environ))

	router := gin.New(func(e *gin.Engine) {
		// Create a new cookie store.
		hashKey, blockKey := common.MakeKeyPair([]byte(*proxySessionSecret))
		store := cookie.NewStore(hashKey, blockKey)
		store.Options(sessions.Options{
			Domain: *proxyHost, // Required to support wildcard subdomains
			Path:   "/",
			// 0: session cookie until the browser is closed, -1: delete the cookie, math.MaxInt32: 68 years
			MaxAge:   int((24 * 7 * time.Hour).Seconds()),
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		})
		e.Use(sessions.Sessions("proxy_session", store))

		// Setup CORS
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
		e.Use(cors.New(config))

		// Use the ginzap middleware to log requests.
		e.Use(ginzap.GinzapWithConfig(common.Logger(), &ginzap.Config{
			TimeFormat:   time.RFC3339,
			UTC:          true,
			DefaultLevel: zapcore.DebugLevel,
			Context:      func(ctx *gin.Context) []zapcore.Field { return []zapcore.Field{zap.Any("headers", ctx.Request.Header)} },
		}))

		// Use the ginzap middleware to log panics.
		e.Use(ginzap.CustomRecoveryWithZap(common.Logger(), true, func(c *gin.Context, err any) {
			nonce, _ := common.GetNonce()
			api.SetContentSecurityHeaders(c.Writer, nonce)
			c.HTML(http.StatusInternalServerError, "error.html", gin.H{
				"error": html.EscapeString(fmt.Errorf("%v", err).Error()),
				"code":  http.StatusInternalServerError,
				"nonce": nonce,
			})
		}))

		// Set the HTML templates.
		e.SetHTMLTemplate(api.HTMLTemplates())

		// Use the rate limiting middleware.
		e.Use(api.Rate(*limitRPS, int(*limitBurst)))
	})

	// Add a health check route.
	router.Match([]string{http.MethodHead, http.MethodGet}, "/health", func(ctx *gin.Context) { ctx.Status(http.StatusOK) })

	// Add a redirect login route.
	if login := router.Group("/signin", api.CSRF()); true {
		login.GET("/", api.ShowLogin())
		login.POST("/", api.HandleLogin())
	}

	// Overwrite the logout route.
	router.GET("/logout", api.HandleLogout())

	// Add a proxy route for anything else, do not require authentication for the favicon.
	router.NoRoute(api.BasicAuth([]string{"/favicon.ico"}), api.ProxyGuard(), api.ProxyPass())

	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", *port),
		Handler: router,
	}
	server.RegisterOnShutdown(func() {
		common.Logger().Info("Server shutdown")
		api.SessionMap.Close()
	})

	// Start the server.
	if err := server.ListenAndServe(); err != nil {
		common.Logger().Fatal("Unexpected server error", zap.Error(err))
	}
}
