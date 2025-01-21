package main

import (
	"flag"
	"fmt"
	"html"
	"math"
	"net/http"
	"os"
	"slices"
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
			"status" + *proxyHost:     "status.kagi.com",
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
			Domain:   *proxyHost, // Required to support wildcard subdomains
			Path:     "/",
			MaxAge:   math.MaxInt32, // 0: session cookie until the browser is closed, -1: delete the cookie, math.MaxInt32: 68 years
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		})
		e.Use(sessions.Sessions("proxy_session", store))

		// Setup CORS
		config := cors.DefaultConfig()
		config.AllowCredentials = true
		config.AllowBrowserExtensions = true
		config.AllowWebSockets = true
		config.AddAllowHeaders("X-Requested-With")
		config.AllowOrigins = append(config.AllowOrigins,
			"http://localhost:"+fmt.Sprint(*port),
			"https://kagi.com",
			"https://"+*proxyHost,
			"https://*.kagi.com",
			"https://*."+*proxyHost,
		)
		config.AddExposeHeaders("Location", "Content-Disposition")
		config.AllowWildcard = true
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

	// Overwrite the settings route.
	router.GET("/settings", api.HandleUnauthorized())

	// Add a proxy route for anything else, do not require authentication for the favicon.
	router.NoRoute(api.BasicAuth([]string{"/favicon.ico"}), api.ProxyPass())

	// Start the server.
	if err := router.Run(fmt.Sprintf(":%d", *port)); err != nil {
		common.Logger().Fatal("Unexpected server error", zap.Error(err))
	}
}
