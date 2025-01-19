package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"slices"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	ginzap "github.com/gin-contrib/zap"
	"github.com/gin-gonic/gin"
	"github.com/sarumaj/kagi/pkg/api"
	"github.com/sarumaj/kagi/pkg/common"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	environ []string

	limitRPS      = flag.Float64("limit-rps", 90, "requests per second for rate limiting")
	limitBurst    = flag.Uint("limit-burst", 12, "burst size for rate limiting")
	port          = flag.Uint("port", common.Getenv[uint]("PORT", 8080), "port to listen on")
	sessionToken  = flag.String("session-token", common.Getenv[string]("KAGI_SESSION_TOKEN", ""), "")
	sessionSecret = flag.String("session-secret", common.Getenv[string]("KAGI_SESSION_SECRET", "test"), "test")
	sessionUser   = flag.String("session-user", common.Getenv[string]("KAGI_SESSION_USER", "user"), "user")
	sessionPass   = flag.String("session-pass", common.Getenv[string]("KAGI_SESSION_PASS", "pass"), "pass")
)

func main() {
	flag.Parse()
	gin.SetMode(gin.ReleaseMode)

	defer func() { _ = common.Logger.Sync() }()

	// Log the server start.
	common.Logger.Info("Starting server",
		zap.Uintp("port", port),
		zap.Float64p("limitRPS", limitRPS),
		zap.Uintp("limitBurst", limitBurst),
		zap.Stringp("sessionToken", sessionToken),
		zap.Stringp("sessionSecret", sessionSecret),
		zap.Stringp("sessionUser", sessionUser),
		zap.Stringp("sessionPass", sessionPass),
	)

	environ = os.Environ()
	slices.Sort(environ)
	common.Logger.Info("Environment variables", zap.Strings("environ", environ))

	router := gin.New(func(e *gin.Engine) {
		// Create a new cookie store.
		store := cookie.NewStore([]byte(*sessionSecret))
		store.Options(sessions.Options{
			Path:     "/",
			MaxAge:   3600 * 24, // 1 day
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
		})
		e.Use(sessions.Sessions("proxy_session", store))

		// Use the ginzap middleware to log requests.
		e.Use(ginzap.GinzapWithConfig(common.Logger, &ginzap.Config{
			TimeFormat:   time.RFC3339,
			UTC:          true,
			DefaultLevel: zapcore.DebugLevel,
			Context:      func(ctx *gin.Context) []zapcore.Field { return []zapcore.Field{zap.Any("headers", ctx.Request.Header)} },
		}))

		// Use the ginzap middleware to log panics.
		e.Use(ginzap.CustomRecoveryWithZap(common.Logger, true, func(c *gin.Context, err any) {
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("%v", err)})
		}))

		// Set the HTML templates.
		e.SetHTMLTemplate(api.Templates())

		// Use the rate limiting middleware.
		e.Use(api.Rate(*limitRPS, int(*limitBurst)))
	})

	// Add a health check route.
	router.Match([]string{http.MethodHead, http.MethodGet}, "/health", func(ctx *gin.Context) { ctx.Status(http.StatusOK) })

	// Add a redirect login route.
	api.RedirectLoginURL = "/signin"
	if login := router.Group(api.RedirectLoginURL, api.CSRF(*sessionSecret)); true {
		login.GET("/", api.ShowLogin())
		login.POST("/", api.HandleLogin(*sessionUser, *sessionPass))
	}

	// Overwrite the logout route.
	router.GET("/logout", api.HandleLogout())

	// Overwrite the settings route.
	router.GET("/settings", api.HandleLogout())

	// Add a proxy route.
	router.NoRoute(api.BasicAuth([]string{"/favicon.ico"}), api.ProxyPass(*sessionToken))

	if err := router.Run(fmt.Sprintf(":%d", *port)); err != nil {
		common.Logger.Fatal("Unexpected server error", zap.Error(err))
	}
}
