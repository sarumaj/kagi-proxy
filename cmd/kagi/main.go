package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"slices"
	"time"

	ginzap "github.com/gin-contrib/zap"
	"github.com/gin-gonic/gin"
	"github.com/sarumaj/kagi/pkg/api"
	"github.com/sarumaj/kagi/pkg/common"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	environ []string
	logger  *zap.Logger

	limitRPS     = flag.Float64("limit-rps", 90, "requests per second for rate limiting")
	limitBurst   = flag.Uint("limit-burst", 12, "burst size for rate limiting")
	port         = flag.Uint("port", common.Getenv[uint]("PORT", 8080), "port to listen on")
	sessionToken = flag.String("session-token", common.Getenv[string]("KAGI_SESSION_TOKEN", ""), "")
)

func init() {
	flag.Parse()
	gin.SetMode(gin.ReleaseMode)

	cfg := zap.NewDevelopmentEncoderConfig()
	cfg.EncodeLevel = zapcore.CapitalColorLevelEncoder
	enc := zapcore.NewConsoleEncoder(cfg)
	logger = zap.New(zapcore.NewTee(
		zapcore.NewCore(enc, zapcore.Lock(os.Stdout), zap.LevelEnablerFunc(func(lvl zapcore.Level) bool { return lvl < zapcore.ErrorLevel })),
		zapcore.NewCore(enc, zapcore.Lock(os.Stderr), zap.LevelEnablerFunc(func(lvl zapcore.Level) bool { return lvl >= zapcore.ErrorLevel })),
	))
}

func main() {
	defer func() { _ = logger.Sync() }()

	// Log the server start.
	logger.Info("Starting server",
		zap.Uintp("port", port),
		zap.Float64p("limitRPS", limitRPS),
		zap.Uintp("limitBurst", limitBurst),
	)

	environ = os.Environ()
	slices.Sort(environ)
	logger.Info("Environment variables", zap.Strings("environ", environ))

	router := gin.New(func(e *gin.Engine) {
		e.Use(ginzap.GinzapWithConfig(logger, &ginzap.Config{
			TimeFormat:   time.RFC3339,
			UTC:          true,
			DefaultLevel: zapcore.DebugLevel,
			Context:      func(ctx *gin.Context) []zapcore.Field { return []zapcore.Field{zap.Any("headers", ctx.Request.Header)} },
		}))
		e.Use(ginzap.CustomRecoveryWithZap(logger, true, func(c *gin.Context, err any) {
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("%v", err)})
		}))
	})

	router.Any("/", api.Redirect(*sessionToken))
}
