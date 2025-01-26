//go:generate go run generate/examples.go
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"slices"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/sarumaj/kagi-proxy/pkg/api/endpoints"
	"github.com/sarumaj/kagi-proxy/pkg/api/middlewares"
	"github.com/sarumaj/kagi-proxy/pkg/api/templates"
	"github.com/sarumaj/kagi-proxy/pkg/common"
)

var (
	limitBurst           = flag.Uint("limit-burst", 12, "burst size for rate limiting")
	limitRPS             = flag.Float64("limit-rps", 90, "requests per second for rate limiting")
	port                 = flag.Uint("port", common.Getenv[uint]("PORT", 8080), "port to listen on")
	proxyExtraPolicy     = flag.String("proxy-extra-policy", "", "path to a JSON file with additional policy rules, see https://github.com/sarumaj/kagi-proxy/tree/main/examples")
	proxyHost            = flag.String("proxy-host", common.Getenv("PROXY_HOST", "kagi.com"), "proxy domain")
	proxyOTPSecret       = flag.String("proxy-otp-secret", common.Getenv("PROXY_OTP_SECRET", "test"), "OTP encryption secret for the proxy session")
	proxyPass            = flag.String("proxy-pass", common.Getenv("PROXY_PASS", "pass"), "proxy user password")
	proxySessionDuration = flag.Duration("proxy-session-duration", common.Getenv("PROXY_SESSION_DURATION", time.Hour*24*30), "session duration for the proxy session")
	proxySessionSecret   = flag.String("proxy-session-secret", common.Getenv("PROXY_SESSION_SECRET", "test"), "cookie encryption secret for the proxy session")
	proxyUser            = flag.String("proxy-user", common.Getenv("PROXY_USER", "user"), "proxy user")
	sessionToken         = flag.String("session-token", common.Getenv("KAGI_SESSION_TOKEN", ""), "session token for the Kagi website")
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

	var extraPolicy common.Policy
	if len(*proxyExtraPolicy) > 0 {
		fileDescriptor, err := os.Open(*proxyExtraPolicy)
		if err != nil {
			common.Logger().Fatal("Failed to open extra policy file", zap.Error(err))
		}

		decoder := json.NewDecoder(fileDescriptor)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&extraPolicy); err != nil {
			common.Logger().Fatal("Failed to decode extra policy file", zap.Error(err))
		}

		common.Logger().Debug("Extra policy", zap.Reflect("extraPolicy", extraPolicy), zap.String("file", *proxyExtraPolicy))
	}

	// Define ABAC rules. The rules are used to determine if a request is allowed.
	// Denial rules are explicit and make endpoints inaccessible through the proxy.
	// Allow rules are public and do not require authentication.
	// Override rules are used to override the form data of a request before it is sent.
	// The JS selectors in Override rules are used to disable the corresponding form elements.
	common.SetProxyGuardPolicy(common.Policy{
		Deny: common.Ruleset{
			common.Rule{Path: "/api/user_token", PathType: common.Prefix},
			common.Rule{Path: "/settings", PathType: common.Exact, Query: url.Values{"p": {"api"}, "generate": {"1"}}},
			common.Rule{Path: "/settings", PathType: common.Exact, Query: url.Values{"p": {"billing"}}},
			common.Rule{Path: "/settings", PathType: common.Exact, Query: url.Values{"p": {"gift"}}},
			common.Rule{Path: "/settings", PathType: common.Exact, Query: url.Values{"p": {"user_details"}}},
		}.Merge(extraPolicy.Deny),
		Allow: common.Ruleset{
			common.Rule{Path: "/discord", PathType: common.Prefix},
			common.Rule{Path: `/favicon(?:(?:-\d+x\d+)?\.png|\.ico)`, PathType: common.Regex},
		}.Merge(extraPolicy.Allow),
		Override: common.Ruleset{
			common.Rule{
				FormData: url.Values{"translate_debug": {"false"}},
				JsSelectors: []string{
					`input#settings_translate_debug`,
					`label[for="settings_translate_debug"]`,
				},
				Path:     "/settings",
				PathType: common.Exact,
			},
			common.Rule{
				FormData: url.Values{"retention": {"2"}},
				JsSelectors: []string{
					`button._0_k_ui_dropdown.k_ui_dropdown.__basic.min-w-xxxs`,
				},
				Path:     "/settings/ast",
				PathType: common.Exact,
			},
		}.Merge(extraPolicy.Override),
	})
	common.SetProxyPass(*proxyPass)                       // Set the proxy password.
	common.SetProxyRedirectLoginURL("/signin")            // Redirect to the login page if the user is not authenticated.
	common.SetProxySessionDuration(*proxySessionDuration) // Set the session duration for the proxy session.
	common.SetProxySessionSecret(*proxySessionSecret)     // Set the session secret for the proxy session cookie.
	common.SetProxyOTPSecret(*proxyOTPSecret)             // Set the OTP secret for the second factor authentication.
	// Define the public domains that do not require authentication.
	common.SetProxyPublicDomains([]string{
		"help." + *proxyHost,
		"status." + *proxyHost,
	})
	// Define the target hosts for the proxy. The key is the proxy host and the value is the target host.
	// The target host is used to create the request URL and forward the request.
	common.SetProxyTargetHosts(common.HostMap{
		*proxyHost:                "kagi.com",
		"assets." + *proxyHost:    "assets.kagi.com",
		"help." + *proxyHost:      "help.kagi.com",
		"status." + *proxyHost:    "status.kagi.com",
		"translate." + *proxyHost: "translate.kagi.com",
	})
	common.SetProxyUser(*proxyUser)       // Set the proxy user.
	common.SetSessionToken(*sessionToken) // Set the session token for the Kagi website, will be delivered as a cookie.

	environ := os.Environ()
	slices.Sort(environ)
	common.Logger().Debug("Environment variables", zap.Strings("environ", environ))

	// Create a new server.
	server := &http.Server{
		Addr:     fmt.Sprintf(":%d", *port),
		ErrorLog: log.New(io.Discard, "", 0), // Disable the default logger.
	}

	router := gin.New(func(e *gin.Engine) {
		// Set the HTML templates.
		e.SetHTMLTemplate(templates.HTMLTemplates())
		// Recover from panics.
		e.Use(middlewares.Recover())
		// Log all requests.
		e.Use(middlewares.Logger())
		// Create a new cookie store.
		e.Use(middlewares.Session())
		// Setup CORS.
		e.Use(middlewares.CORS())
		// Use the rate limiting middleware.
		e.Use(middlewares.Rate(*limitRPS, int(*limitBurst)))
	})

	// Add a health check route. It is used for deployment monitoring.
	router.Match([]string{http.MethodHead, http.MethodGet}, "/health", endpoints.CheckHealth)

	// Add a redirect login route.
	// It overwrites the default login route of kagi.com.
	if login := router.Group("/signin", middlewares.CSRF()); true {
		login.GET("/", endpoints.SignInWeb)
		login.POST("/", endpoints.SignInForm)
	}

	// Overwrite the logout route.
	// Without it, a user could terminate the kagi.com session.
	router.GET("/logout", endpoints.SignOut)

	// Handle summary.json requests.
	// Status.kagi.com returns for some requests a valid response but the status is always "404".
	// This is a workaround to return a valid response.
	router.GET("/summary.json", endpoints.CheckStatus)
	router.GET("/api/summary.json", endpoints.CheckStatus)

	// Add a proxy route for anything else, do not require authentication for the favicon.
	router.NoRoute(middlewares.BasicAuth(), middlewares.ProxyGuard(), endpoints.Proxy())

	// Install handler on the server
	server.Handler = router

	// Serve the content.
	if err := server.ListenAndServe(); err != nil {
		common.Logger().Fatal("Server error", zap.Error(err))
	}
}
