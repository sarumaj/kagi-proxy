package api

import (
	"bytes"
	"html"
	"html/template"
	"image/png"
	"net/http"
	"strings"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/sarumaj/kagi-proxy/pkg/common"
	csrf "github.com/utrack/gin-csrf"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

// BasicAuth is a middleware that checks if the user is authenticated.
// It skips authentication for the paths in exceptPaths.
// It seeks the proxy_token query parameter to authenticate the user.
// Otherwise, it seeks the user session.
// If the user is not authenticated, it redirects to the login page.
func BasicAuth(exceptPaths []string) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		for _, path := range exceptPaths {
			if ctx.Request.URL.Path == path {
				common.Logger().Debug("Skipping basic auth for path", zap.String("path", path))
				ctx.Next()
				return
			}
		}

		// Seek the proxy_token query parameter
		session := sessions.Default(ctx)
		if token := ctx.Query("proxy_token"); len(token) > 0 {
			common.Logger().Debug("User provided token", zap.String("token", token))
			if hash, err := common.B64URLNoPadding.DecodeString(token); err != nil {
				common.Logger().Error("failed to decode token", zap.Error(err))
			} else if err := bcrypt.CompareHashAndPassword(hash, []byte(common.ConfigProxyUser())); err != nil {
				common.Logger().Error("hash mismatched", zap.Error(err))
			} else {
				common.Logger().Debug("User authenticated with token")

				// Establish or overwrite the user session
				session.Set("user", common.ConfigProxyUser())
				if !sessionSave(session, ctx) {
					return
				}

				// Dispose the proxy_token query parameter
				q := ctx.Request.URL.Query()
				q.Del("proxy_token")
				ctx.Request.URL.RawQuery = q.Encode()

				ctx.Next()
				return
			}
		}

		// Seek the user session
		if user := session.Get("user"); user == nil {
			common.Logger().Debug("User not authenticated")
			session.Set("redirect_url", ctx.Request.URL.String())
			if !sessionSave(session, ctx) {
				return
			}

			ctx.Redirect(http.StatusSeeOther, common.ConfigProxyRedirectLoginURL())
			ctx.Abort()
			return
		}

		common.Logger().Debug("User authenticated with session")
		ctx.Next()
	}
}

// CSRF is a middleware that checks if the CSRF token is valid.
func CSRF() gin.HandlerFunc {
	return csrf.Middleware(csrf.Options{
		Secret: common.ConfigCsrfSecret(),
		ErrorFunc: func(ctx *gin.Context) {
			session := sessions.Default(ctx)
			session.AddFlash("Invalid CSRF token")
			if !sessionSave(session, ctx) {
				return
			}

			common.Logger().Debug("Invalid CSRF token")
			ctx.Redirect(http.StatusSeeOther, ctx.Request.URL.Path)
			ctx.Abort()
		},
	})
}

// HandleLogin is a handler that authenticates the user.
// If the user is not authenticated, it redirects to the login page.
// If the user is authenticated, it redirects to the root page or
// the location he attempted to access before page.
// It supports two actions: login and signup.
// Login action authenticates the user with username, password, and OTP.
// Signup action generates a QR code for the user to set up OTP.
func HandleLogin() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		session := sessions.Default(ctx)

		// Check if the OTP secret is set
		if len(common.ConfigProxyOTPSecret()) == 0 {
			common.Logger().Error("OTP secret is not set")
			session.AddFlash("Internal server error")
			if !sessionSave(session, ctx) {
				return
			}
			ctx.Redirect(http.StatusSeeOther, common.ConfigProxyRedirectLoginURL())
			return
		}

		// Verify mode operation
		var query struct {
			SignUp bool `form:"signup"`
		}
		if err := ctx.ShouldBindQuery(&query); err != nil {
			common.Logger().Error("failed to bind query", zap.Error(err))
			session.AddFlash("Invalid request")
			if !sessionSave(session, ctx) {
				return
			}
			ctx.Redirect(http.StatusSeeOther, common.ConfigProxyRedirectLoginURL())
			return
		}

		// Handle login and signup actions
		if query.SignUp { // Signup action
			var request struct {
				Username string `json:"username" form:"username" binding:"required"`
				Width    int    `json:"width" form:"width" binding:"required,min=100,max=250"`
				Height   int    `json:"height" form:"height" binding:"required,eqfield=Width"`
			}
			if err := ctx.Bind(&request); err != nil {
				common.Logger().Error("failed to bind JSON", zap.Error(err))
				session.AddFlash("Invalid request")
				if !sessionSave(session, ctx) {
					return
				}
				ctx.Redirect(http.StatusSeeOther, common.ConfigProxyRedirectLoginURL()+"?signup=true")
				return
			}

			validUsername := common.CTEqual(request.Username, common.ConfigProxyUser())
			if !validUsername {
				common.Logger().Info("invalid username", zap.String("username", request.Username))
				session.AddFlash("Invalid username")
				if !sessionSave(session, ctx) {
					return
				}
				ctx.Redirect(http.StatusSeeOther, common.ConfigProxyRedirectLoginURL()+"?signup=true")
				return
			}

			// Generate a QR code for the user to set up OTP
			key, err := totp.Generate(totp.GenerateOpts{
				Issuer:      "Kagi-Proxy",
				AccountName: request.Username,
				Period:      30, // 30 seconds
				Digits:      otp.DigitsEight,
				Algorithm:   otp.AlgorithmSHA1,
				// Overwrite the attributes below to ensure deterministic behavior
				SecretSize: uint(len(common.ConfigProxyOTPSecret())),
				Rand:       bytes.NewReader([]byte(common.ConfigProxyOTPSecret())),
			})
			if err != nil {
				common.Logger().Error("failed to generate OTP", zap.Error(err))
				session.AddFlash("Internal server error")
				if !sessionSave(session, ctx) {
					return
				}
				ctx.Redirect(http.StatusSeeOther, common.ConfigProxyRedirectLoginURL()+"?signup=true")
				return
			}

			// Generate a QR code
			img, err := key.Image(request.Width, request.Height)
			if err != nil {
				common.Logger().Error("failed to generate QR code", zap.Error(err))
				session.AddFlash("Internal server error")
				if !sessionSave(session, ctx) {
					return
				}
				ctx.Redirect(http.StatusSeeOther, common.ConfigProxyRedirectLoginURL()+"?signup=true")
				return
			}

			var buf bytes.Buffer
			if err := png.Encode(&buf, img); err != nil {
				common.Logger().Error("failed to encode QR code", zap.Error(err))
				session.AddFlash("Internal server error")
				if !sessionSave(session, ctx) {
					return
				}
				ctx.Redirect(http.StatusSeeOther, common.ConfigProxyRedirectLoginURL()+"?signup=true")
				return
			}

			// In following the content of the page will get update over PRG pattern:
			// 1. POST request to /signin?signup=true to generate the QR code and the OTP setup URL
			// 2. Redirect to /signin?signup=true to force reloading the page
			// 3. GET request to /signin?signup=true to display the QR code and the OTP setup URL

			// Encode the QR code and the OTP setup URL in location fragment
			param, err := common.EncodeForQuery(map[string]any{
				"qr_code":    `<img src="data:image/png;base64,` + common.B64StdWithPadding.EncodeToString(buf.Bytes()) + `" alt="QR code" />`,
				"secret_key": key.URL(),
			}, []byte(common.ConfigProxyPass()), session)
			if err != nil {
				common.Logger().Error("failed to encode query parameter", zap.Error(err))
				session.AddFlash("Internal server error")
				if !sessionSave(session, ctx) {
					return
				}
				ctx.Redirect(http.StatusSeeOther, common.ConfigProxyRedirectLoginURL()+"?signup=true")
				return
			}
			if !sessionSave(session, ctx) {
				return
			}

			// Redirect to force reloading the page
			ctx.Redirect(http.StatusSeeOther, common.ConfigProxyRedirectLoginURL()+"?signup=true&data="+param)
			return
		}

		// Handle login action
		var request struct {
			Username string `json:"username" form:"username" binding:"required"`
			Password string `json:"password" form:"password" binding:"required"`
			OTP      string `json:"otp" form:"otp" binding:"required,max=8,min=8,numeric"`
		}
		if err := ctx.ShouldBind(&request); err != nil {
			common.Logger().Error("failed to bind JSON", zap.Error(err))
			session.AddFlash("Invalid request")
			if !sessionSave(session, ctx) {
				return
			}

			ctx.Redirect(http.StatusSeeOther, common.ConfigProxyRedirectLoginURL())
			return
		}

		// Validate the user credentials
		validUsername := common.CTEqual(request.Username, common.ConfigProxyUser())
		validPassword := common.CTEqual(request.Password, common.ConfigProxyPass())
		validOTP, err := totp.ValidateCustom(
			request.OTP,
			common.B32StdNoPadding.EncodeToString([]byte(common.ConfigProxyOTPSecret())),
			time.Now(),
			totp.ValidateOpts{
				Period:    30,                // 30 seconds
				Skew:      1,                 // +/- 1 period
				Digits:    otp.DigitsEight,   // 8 digits
				Algorithm: otp.AlgorithmSHA1, // HMAC-SHA1
			},
		)
		if err != nil {
			common.Logger().Error("failed to validate OTP", zap.Error(err))
			session.AddFlash("Internal server error")
			if !sessionSave(session, ctx) {
				return
			}
			ctx.Redirect(http.StatusSeeOther, common.ConfigProxyRedirectLoginURL())
			return
		}

		// Success: Redirect the user to the root page or the location he attempted to access before page
		if validUsername && validPassword && validOTP {
			session.Set("user", request.Username)
			redirectURL := session.Get("redirect_url")
			session.Delete("redirect_url")
			if !sessionSave(session, ctx) {
				return
			}

			if redirectURL != nil {
				ctx.Redirect(http.StatusSeeOther, redirectURL.(string))
				return
			}

			ctx.Redirect(http.StatusSeeOther, "/")
			return

		}

		common.Logger().Info("invalid credentials",
			zap.Bool("valid_username", validUsername),
			zap.Bool("valid_password", validPassword),
			zap.Bool("valid_otp", validOTP))

		// Failure: Redirect the user to the login page
		session.AddFlash("Invalid credentials")
		if !sessionSave(session, ctx) {
			return
		}
		ctx.Redirect(http.StatusSeeOther, common.ConfigProxyRedirectLoginURL())
	}
}

// HandleLogout is a handler that logs out the user.
func HandleLogout() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		session := sessions.Default(ctx)
		session.Clear()
		if !sessionSave(session, ctx) {
			return
		}

		ctx.Redirect(http.StatusFound, common.ConfigProxyRedirectLoginURL())
	}
}

// HandleUnauthorized is a handler that displays an unauthorized page.
func HandleUnauthorized() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		nonce, _ := common.GetNonce()
		SetContentSecurityHeaders(ctx.Writer, nonce)
		ctx.HTML(http.StatusForbidden, "error.html", gin.H{
			"code":  http.StatusForbidden,
			"csp":   ctx.Writer.Header().Get("Content-Security-Policy"),
			"error": nil,
			"nonce": nonce,
		})
	}
}

// sessionSave saves the session and handles any errors that occur.
// If an error occurs, it displays an error page and aborts the request.
// It returns true if the session is saved successfully.
func sessionSave(session sessions.Session, ctx *gin.Context) (success bool) {
	if err := session.Save(); err != nil {
		common.Logger().Error("failed to save session", zap.Error(err))
		nonce, _ := common.GetNonce()
		SetContentSecurityHeaders(ctx.Writer, nonce)
		ctx.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"code":  http.StatusInternalServerError,
			"csp":   ctx.Writer.Header().Get("Content-Security-Policy"),
			"error": html.EscapeString(err.Error()),
			"nonce": nonce,
		})
		ctx.Abort()
	}

	return !ctx.IsAborted()
}

// SetContentSecurityHeaders sets the Content-Security-Policy, X-Frame-Options, and X-Content-Type-Options headers.
// It uses the nonce to set the script-src and style-src directives.
func SetContentSecurityHeaders(w http.ResponseWriter, nonce string) {
	w.Header().Set("Content-Security-Policy", strings.Join([]string{
		"default-src 'none'",
		"script-src 'self' 'nonce-" + nonce + "'",
		"style-src 'self' 'nonce-" + nonce + "'",
		"img-src 'self' data:",
		"connect-src 'self'",
		"form-action 'self'",
		"base-uri 'none'",
		"font-src 'self'",
		"manifest-src 'self'",
		"object-src 'none'",
		"child-src 'none'",
		"worker-src 'none'",
		"upgrade-insecure-requests",
	}, "; "))
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-Content-Type-Options", "nosniff")
}

// ShowLogin is a handler that displays the login page.
// It displays the login page with renders the flash messages originating from the session.
func ShowLogin() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		session := sessions.Default(ctx)
		flash := session.Flashes()
		if !sessionSave(session, ctx) {
			return
		}

		var query struct {
			SignUp bool   `form:"signup"`
			Data   string `form:"data"`
		}
		if err := ctx.ShouldBindQuery(&query); err != nil {
			common.Logger().Error("failed to bind query", zap.Error(err))
			session.AddFlash("Invalid request")
			if !sessionSave(session, ctx) {
				return
			}

			ctx.Redirect(http.StatusSeeOther, common.ConfigProxyRedirectLoginURL())
			return
		}

		token := csrf.GetToken(ctx)
		nonce, _ := common.GetNonce()

		// Decode the QR code and the OTP setup URL from the location fragment
		data, err := common.DecodeFromQuery(query.Data, []byte(common.ConfigProxyPass()), session)
		if err != nil {
			common.Logger().Warn("failed to decode data from query", zap.Error(err))
		} else if !sessionSave(session, ctx) {
			return
		}

		common.Logger().Debug("Displaying login page",
			zap.String("nonce", nonce),
			zap.Any("flash", flash),
			zap.String("token", token),
			zap.String("path", ctx.Request.URL.Path),
			zap.Bool("setup_active", query.SignUp),
			zap.Reflect("data", data))

		SetContentSecurityHeaders(ctx.Writer, nonce)
		ctx.HTML(http.StatusOK, "login.html", gin.H{
			"login_action": common.ConfigProxyRedirectLoginURL(),
			"csp":          ctx.Writer.Header().Get("Content-Security-Policy"),
			"csrf_token":   token,
			"flash":        flash,
			"nonce":        nonce,
			"qr_code":      template.HTML(common.QuickGet[string](data, "qr_code")),
			"secret_key":   common.QuickGet[string](data, "secret_key"),
			"setup_action": common.ConfigProxyRedirectLoginURL() + "?signup=true",
			"setup_active": query.SignUp,
		})
	}
}
