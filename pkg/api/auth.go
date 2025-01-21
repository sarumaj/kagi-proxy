package api

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
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
	"golang.org/x/net/html"
)

// BasicAuth is a middleware that checks if the user is authenticated.
func BasicAuth(exceptPaths []string) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		for _, path := range exceptPaths {
			if ctx.Request.URL.Path == path {
				common.Logger().Debug("Skipping basic auth for path", zap.String("path", path))
				ctx.Next()
				return
			}
		}

		session := sessions.Default(ctx)
		if user := session.Get("user"); user == nil {
			common.Logger().Debug("User not authenticated")
			session.Set("redirect_url", ctx.Request.URL.String())
			_ = session.Save()

			ctx.Redirect(http.StatusFound, common.ConfigProxyRedirectLoginURL())
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
			_ = session.Save()

			ctx.Redirect(http.StatusFound, common.ConfigProxyRedirectLoginURL())
			ctx.Abort()
		},
	})
}

// CTEqual is a constant-time comparison function.
func CTEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// GetNonce generates a random nonce.
func GetNonce() (string, error) {
	nonce := make([]byte, 32)
	_, err := rand.Read(nonce)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(nonce), nil
}

// GenerateOTP is a handler that generates an OTP.
func GenerateOTP() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		session := sessions.Default(ctx)
		if len(common.ConfigProxyOTPSecret()) == 0 {
			common.Logger().Error("OTP secret is not set")
			session.AddFlash("Internal server error")
			_ = session.Save()
			ctx.Redirect(http.StatusFound, common.ConfigProxyRedirectLoginURL())
			return
		}

		var request struct {
			Username string `json:"username" form:"username" binding:"required"`
			Width    int    `json:"width" form:"width" binding:"required,min=100,max=250"`
			Height   int    `json:"height" form:"height" binding:"required,eqfield=Width"`
		}
		if err := ctx.Bind(&request); err != nil {
			common.Logger().Error("failed to bind JSON", zap.Error(err))
			session.AddFlash("Invalid request")
			_ = session.Save()
			ctx.Redirect(http.StatusFound, common.ConfigProxyRedirectLoginURL())
			return
		}

		validUsername := CTEqual(request.Username, common.ConfigProxyUser())
		if !validUsername {
			common.Logger().Info("invalid username", zap.String("username", request.Username))
			session.AddFlash("Invalid username")
			_ = session.Save()
			ctx.Redirect(http.StatusFound, common.ConfigProxyRedirectLoginURL())
			return
		}

		key, err := totp.Generate(totp.GenerateOpts{
			Issuer:      "Kagi-Proxy",
			AccountName: request.Username,
			Period:      30, // 30 seconds
			Digits:      otp.DigitsEight,
			Algorithm:   otp.AlgorithmSHA1,
			SecretSize:  uint(len(common.ConfigProxyOTPSecret())),
			Rand:        bytes.NewReader([]byte(common.ConfigProxyOTPSecret())),
		})
		if err != nil {
			common.Logger().Error("failed to generate OTP", zap.Error(err))
			session.AddFlash("Internal server error")
			_ = session.Save()
			ctx.Redirect(http.StatusFound, common.ConfigProxyRedirectLoginURL())
			return
		}

		var response struct {
			QRCode string `json:"qrCode"`
			Secret string `json:"secret"`
			URL    string `json:"url"`
		}

		img, err := key.Image(request.Width, request.Height)
		if err != nil {
			common.Logger().Error("failed to generate QR code", zap.Error(err))
			session.AddFlash("Internal server error")
			_ = session.Save()
			ctx.Redirect(http.StatusFound, common.ConfigProxyRedirectLoginURL())
			return
		}

		var buf bytes.Buffer
		if err := png.Encode(&buf, img); err != nil {
			common.Logger().Error("failed to encode QR code", zap.Error(err))
			session.AddFlash("Internal server error")
			_ = session.Save()
			ctx.Redirect(http.StatusFound, common.ConfigProxyRedirectLoginURL())
			return
		}

		response.QRCode = "data:image/png;base64," + base64.StdEncoding.EncodeToString(buf.Bytes())
		response.Secret = key.Secret()
		response.URL = key.URL()

		ctx.JSON(http.StatusOK, response)
	}
}

// HandleLogin is a handler that authenticates the user.
func HandleLogin() gin.HandlerFunc {
	b32NoPadding := base32.StdEncoding.WithPadding(base32.NoPadding)

	return func(ctx *gin.Context) {
		session := sessions.Default(ctx)
		if len(common.ConfigProxyOTPSecret()) == 0 {
			common.Logger().Error("OTP secret is not set")
			session.AddFlash("Internal server error")
			_ = session.Save()
			ctx.Redirect(http.StatusFound, common.ConfigProxyRedirectLoginURL())
			return
		}

		var request struct {
			Username string `json:"username" form:"username" binding:"required"`
			Password string `json:"password" form:"password" binding:"required"`
			OTP      string `json:"otp" form:"otp" binding:"required,max=8,min=8,numeric"`
		}
		if err := ctx.ShouldBind(&request); err != nil {
			common.Logger().Error("failed to bind JSON", zap.Error(err))
			session.AddFlash("Invalid request")
			_ = session.Save()
			ctx.Redirect(http.StatusFound, common.ConfigProxyRedirectLoginURL())
			return
		}

		validUsername := CTEqual(request.Username, common.ConfigProxyUser())
		validPassword := CTEqual(request.Password, common.ConfigProxyPass())
		validOTP, err := totp.ValidateCustom(
			request.OTP,
			b32NoPadding.EncodeToString([]byte(common.ConfigProxyOTPSecret())),
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
			_ = session.Save()
			ctx.Redirect(http.StatusFound, common.ConfigProxyRedirectLoginURL())
			return
		}

		if validUsername && validPassword && validOTP {
			session.Set("user", request.Username)
			_ = session.Save()

			redirectURL := session.Get("redirect_url")
			session.Delete("redirect_url")
			_ = session.Save()

			if redirectURL != nil {
				ctx.Redirect(http.StatusFound, redirectURL.(string))
				return
			}

			ctx.Redirect(http.StatusFound, "/")
			return

		}

		common.Logger().Info("invalid credentials",
			zap.Bool("valid_username", validUsername),
			zap.Bool("valid_password", validPassword),
			zap.Bool("valid_otp", validOTP))
		session.AddFlash("Invalid credentials")
		_ = session.Save()
		ctx.Redirect(http.StatusFound, common.ConfigProxyRedirectLoginURL())
	}
}

// HandleLogout is a handler that logs out the user.
func HandleLogout() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		session := sessions.Default(ctx)
		session.Clear()
		_ = session.Save()

		ctx.Redirect(http.StatusFound, common.ConfigProxyRedirectLoginURL())
	}
}

// SetContentSecurityHeaders sets the Content-Security-Policy, X-Frame-Options, and X-Content-Type-Options headers.
func SetContentSecurityHeaders(w http.ResponseWriter, nonce string) {
	w.Header().Set("Content-Security-Policy", strings.Join([]string{
		"default-src 'none'",
		"script-src 'self' 'nonce-" + nonce + "'",
		"style-src 'self' 'nonce-" + nonce + "'",
		"img-src 'self' data:",
		"connect-src 'self'",
		"form-action 'self'",
		"frame-ancestors 'none'",
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
func ShowLogin() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		session := sessions.Default(ctx)
		flash := session.Flashes()
		_ = session.Save()

		token := csrf.GetToken(ctx)
		nonce, err := GetNonce()
		if err != nil {
			ctx.HTML(http.StatusInternalServerError, "error.html", gin.H{
				"error": html.EscapeString(err.Error()),
				"code":  http.StatusInternalServerError,
				"nonce": nonce,
			})
			return
		}

		SetContentSecurityHeaders(ctx.Writer, nonce)
		ctx.HTML(http.StatusOK, "login.html", gin.H{
			"login_action": common.ConfigProxyRedirectLoginURL(),
			"csrf_token":   token,
			"flash":        flash,
			"nonce":        nonce,
			"setup_action": common.ConfigProxyGenerateQRCodeURL(),
		})
	}
}
