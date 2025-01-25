package endpoints

import (
	"bytes"
	"html/template"
	"image/png"
	"net/http"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/sarumaj/kagi-proxy/pkg/common"
	"github.com/sarumaj/kagi-proxy/pkg/common/web"
	csrf "github.com/utrack/gin-csrf"
	"go.uber.org/zap"
	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
)

// SignInForm is a handler that authenticates the user.
// If the user is not authenticated, it redirects to the login page.
// If the user is authenticated, it redirects to the root page or
// the location he attempted to access before page.
// It supports two actions: login and signup.
// Login action authenticates the user with username, password, and OTP.
// Signup action generates a QR code for the user to set up OTP.
func SignInForm(ctx *gin.Context) {
	session := sessions.Default(ctx)

	// Check if the OTP secret is set
	if len(common.ConfigProxyOTPSecret()) == 0 {
		common.Logger().Error("OTP secret is not set")
		session.AddFlash("Internal server error")
		if !web.SessionSave(session, ctx) {
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
		if !web.SessionSave(session, ctx) {
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
			if !web.SessionSave(session, ctx) {
				return
			}
			ctx.Redirect(http.StatusSeeOther, common.ConfigProxyRedirectLoginURL()+"?signup=true")
			return
		}

		validUsername := common.CTEqual(request.Username, common.ConfigProxyUser())
		if !validUsername {
			common.Logger().Info("invalid username", zap.String("username", request.Username))
			session.AddFlash("Invalid username")
			if !web.SessionSave(session, ctx) {
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
			if !web.SessionSave(session, ctx) {
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
			if !web.SessionSave(session, ctx) {
				return
			}
			ctx.Redirect(http.StatusSeeOther, common.ConfigProxyRedirectLoginURL()+"?signup=true")
			return
		}

		var buf bytes.Buffer
		if err := png.Encode(&buf, img); err != nil {
			common.Logger().Error("failed to encode QR code", zap.Error(err))
			session.AddFlash("Internal server error")
			if !web.SessionSave(session, ctx) {
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
			"qr_code": html.Token{
				Data: atom.Img.String(),
				Type: html.SelfClosingTagToken,
				Attr: []html.Attribute{
					{Key: "src", Val: "data:image/png;base64," + common.B64StdWithPadding.EncodeToString(buf.Bytes())},
					{Key: "alt", Val: "QR code"},
				},
			}.String(),
			"secret_key": key.URL(),
		}, []byte(common.ConfigProxyPass()), session)
		if err != nil {
			common.Logger().Error("failed to encode query parameter", zap.Error(err))
			session.AddFlash("Internal server error")
			if !web.SessionSave(session, ctx) {
				return
			}
			ctx.Redirect(http.StatusSeeOther, common.ConfigProxyRedirectLoginURL()+"?signup=true")
			return
		}
		if !web.SessionSave(session, ctx) {
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
		if !web.SessionSave(session, ctx) {
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
		if !web.SessionSave(session, ctx) {
			return
		}
		ctx.Redirect(http.StatusSeeOther, common.ConfigProxyRedirectLoginURL())
		return
	}

	// Success: Redirect the user to the root page or the location he attempted to access before page
	if validUsername && validPassword && validOTP {
		session.Set("user", request.Username)
		sessionId, _ := uuid.NewRandom()
		session.Set("session_id", sessionId.String())
		session.Set("created_at", time.Now().Unix())
		redirectURL := session.Get("redirect_url")
		session.Delete("redirect_url")
		if !web.SessionSave(session, ctx) {
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
	if !web.SessionSave(session, ctx) {
		return
	}
	ctx.Redirect(http.StatusSeeOther, common.ConfigProxyRedirectLoginURL())
}

// SignInWeb is a handler that displays the login page.
// It displays the login page with renders the flash messages originating from the session.
func SignInWeb(ctx *gin.Context) {
	session := sessions.Default(ctx)
	flash := session.Flashes()
	if !web.SessionSave(session, ctx) {
		return
	}

	var query struct {
		SignUp bool   `form:"signup"`
		Data   string `form:"data"`
	}
	if err := ctx.ShouldBindQuery(&query); err != nil {
		common.Logger().Error("failed to bind query", zap.Error(err))
		session.AddFlash("Invalid request")
		if !web.SessionSave(session, ctx) {
			return
		}

		ctx.Redirect(http.StatusSeeOther, common.ConfigProxyRedirectLoginURL())
		return
	}

	token := csrf.GetToken(ctx)
	nonce, _ := common.GetNonce()

	// Decode the QR code and the OTP setup URL from the location fragment
	var data map[string]any
	if len(query.Data) > 0 {
		var err error
		data, err = common.DecodeFromQuery(query.Data, []byte(common.ConfigProxyPass()), session)
		if err != nil {
			common.Logger().Warn("failed to decode data from query", zap.Error(err))
		} else if !web.SessionSave(session, ctx) {
			return
		}
	}

	common.Logger().Debug("Displaying login page",
		zap.String("nonce", nonce),
		zap.Any("flash", flash),
		zap.String("token", token),
		zap.String("path", ctx.Request.URL.Path),
		zap.Bool("setup_active", query.SignUp),
		zap.Reflect("data", data))

	web.SetContentSecurityHeaders(ctx.Writer, nonce)
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
