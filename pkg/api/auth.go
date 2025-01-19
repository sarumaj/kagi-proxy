package api

import (
	"crypto/subtle"
	"net/http"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	csrf "github.com/utrack/gin-csrf"
	"golang.org/x/time/rate"
)

// RedirectLoginURL is the URL to redirect to when the user is not authenticated.
var RedirectLoginURL = "/login"

// BasicAuth is a middleware that checks if the user is authenticated.
func BasicAuth(exceptPaths []string) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		for _, path := range exceptPaths {
			if ctx.Request.URL.Path == path {
				ctx.Next()
				return
			}
		}

		session := sessions.Default(ctx)
		user := session.Get("user")
		if user == nil {
			session.Set("redirect_url", ctx.Request.URL.String())
			_ = session.Save()

			ctx.Redirect(http.StatusFound, RedirectLoginURL)
			ctx.Abort()
			return
		}

		ctx.Next()
	}
}

// CSRF is a middleware that checks if the CSRF token is valid.
func CSRF(secret string) gin.HandlerFunc {
	return csrf.Middleware(csrf.Options{
		Secret: secret,
		ErrorFunc: func(ctx *gin.Context) {
			session := sessions.Default(ctx)
			session.AddFlash("Invalid CSRF token")
			_ = session.Save()

			ctx.Redirect(http.StatusFound, RedirectLoginURL)
			ctx.Abort()
		},
	})
}

// HandleLogin is a handler that authenticates the user.
func HandleLogin(username, password string) gin.HandlerFunc {
	loginLimiter := rate.NewLimiter(rate.Every(5*time.Second), 3) // 3 attempts every 5 seconds

	return func(ctx *gin.Context) {
		session := sessions.Default(ctx)
		if !loginLimiter.Allow() {
			session.AddFlash("Too many login attempts. Please try again later.")
			_ = session.Save()
			ctx.Redirect(http.StatusFound, RedirectLoginURL)
			return
		}

		submittedUsername := ctx.PostForm("username")
		submittedPassword := ctx.PostForm("password")

		validUsername := subtle.ConstantTimeCompare([]byte(submittedUsername), []byte(username)) == 1
		validPassword := subtle.ConstantTimeCompare([]byte(submittedPassword), []byte(password)) == 1

		if validUsername && validPassword {
			session.Set("user", username)
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

		session.AddFlash("Invalid credentials")
		_ = session.Save()
		ctx.Redirect(http.StatusFound, RedirectLoginURL)
	}
}

// HandleLogout is a handler that logs out the user.
func HandleLogout() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		session := sessions.Default(ctx)
		session.Clear()
		_ = session.Save()

		ctx.Redirect(http.StatusFound, RedirectLoginURL)
	}
}

// ShowLogin is a handler that displays the login page.
func ShowLogin() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		session := sessions.Default(ctx)
		flash := session.Flashes()
		_ = session.Save()

		token := csrf.GetToken(ctx)

		ctx.HTML(http.StatusOK, "login.html", gin.H{
			"flash":      flash,
			"csrf_token": token,
		})
	}
}
