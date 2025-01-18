package api

import (
	"net/http"
	"net/url"
	"time"

	"github.com/gin-gonic/gin"
)

const (
	tokenSourceQueryParam = "token"
	sessionCookieName     = "kagi_session"
	targetHostDomain      = "kagi.com"
)

func Redirect(sessionToken string) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		targetUrl := &url.URL{
			Scheme:     "https",
			Host:       targetHostDomain,
			User:       ctx.Request.URL.User,
			Opaque:     ctx.Request.URL.Opaque,
			Path:       ctx.Request.URL.Path,
			RawPath:    ctx.Request.URL.RawPath,
			RawQuery:   ctx.Request.URL.RawQuery,
			Fragment:   ctx.Request.URL.Fragment,
			OmitHost:   ctx.Request.URL.OmitHost,
			ForceQuery: ctx.Request.URL.ForceQuery,
		}

		if token := ctx.Query(tokenSourceQueryParam); token != "" {
			ctx.Redirect(http.StatusMovedPermanently, targetUrl.String())
			return
		}

		if token, err := ctx.Cookie(sessionCookieName); err == nil && token != "" {
			ctx.Redirect(http.StatusMovedPermanently, targetUrl.String())
			return
		}

		ctx.SetCookie(sessionCookieName, sessionToken, int(time.Hour.Seconds()), "/", targetHostDomain, true, true)
		ctx.Redirect(http.StatusMovedPermanently, targetUrl.String())
	}
}
