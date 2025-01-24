package endpoints

import (
	"fmt"
	"html"
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/sarumaj/kagi-proxy/pkg/common"
	"github.com/sarumaj/kagi-proxy/pkg/common/web"
)

// CheckHealth is a health check endpoint.
// It returns a 200 OK status code.
func CheckHealth(ctx *gin.Context) { ctx.Status(http.StatusOK) }

// CheckStatus is a workaround to return a valid response for status.kagi.com.
// Status.kagi.com returns for some requests a valid response but the status is always "404".
// This is a workaround to return a valid response.
func CheckStatus(ctx *gin.Context) {
	resp, err := http.Get("https://status.kagi.com/" + strings.TrimPrefix(ctx.Request.URL.Path, "/"))
	if err != nil {
		nonce, _ := common.GetNonce()
		web.SetContentSecurityHeaders(ctx.Writer, nonce)
		ctx.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"error": html.EscapeString(fmt.Errorf("%v", err).Error()),
			"code":  http.StatusInternalServerError,
			"nonce": nonce,
		})
		return
	}

	if resp.Body != nil {
		defer resp.Body.Close()
		ctx.DataFromReader(http.StatusOK, resp.ContentLength, resp.Header.Get("Content-Type"), resp.Body, nil)
		return
	}

	ctx.JSON(http.StatusOK, gin.H{
		"page": gin.H{
			"name":   ctx.Request.URL.Hostname(),
			"url":    (&url.URL{Scheme: ctx.Request.URL.Scheme, Host: ctx.Request.URL.Hostname()}).String(),
			"status": "UP",
		},
	})
}
