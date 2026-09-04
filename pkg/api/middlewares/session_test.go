package middlewares

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/sarumaj/kagi-proxy/pkg/common"
)

// TestSessionCookieScoping pins how the session cookie is scoped per host. The Domain
// attribute must stay on the proxied domain so one login covers every proxied subdomain,
// and must be absent everywhere else, because a browser silently discards a cookie whose
// Domain does not match the host that issued it.
func TestSessionCookieScoping(t *testing.T) {
	gin.SetMode(gin.TestMode)

	common.SetSessionToken("token")
	common.SetProxySessionDuration(30 * 24 * time.Hour)
	common.SetProxyTargetHosts(common.HostMap{
		"kagi.sarumaj.com":        "kagi.com",
		"assets.kagi.sarumaj.com": "assets.kagi.com",
	})

	router := gin.New(func(e *gin.Engine) { e.Use(Session()) })
	router.GET("/", func(ctx *gin.Context) {
		session := sessions.Default(ctx)
		session.Set("user", "owner")
		if err := session.Save(); err != nil {
			ctx.Status(http.StatusInternalServerError)
			return
		}
		ctx.Status(http.StatusOK)
	})

	for _, tt := range []struct {
		name       string
		host       string
		forwarded  string
		wantDomain string
		wantSecure bool
	}{
		{
			name: "proxied apex keeps the shared domain",
			host: "kagi.sarumaj.com", forwarded: "https",
			wantDomain: "kagi.sarumaj.com", wantSecure: true,
		},
		{
			name: "proxied subdomain shares the same session",
			host: "assets.kagi.sarumaj.com", forwarded: "https",
			wantDomain: "kagi.sarumaj.com", wantSecure: true,
		},
		{
			// Without this the cookie is dropped, every request starts a fresh session and
			// the CSRF check rejects each form POST.
			name:       "localhost gets a host-only cookie it will actually keep",
			host:       "localhost:8080",
			wantDomain: "", wantSecure: false,
		},
		{
			name:       "loopback address behaves like localhost",
			host:       "127.0.0.1:8080",
			wantDomain: "", wantSecure: false,
		},
		{
			// A plain-HTTP hop from the platform edge must not downgrade the attribute.
			name: "unproxied host over a forwarded TLS hop stays secure",
			host: "preview.example.com", forwarded: "https",
			wantDomain: "", wantSecure: true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Host = tt.host
			if len(tt.forwarded) > 0 {
				req.Header.Set("X-Forwarded-Proto", tt.forwarded)
			}

			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200", rec.Code)
			}

			cookies := (&http.Response{Header: rec.Header()}).Cookies()
			var issued *http.Cookie
			for _, cookie := range cookies {
				if cookie.Name == sessionName {
					issued = cookie
				}
			}
			if issued == nil {
				t.Fatalf("no %s cookie was issued", sessionName)
			}

			if issued.Domain != tt.wantDomain {
				t.Errorf("Domain = %q, want %q", issued.Domain, tt.wantDomain)
			}
			if issued.Secure != tt.wantSecure {
				t.Errorf("Secure = %t, want %t", issued.Secure, tt.wantSecure)
			}
		})
	}
}
