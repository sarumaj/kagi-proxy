package endpoints

import (
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sarumaj/kagi-proxy/pkg/api/middlewares"
	"github.com/sarumaj/kagi-proxy/pkg/api/templates"
	"github.com/sarumaj/kagi-proxy/pkg/common"
)

// csrfField pulls the token the login template embeds in both of its forms.
var csrfField = regexp.MustCompile(`name="_csrf" value="([^"]*)"`)

// signinServer boots the /signin routes exactly as main.go wires them, with the default
// proxy host, and returns the base URL plus a client whose cookie jar enforces the same
// RFC 6265 domain matching a browser applies.
func signinServer(t *testing.T) (string, *http.Client) {
	t.Helper()

	gin.SetMode(gin.TestMode)

	common.SetProxyUser("user")
	common.SetProxyPass("pass")
	common.SetProxyOTPSecret("test")
	common.SetProxySessionSecret("test")
	common.SetSessionToken("")
	common.SetProxyRedirectLoginURL("/signin")
	common.SetProxySessionDuration(30 * 24 * time.Hour)
	common.SetProxyGuardPolicy(common.Policy{})
	// The defaults from main.go: the operator has not told the proxy it is being reached
	// on localhost, so the cookie domain is derived from the proxied host.
	common.SetProxyTargetHosts(common.HostMap{
		"kagi.com":           "kagi.com",
		"assets.kagi.com":    "assets.kagi.com",
		"help.kagi.com":      "help.kagi.com",
		"status.kagi.com":    "status.kagi.com",
		"translate.kagi.com": "translate.kagi.com",
	})

	router := gin.New(func(e *gin.Engine) {
		e.SetHTMLTemplate(templates.HTMLTemplates())
		e.Use(middlewares.Session())
	})
	login := router.Group("/signin", middlewares.CSRF())
	login.GET("/", SignInWeb)
	login.POST("/", SignInForm)

	server := httptest.NewServer(router)
	t.Cleanup(server.Close)

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}

	return server.URL, &http.Client{
		Jar: jar,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// TestSignUpIssuesQRCodeOverLocalhost reproduces the reported failure: the QR code never
// renders because the CSRF check rejects the POST. The token itself is fine — the session
// cookie carrying its counterpart is discarded by the browser before the form is
// submitted, so the POST arrives against an empty session.
func TestSignUpIssuesQRCodeOverLocalhost(t *testing.T) {
	base, client := signinServer(t)

	page, err := client.Get(base + "/signin/")
	if err != nil {
		t.Fatal(err)
	}
	defer page.Body.Close()

	body, err := io.ReadAll(page.Body)
	if err != nil {
		t.Fatal(err)
	}

	match := csrfField.FindSubmatch(body)
	if match == nil {
		t.Fatal("login page carried no _csrf field")
	}

	parsed, err := url.Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	if stored := client.Jar.Cookies(parsed); len(stored) == 0 {
		t.Fatalf("the browser stored no session cookie for %s; Set-Cookie was %q",
			parsed.Host, page.Header.Values("Set-Cookie"))
	}

	form := url.Values{
		"_csrf":    {string(match[1])},
		"username": {common.ConfigProxyUser()},
		"width":    {"200"},
		"height":   {"200"},
	}
	resp, err := client.PostForm(base+"/signin/?signup=true", form)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	// The handler answers a successful signup with a redirect that carries the encoded QR
	// payload; a bare redirect back to the login page means the CSRF gate rejected it.
	if resp.StatusCode == http.StatusSeeOther && !strings.Contains(resp.Header.Get("Location"), "data=") {
		t.Fatalf("signup bounced back to %q instead of returning a QR code", resp.Header.Get("Location"))
	}
}
