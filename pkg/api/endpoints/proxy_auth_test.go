package endpoints

import (
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/sarumaj/kagi-proxy/pkg/api/middlewares"
	"github.com/sarumaj/kagi-proxy/pkg/api/templates"
	"github.com/sarumaj/kagi-proxy/pkg/common"
	"golang.org/x/crypto/bcrypt"
)

const (
	proxyHost  = "kagi.sarumaj.com"
	ownerToken = "OWNER-SUBSCRIPTION-TOKEN"
)

// authFixture runs the production middleware chain (session, auth, guard) in front of
// ProxyState. Only the upstream transport is substituted, so everything the patches
// touched — the director, the response rewriting and the auth gate ahead of them — is
// exercised as deployed.
type authFixture struct {
	front      *httptest.Server
	upstream   *httptest.Server
	seen       chan *http.Request
	setCookies []string
}

func newAuthFixture(t *testing.T) *authFixture {
	t.Helper()

	gin.SetMode(gin.TestMode)

	common.SetProxyUser("owner")
	common.SetProxyPass("pass")
	common.SetSessionToken(ownerToken)
	common.SetProxyRedirectLoginURL("/signin")
	common.SetProxySessionDuration(3600)
	common.SetProxySessionSecret("test-secret")
	common.SetProxyPublicDomains(common.Domains{})
	common.SetProxyGuardPolicy(common.Policy{})

	fixture := &authFixture{seen: make(chan *http.Request, 8)}

	fixture.upstream = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fixture.seen <- r.Clone(r.Context())
		for _, cookie := range fixture.setCookies {
			w.Header().Add("Set-Cookie", cookie)
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("upstream"))
	}))
	t.Cleanup(fixture.upstream.Close)

	upstreamHost := strings.TrimPrefix(fixture.upstream.URL, "http://")
	common.SetProxyTargetHosts(common.HostMap{proxyHost: "kagi.com"})

	state := ProxyState{}
	reverse := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			state.Director(pr.Out)
			pr.Out.URL.Scheme, pr.Out.URL.Host = "http", upstreamHost
		},
		ModifyResponse: state.ModifyResponse,
	}

	router := gin.New(func(e *gin.Engine) {
		e.SetHTMLTemplate(templates.HTMLTemplates())
		e.Use(middlewares.Session())
		e.Use(middlewares.Rate(1000, 1000))
	})
	router.NoRoute(middlewares.BasicAuth(), middlewares.ProxyGuard(), func(ctx *gin.Context) {
		reverse.ServeHTTP(ctx.Writer, ctx.Request)
	})

	fixture.front = httptest.NewServer(router)
	t.Cleanup(fixture.front.Close)

	return fixture
}

// get issues a request carrying the supplied Cookie header, without following redirects.
func (f *authFixture) get(t *testing.T, path, cookie string) *http.Response {
	t.Helper()

	req, err := http.NewRequest(http.MethodGet, f.front.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = proxyHost
	if len(cookie) > 0 {
		req.Header.Set("Cookie", cookie)
	}

	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	return resp
}

// proxyToken mints the bcrypt-hash query parameter that BasicAuth accepts as a session link.
func proxyToken(t *testing.T) string {
	t.Helper()

	hash, err := bcrypt.GenerateFromPassword([]byte(common.ConfigProxyUser()), 12)
	if err != nil {
		t.Fatal(err)
	}

	return common.B64URLNoPadding.EncodeToString(hash)
}

// TestUnauthenticatedRequestIsRejected confirms the proxy still refuses to forward
// anything before the visitor has a session: stripping cookies in the director must not
// weaken the gate that runs ahead of it.
func TestUnauthenticatedRequestIsRejected(t *testing.T) {
	fixture := newAuthFixture(t)

	resp := fixture.get(t, "/search?q=cats", "")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusSeeOther {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusSeeOther)
	}
	if got := resp.Header.Get("Location"); got != "/signin" {
		t.Errorf("Location = %q, want /signin", got)
	}
	select {
	case req := <-fixture.seen:
		t.Fatalf("unauthenticated request reached the upstream: %s", req.URL)
	default:
	}
}

// TestAuthenticatedRequestCarriesOwnerToken covers the whole authenticated round trip:
// the proxy session is accepted, the shared subscription token is injected, and the
// proxy's own cookie stays behind.
func TestAuthenticatedRequestCarriesOwnerToken(t *testing.T) {
	fixture := newAuthFixture(t)

	resp := fixture.get(t, "/search?q=cats&proxy_token="+proxyToken(t), "")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	var session string
	for _, cookie := range resp.Cookies() {
		if cookie.Name == "proxy_session" {
			session = cookie.Name + "=" + cookie.Value
		}
	}
	if len(session) == 0 {
		t.Fatal("no proxy_session cookie was issued")
	}

	req := <-fixture.seen
	cookie := req.Header.Get("Cookie")
	if strings.Contains(cookie, "proxy_session") {
		t.Errorf("Cookie = %q, leaks proxy_session upstream", cookie)
	}
	if !strings.Contains(cookie, "kagi_session="+ownerToken) {
		t.Errorf("Cookie = %q, want the owner token injected", cookie)
	}
	if strings.Contains(req.URL.RawQuery, "proxy_token") {
		t.Errorf("RawQuery = %q, leaks proxy_token upstream", req.URL.RawQuery)
	}

	// The session issued above must authenticate a follow-up request on its own.
	second := fixture.get(t, "/search?q=dogs", session)
	defer second.Body.Close()
	if second.StatusCode != http.StatusOK {
		t.Fatalf("second request status = %d, want 200", second.StatusCode)
	}
	<-fixture.seen
}

// TestOwnerTokenSurvivesUpstreamSessionCookie is the regression guard for the Set-Cookie
// domain rewriting. Once upstream cookies are re-scoped onto the proxy domain the browser
// starts returning kagi_session, and a director that trusts whatever the client sent would
// forward that value instead of the paid subscription token — silently signing every user
// out of the shared account.
func TestOwnerTokenSurvivesUpstreamSessionCookie(t *testing.T) {
	fixture := newAuthFixture(t)
	fixture.setCookies = []string{
		"kagi_session=ANONYMOUS-UPSTREAM-SESSION; Path=/; Domain=kagi.com; Secure; HttpOnly",
		"theme=dark; Path=/; Domain=.kagi.com",
	}

	resp := fixture.get(t, "/?proxy_token="+proxyToken(t), "")
	defer resp.Body.Close()
	<-fixture.seen

	var session, replay string
	for _, cookie := range resp.Cookies() {
		switch cookie.Name {
		case "proxy_session":
			session = cookie.Name + "=" + cookie.Value
		case "kagi_session":
			t.Errorf("upstream kagi_session was handed to the browser (Domain=%q); "+
				"this both shadows the injected token and distributes the subscription", cookie.Domain)
			replay = cookie.Name + "=" + cookie.Value
		case "theme":
			if cookie.Domain != "."+proxyHost && cookie.Domain != proxyHost {
				t.Errorf("theme cookie Domain = %q, want it re-scoped onto %q", cookie.Domain, proxyHost)
			}
			replay = strings.TrimPrefix(replay+"; "+cookie.Name+"="+cookie.Value, "; ")
		}
	}

	// Replay what the browser would now send back.
	second := fixture.get(t, "/", strings.TrimPrefix(session+"; "+replay, "; "))
	defer second.Body.Close()

	req := <-fixture.seen
	if !strings.Contains(req.Header.Get("Cookie"), "kagi_session="+ownerToken) {
		t.Errorf("Cookie = %q, want the owner token still injected", req.Header.Get("Cookie"))
	}
	if strings.Contains(req.Header.Get("Cookie"), "ANONYMOUS-UPSTREAM-SESSION") {
		t.Errorf("Cookie = %q, forwards the upstream anonymous session", req.Header.Get("Cookie"))
	}
}
