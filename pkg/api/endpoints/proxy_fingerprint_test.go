package endpoints

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"strings"
	"testing"

	"github.com/sarumaj/kagi-proxy/pkg/common"
)

func setup() {
	common.SetProxyTargetHosts(common.HostMap{
		"kagi.sarumaj.com":        "kagi.com",
		"assets.kagi.sarumaj.com": "assets.kagi.com",
	})
	common.SetSessionToken("KAGITOKEN")
	common.SetProxyGuardPolicy(common.Policy{})
}

// TestUpstreamRequestLooksDirect asserts that nothing identifying the hop survives
// the director: no forwarded metadata, no proxy cookie, no synthesised Origin.
func TestUpstreamRequestLooksDirect(t *testing.T) {
	setup()

	var seen *http.Request
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Clone(r.Context())
		w.Header().Add("Set-Cookie", "kagi_session=abc; Path=/; Domain=kagi.com; Secure; HttpOnly")
		w.Header().Add("Set-Cookie", "theme=dark; Path=/; Domain=.kagi.com")
		w.Header().Add("Set-Cookie", "hostonly=1; Path=/")
		w.Header().Set("Content-Type", "text/plain")
	}))
	defer upstream.Close()

	state := ProxyState{}
	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			state.Director(pr.Out)
			// redirect to the test upstream, preserving the rewritten Host
			pr.Out.URL.Scheme, pr.Out.URL.Host = "http", strings.TrimPrefix(upstream.URL, "http://")
		},
		ModifyResponse: state.ModifyResponse,
	}

	front := httptest.NewServer(rp)
	defer front.Close()

	req, _ := http.NewRequest(http.MethodGet, front.URL+"/search?q=cats", nil)
	req.Host = "kagi.sarumaj.com"
	req.Header.Set("Referer", "https://kagi.sarumaj.com/settings")
	req.Header.Set("Cookie", "proxy_session=SECRETBLOB; theme=dark")
	req.Header.Set("X-Request-Id", "heroku-abc")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("Via", "1.1 heroku-router")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if seen == nil {
		t.Fatal("upstream never received the request")
	}

	if got := seen.Header.Get("Referer"); got != "https://kagi.com/settings" {
		t.Errorf("Referer = %q, want https://kagi.com/settings", got)
	}
	if got := seen.Header.Get("Origin"); got != "" {
		t.Errorf("Origin = %q, want it absent (browser omits it on navigation)", got)
	}
	for _, h := range []string{"X-Forwarded-For", "X-Forwarded-Proto", "X-Request-Id", "Via"} {
		if got := seen.Header.Get(h); got != "" {
			t.Errorf("%s = %q, want it stripped", h, got)
		}
	}
	cookie := seen.Header.Get("Cookie")
	if strings.Contains(cookie, "proxy_session") {
		t.Errorf("Cookie = %q, still leaks proxy_session", cookie)
	}
	if n := strings.Count(cookie, "kagi_session="); n != 1 {
		t.Errorf("Cookie = %q, want exactly one kagi_session, got %d", cookie, n)
	}

	// kagi_session is absent by design: the proxy manages the upstream session itself, so
	// the target host's own copy is withheld rather than re-scoped. See
	// TestOwnerTokenSurvivesUpstreamSessionCookie.
	want := map[string]bool{
		"theme=dark; Path=/; Domain=.kagi.sarumaj.com": true,
		"hostonly=1; Path=/":                           true,
	}
	for _, v := range resp.Header.Values("Set-Cookie") {
		if !want[v] {
			t.Errorf("unexpected Set-Cookie %q", v)
		}
		delete(want, v)
	}
	for v := range want {
		t.Errorf("missing Set-Cookie %q", v)
	}
}

// TestRewriteURLHeaderKeepsThirdPartyOrigins guards against clobbering a Referer that
// legitimately points outside the proxied domains.
func TestRewriteURLHeaderKeepsThirdPartyOrigins(t *testing.T) {
	setup()

	req, _ := http.NewRequest(http.MethodGet, "https://kagi.com/", nil)
	req.Header.Set("Referer", "https://example.org/page")
	rewriteURLHeader(req, "Referer")
	if got := req.Header.Get("Referer"); got != "https://example.org/page" {
		t.Errorf("Referer = %q, want it untouched", got)
	}

	req.Header.Set("Origin", "https://assets.kagi.sarumaj.com")
	rewriteURLHeader(req, "Origin")
	if got := req.Header.Get("Origin"); got != "https://assets.kagi.com" {
		t.Errorf("Origin = %q, want https://assets.kagi.com", got)
	}
}

// TestUpstreamSpeaksHTTP2 pins the transport to HTTP/2. Setting TLSClientConfig without
// ForceAttemptHTTP2 silently drops the connection to HTTP/1.1, where Go emits
// canonicalised, alphabetically sorted header names that no browser produces.
func TestUpstreamSpeaksHTTP2(t *testing.T) {
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(r.Proto))
	}))
	upstream.EnableHTTP2 = true
	upstream.StartTLS()
	defer upstream.Close()

	pool := x509.NewCertPool()
	pool.AddCert(upstream.Certificate())

	transport := &http.Transport{
		ForceAttemptHTTP2: true,
		TLSClientConfig: &tls.Config{
			RootCAs:    pool,
			MinVersion: tls.VersionTLS12,
			NextProtos: []string{"h2", "http/1.1"},
		},
	}

	resp, err := (&http.Client{Transport: transport}).Get(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.Proto != "HTTP/2.0" {
		t.Errorf("negotiated %s, want HTTP/2.0", resp.Proto)
	}
}
