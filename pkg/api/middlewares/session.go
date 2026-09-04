package middlewares

import (
	"net"
	"net/http"
	"strings"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	gsessions "github.com/gorilla/sessions"
	"github.com/sarumaj/kagi-proxy/pkg/common"
)

// sessionName is the cookie the proxy keeps its own session in.
const sessionName = "proxy_session"

type (
	// hostScopedStore fixes the session cookie's Domain and Secure attributes to the host
	// the browser is actually talking to.
	//
	// The Domain attribute is what lets one login span the proxied subdomains, but a
	// browser discards any cookie whose Domain does not match the host that issued it.
	// Pinning it to the proxied domain therefore loses the cookie on every other host the
	// proxy answers on — notably localhost during development, where the dropped session
	// makes each request start empty and the CSRF check reject every form submission.
	//
	// Scoping happens in the store rather than in a second middleware because the session
	// is created lazily on first use, and gin-csrf writes the cookie from inside its own
	// middleware, before any handler of this package runs.
	hostScopedStore struct {
		sessions.Store
		base string
	}
)

// Get implements the sessions.Store interface for hostScopedStore.
func (s hostScopedStore) Get(req *http.Request, name string) (*gsessions.Session, error) {
	session, err := s.Store.Get(req, name)
	s.scope(req, session)
	return session, err
}

// New implements the sessions.Store interface for hostScopedStore.
func (s hostScopedStore) New(req *http.Request, name string) (*gsessions.Session, error) {
	session, err := s.Store.New(req, name)
	s.scope(req, session)
	return session, err
}

// scope overwrites the cookie attributes that depend on how the browser reached the proxy.
func (s hostScopedStore) scope(req *http.Request, session *gsessions.Session) {
	if session == nil {
		return
	}

	host := req.Host
	if hostname, _, err := net.SplitHostPort(host); err == nil {
		host = hostname
	}

	// Outside the proxied domain a host-only cookie is the only one the browser keeps, and
	// the subdomain sharing that the Domain attribute buys does not apply there anyway.
	domain := s.base
	if !strings.EqualFold(host, s.base) && !strings.HasSuffix(strings.ToLower(host), "."+strings.ToLower(s.base)) {
		domain = ""
	}

	session.Options = sessionOptions(domain, secureCookie(req, host)).ToGorillaOptions()
}

// Session is a middleware that manages the session.
// It sets the session cookie with the domain and secret.
// If the domain is empty, it will log a fatal error.
// If the secret is at least 64 bytes, it setup an AES-GCM encryption.
func Session() gin.HandlerFunc {
	domain := common.ConfigProxyTargetHosts().Base()
	if len(domain) == 0 {
		common.Logger().Fatal("domain is required")
	}

	hashKey, blockKey := common.MakeKeyPair([]byte(common.ConfigSessionToken()))
	store := cookie.NewStore(hashKey, blockKey)
	store.Options(sessionOptions(domain, true))

	return sessions.Sessions(sessionName, hostScopedStore{Store: store, base: domain})
}

// secureCookie reports whether the session cookie may carry the Secure attribute.
//
// TLS terminates at the platform edge, so the request reaching this process is plain HTTP
// and only the forwarded scheme reveals what the browser used. The attribute therefore
// stays on unless the browser is plainly speaking HTTP to a loopback address, which is the
// local development case where a Secure cookie would be refused.
func secureCookie(req *http.Request, host string) bool {
	if req.TLS != nil || strings.EqualFold(req.Header.Get("X-Forwarded-Proto"), "https") {
		return true
	}

	if ip := net.ParseIP(host); ip != nil {
		return !ip.IsLoopback()
	}

	return !strings.EqualFold(host, "localhost")
}

// sessionOptions builds the cookie attributes for the proxy session.
func sessionOptions(domain string, secure bool) sessions.Options {
	return sessions.Options{
		Domain: domain,
		Path:   "/",
		// 0: session cookie until the browser is closed, -1: delete the cookie, math.MaxInt32: 68 years
		MaxAge:   int(common.ConfigProxySessionDuration().Seconds()),
		Secure:   secure,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
}
