package web

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

// errNoHTTP2 reports that the peer selected HTTP/1.1 during ALPN, so the request has
// to be replayed over the HTTP/1.1 transport.
var errNoHTTP2 = errors.New("peer did not negotiate http/2")

type (
	// BrowserTransport is an http.RoundTripper whose TLS ClientHello mimics Chrome.
	//
	// Go's crypto/tls emits a ClientHello whose cipher list, extension set and extension
	// order are distinctive enough to identify the client from the handshake alone
	// (JA3/JA4), independently of any HTTP header. utls replays a recorded Chrome
	// handshake instead, so the connection fingerprints as the browser the User-Agent
	// claims to be.
	//
	// A custom TLS dialer suppresses net/http's own HTTP/2 upgrade — it only inspects
	// connection state when the dialer returns a *tls.Conn — so the two protocol
	// versions are dispatched here explicitly. Both dialers offer the same Chrome ALPN
	// list, so choosing between them never changes the handshake on the wire.
	BrowserTransport struct {
		h1 *http.Transport
		h2 *http2.Transport
		// downgraded records hosts that answered ALPN with http/1.1, so that later
		// requests skip the HTTP/2 attempt instead of paying for a failed dial.
		downgraded sync.Map
	}
)

// NewBrowserTransport builds a transport that presents a Chrome TLS fingerprint and
// prefers HTTP/2, falling back to HTTP/1.1 per host when the peer declines it.
func NewBrowserTransport(rootCAs *x509.CertPool) *BrowserTransport {
	return &BrowserTransport{
		h1: &http.Transport{
			DialTLSContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
				return dialBrowserTLS(ctx, addr, rootCAs)
			},
			ForceAttemptHTTP2:   false,
			MaxIdleConns:        100,
			IdleConnTimeout:     90 * time.Second,
			TLSHandshakeTimeout: 10 * time.Second,
		},
		h2: &http2.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
				conn, err := dialBrowserTLS(ctx, addr, rootCAs)
				if err != nil {
					return nil, err
				}

				if state := conn.ConnectionState(); state.NegotiatedProtocol != http2.NextProtoTLS {
					_ = conn.Close()
					return nil, errNoHTTP2
				}

				return conn, nil
			},
		},
	}
}

// RoundTrip implements the http.RoundTripper interface for BrowserTransport.
func (t *BrowserTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if _, downgraded := t.downgraded.Load(req.URL.Host); req.URL.Scheme != "https" || downgraded {
		return t.h1.RoundTrip(req)
	}

	resp, err := t.h2.RoundTrip(req)
	if errors.Is(err, errNoHTTP2) {
		t.downgraded.Store(req.URL.Host, struct{}{})
		return t.h1.RoundTrip(req)
	}

	return resp, err
}

// dialBrowserTLS opens a TCP connection and completes a Chrome-shaped TLS handshake.
func dialBrowserTLS(ctx context.Context, addr string, rootCAs *x509.CertPool) (*utls.UConn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}

	raw, err := (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}

	// HelloChrome_Auto tracks the most recent Chrome profile utls ships, including its
	// ALPN offer; NextProtos is left unset so the preset is not overridden.
	conn := utls.UClient(raw, &utls.Config{ServerName: host, RootCAs: rootCAs}, utls.HelloChrome_Auto)
	if err := conn.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return nil, err
	}

	return conn, nil
}
