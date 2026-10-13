package web

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"time"

	utls "github.com/refraction-networking/utls"
)

type (
	// BrowserTransport is an http.RoundTripper whose TLS ClientHello mimics Chrome.
	//
	// Go's crypto/tls emits a ClientHello whose cipher list, extension set and extension
	// order are distinctive enough to identify the client from the handshake alone
	// (JA3/JA4), independently of any HTTP header. utls replays a recorded Chrome
	// handshake instead, so the connection fingerprints as the browser the User-Agent
	// claims to be.
	//
	// net/http picks the protocol version per connection from the ALPN result the dialed
	// connection reports, so one transport serves both HTTP/2 and HTTP/1.1 peers without
	// the handshake on the wire depending on which of them is spoken afterwards.
	BrowserTransport struct {
		*http.Transport
	}

	// browserConn makes the ALPN result of a utls handshake visible to net/http, which
	// asks the dialed connection for a crypto/tls ConnectionState and cannot read the
	// utls type of the same name.
	browserConn struct {
		*utls.UConn
	}
)

// ConnectionState reports the negotiated protocol in the crypto/tls representation.
func (c browserConn) ConnectionState() tls.ConnectionState {
	state := c.UConn.ConnectionState()
	return tls.ConnectionState{
		Version:            state.Version,
		HandshakeComplete:  state.HandshakeComplete,
		DidResume:          state.DidResume,
		CipherSuite:        state.CipherSuite,
		NegotiatedProtocol: state.NegotiatedProtocol,
		ServerName:         state.ServerName,
		PeerCertificates:   state.PeerCertificates,
		VerifiedChains:     state.VerifiedChains,
	}
}

// NewBrowserTransport builds a transport that presents a Chrome TLS fingerprint and
// speaks HTTP/2 or HTTP/1.1, whichever the peer selects during ALPN.
func NewBrowserTransport(rootCAs *x509.CertPool) *BrowserTransport {
	// A custom TLS dialer turns off HTTP/2 unless the protocols are named explicitly.
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetHTTP2(true)

	return &BrowserTransport{
		Transport: &http.Transport{
			DialTLSContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
				conn, err := dialBrowserTLS(ctx, addr, rootCAs)
				if err != nil {
					return nil, err
				}

				return browserConn{UConn: conn}, nil
			},
			Protocols:           protocols,
			MaxIdleConns:        100,
			IdleConnTimeout:     90 * time.Second,
			TLSHandshakeTimeout: 10 * time.Second,
		},
	}
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
