package web

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"testing"

	utls "github.com/refraction-networking/utls"
)

// TestBrowserTransportNegotiatesHTTP2 pins the two properties the upstream connection
// depends on: HTTP/2 is selected (net/http silently drops to HTTP/1.1 once a custom TLS
// dialer is in play) and the handshake carries Chrome's shape rather than Go's.
//
// GREASE is the cheap discriminator here: Chrome pads its cipher list and extension list
// with reserved values, Go's crypto/tls never emits any.
func TestBrowserTransportNegotiatesHTTP2(t *testing.T) {
	var hello *tls.ClientHelloInfo
	var serverProto string

	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serverProto = r.Proto
		_, _ = w.Write([]byte("ok"))
	}))
	upstream.EnableHTTP2 = true
	upstream.TLS = &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetConfigForClient: func(info *tls.ClientHelloInfo) (*tls.Config, error) {
			hello = info
			return nil, nil
		},
	}
	upstream.StartTLS()
	defer upstream.Close()

	pool := x509.NewCertPool()
	pool.AddCert(upstream.Certificate())

	resp, err := (&http.Client{Transport: NewBrowserTransport(pool)}).Get(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.Proto != "HTTP/2.0" || serverProto != "HTTP/2.0" {
		t.Errorf("negotiated client=%q server=%q, want HTTP/2.0", resp.Proto, serverProto)
	}

	if hello == nil {
		t.Fatal("no ClientHello captured")
	}

	if got := hello.SupportedProtos; len(got) == 0 || got[0] != "h2" {
		t.Errorf("ALPN offer = %v, want it to lead with h2", got)
	}

	var grease bool
	for _, suite := range hello.CipherSuites {
		// GREASE values all have the form 0xNaNa.
		if suite&0x0f0f == 0x0a0a && byte(suite>>8) == byte(suite) {
			grease = true
			break
		}
	}
	if !grease {
		t.Errorf("cipher suites %#x carry no GREASE (e.g. %#x); this is Go's fingerprint, not Chrome's",
			hello.CipherSuites, utls.GREASE_PLACEHOLDER)
	}
}
