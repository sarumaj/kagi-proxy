package common

import (
	"html/template"
	"strings"
	"sync"

	"go.uber.org/zap"
)

var (
	configMux sync.Mutex
	config    = cfg{
		ProxyTargetHosts:      hosts{},
		ProxyRedirectLoginURL: "/signin",
	}
)

type (
	cfg struct {
		CsrfSecret            string
		ProxyPass             string
		ProxyOTPSecret        string
		ProxyOtpSetupQrCode   template.HTML
		ProxyOtpSetupURL      string
		ProxyRedirectLoginURL string
		ProxyTargetHosts      hosts
		ProxyUser             string
		SessionToken          string
	}

	option func(*cfg)

	hosts map[string]string
)

// Get returns the target host for given proxy domain.
// If the target host is not found, it returns the default value.
// If the default value is not provided, it returns "NXDOMAIN".
func (t hosts) Get(host, def string) string {
	if targetHost, ok := t[host]; ok {
		return targetHost
	}

	for hostPort, targetHost := range t {
		if strings.Split(hostPort, ":")[0] == host {
			return targetHost
		}
	}

	Logger().Warn("Target host not found", zap.String("host", host), zap.Reflect("hosts", t))

	if len(def) > 0 {
		return def
	}

	return "NXDOMAIN"
}

// ConfigCsrfSecret returns the CSRF secret.
func ConfigCsrfSecret() string {
	configMux.Lock()
	defer configMux.Unlock()
	return config.CsrfSecret
}

// ConfigProxyPass returns the proxy password.
func ConfigProxyPass() string {
	configMux.Lock()
	defer configMux.Unlock()
	return config.ProxyPass
}

// ConfigProxyOTPSecret returns the proxy OTP secret.
func ConfigProxyOTPSecret() string {
	configMux.Lock()
	defer configMux.Unlock()
	return config.ProxyOTPSecret
}

// ConfigProxyOtpSetupQrCode returns the proxy OTP setup QR code.
func ConfigProxyOtpSetupQrCode() template.HTML {
	configMux.Lock()
	defer configMux.Unlock()
	return config.ProxyOtpSetupQrCode
}

// ConfigProxyOtpSetupURL returns the proxy OTP setup URL.
func ConfigProxyOtpSetupURL() string {
	configMux.Lock()
	defer configMux.Unlock()
	return config.ProxyOtpSetupURL
}

// ConfigProxyRedirectLoginURL returns the proxy redirect login URL.
func ConfigProxyRedirectLoginURL() string {
	configMux.Lock()
	defer configMux.Unlock()
	return config.ProxyRedirectLoginURL
}

// ConfigProxyTargetHosts returns the proxy target hosts.
func ConfigProxyTargetHosts() hosts {
	configMux.Lock()
	defer configMux.Unlock()
	return config.ProxyTargetHosts
}

// ConfigProxyUser returns the proxy user.
func ConfigProxyUser() string {
	configMux.Lock()
	defer configMux.Unlock()
	return config.ProxyUser
}

// ConfigSessionToken returns the session token.
func ConfigSessionToken() string {
	configMux.Lock()
	defer configMux.Unlock()
	return config.SessionToken
}

// ConfigureProxy configures the proxy.
func ConfigureProxy(opts ...option) {
	for _, opt := range opts {
		opt(&config)
	}
}

// WithCsrfSecret sets the CSRF secret.
func WithCsrfSecret(secret string) option {
	return func(pc *cfg) {
		configMux.Lock()
		pc.CsrfSecret = secret
		configMux.Unlock()
	}
}

// WithProxyPass sets the proxy password.
func WithProxyPass(pass string) option {
	return func(pc *cfg) {
		configMux.Lock()
		pc.ProxyPass = pass
		configMux.Unlock()
	}
}

// WithProxyOTPSecret sets the proxy OTP secret.
func WithProxyOTPSecret(secret string) option {
	return func(pc *cfg) {
		configMux.Lock()
		pc.ProxyOTPSecret = secret
		configMux.Unlock()
	}
}

// WithProxyOtpSetupQrCode sets the proxy OTP setup QR code.
func WithProxyOtpSetupQrCode(qrCode template.HTML) option {
	return func(pc *cfg) {
		configMux.Lock()
		pc.ProxyOtpSetupQrCode = qrCode
		configMux.Unlock()
	}
}

// WithProxyOtpSetupURL sets the proxy OTP setup URL.
func WithProxyOtpSetupURL(url string) option {
	return func(pc *cfg) {
		configMux.Lock()
		pc.ProxyOtpSetupURL = url
		configMux.Unlock()
	}
}

// WithProxyRedirectLoginURL sets the proxy redirect login URL.
func WithProxyRedirectLoginURL(url string) option {
	return func(pc *cfg) {
		configMux.Lock()
		pc.ProxyRedirectLoginURL = url
		configMux.Unlock()
	}
}

// WithSessionToken sets the session token.
func WithSessionToken(token string) option {
	return func(pc *cfg) {
		configMux.Lock()
		pc.SessionToken = token
		configMux.Unlock()
	}
}

// WithProxyTargetHosts sets the proxy target hosts.
func WithProxyTargetHosts(hosts map[string]string) option {
	return func(pc *cfg) {
		if hosts != nil {
			configMux.Lock()
			pc.ProxyTargetHosts = hosts
			configMux.Unlock()
		}
	}
}

// WithProxyUser sets the proxy user.
func WithProxyUser(user string) option {
	return func(pc *cfg) {
		configMux.Lock()
		pc.ProxyUser = user
		configMux.Unlock()
	}
}
