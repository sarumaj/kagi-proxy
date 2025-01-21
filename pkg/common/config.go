package common

import (
	"strings"
	"sync"

	"go.uber.org/zap"
)

var (
	configMux sync.Mutex
	config    = cfg{
		ProxyTargetHosts:       hosts{},
		ProxyRedirectLoginURL:  "/signin",
		ProxyGenerateQRCodeURL: "/generate-otp",
	}
)

type (
	cfg struct {
		ProxyUser              string
		ProxyPass              string
		ProxyOTPSecret         string
		ProxyGenerateQRCodeURL string
		ProxyRedirectLoginURL  string
		CsrfSecret             string
		SessionToken           string
		ProxyTargetHosts       hosts
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

// ConfigProxyUser returns the proxy user.
func ConfigProxyUser() string {
	configMux.Lock()
	defer configMux.Unlock()
	return config.ProxyUser
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

// ConfigProxyGenerateQRCodeURL returns the proxy QR code generation URL.
func ConfigProxyGenerateQRCodeURL() string {
	configMux.Lock()
	defer configMux.Unlock()
	return config.ProxyGenerateQRCodeURL
}

// ConfigProxyRedirectLoginURL returns the proxy redirect login URL.
func ConfigProxyRedirectLoginURL() string {
	configMux.Lock()
	defer configMux.Unlock()
	return config.ProxyRedirectLoginURL
}

// ConfigCsrfSecret returns the CSRF secret.
func ConfigCsrfSecret() string {
	configMux.Lock()
	defer configMux.Unlock()
	return config.CsrfSecret
}

// ConfigSessionToken returns the session token.
func ConfigSessionToken() string {
	configMux.Lock()
	defer configMux.Unlock()
	return config.SessionToken
}

// ConfigProxyTargetHosts returns the proxy target hosts.
func ConfigProxyTargetHosts() hosts {
	configMux.Lock()
	defer configMux.Unlock()
	return config.ProxyTargetHosts
}

// ConfigureProxy configures the proxy.
func ConfigureProxy(opts ...option) {
	for _, opt := range opts {
		opt(&config)
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

// WithProxyGenerateQRCodeURL sets the proxy QR code generation URL.
func WithProxyGenerateQRCodeURL(url string) option {
	return func(pc *cfg) {
		configMux.Lock()
		pc.ProxyGenerateQRCodeURL = url
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

// WithCsrfSecret sets the CSRF secret.
func WithCsrfSecret(secret string) option {
	return func(pc *cfg) {
		configMux.Lock()
		pc.CsrfSecret = secret
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
