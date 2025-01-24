package common

import (
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
		ProxyGuardPolicy      Policy
		ProxyPass             string
		ProxyOTPSecret        string
		ProxyRedirectLoginURL string
		ProxySessionSecret    string
		ProxyTargetHosts      hosts
		ProxyUser             string
		SessionToken          string
	}

	option func(*cfg)

	hosts map[string]string
)

// Base returns the base host.
func (t hosts) Base() (base string) {
	var shortest string
	for host := range t {
		if len(shortest) == 0 || len(host) < len(shortest) {
			shortest = host
		}
	}

	return shortest
}

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

// Reverse returns the reversed hosts mapping.
func (t hosts) Reverse() hosts {
	reversed := make(hosts, len(t))
	for k, v := range t {
		reversed[v] = k
	}
	return reversed
}

// ConfigProxyGuardPolicy returns the proxy guard rules.
func ConfigProxyGuardPolicy() Policy {
	configMux.Lock()
	defer configMux.Unlock()
	return config.ProxyGuardPolicy
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

// ConfigProxyRedirectLoginURL returns the proxy redirect login URL.
func ConfigProxyRedirectLoginURL() string {
	configMux.Lock()
	defer configMux.Unlock()
	return config.ProxyRedirectLoginURL
}

// ConfigProxySessionSecret returns the CSRF secret.
func ConfigProxySessionSecret() string {
	configMux.Lock()
	defer configMux.Unlock()
	return config.ProxySessionSecret
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

// WithProxyGuardPolicy sets the proxy guard rules.
func WithProxyGuardPolicy(policy Policy) option {
	return func(pc *cfg) {
		configMux.Lock()
		pc.ProxyGuardPolicy = policy
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

// WithProxyRedirectLoginURL sets the proxy redirect login URL.
func WithProxyRedirectLoginURL(url string) option {
	return func(pc *cfg) {
		configMux.Lock()
		pc.ProxyRedirectLoginURL = url
		configMux.Unlock()
	}
}

// WithProxySessionSecret sets the CSRF secret.
func WithProxySessionSecret(secret string) option {
	return func(pc *cfg) {
		configMux.Lock()
		pc.ProxySessionSecret = secret
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
