package common

import (
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

const (
	ip2locationApiKey     = "ip2locationApiKey"
	proxyGuardPolicy      = "proxyGuardPolicy"
	proxyPass             = "proxyPass"
	proxyOTPSecret        = "proxyOTPSecret"
	proxyPublicDomains    = "proxyPublicDomains"
	proxyRedirectLoginURL = "proxyRedirectLoginURL"
	proxySessionDuration  = "proxySessionDuration"
	proxySessionSecret    = "proxySessionSecret"
	proxyTargetHosts      = "proxyTargetHosts"
	proxyUser             = "proxyUser"
	sessionToken          = "sessionToken"
)

var config = sync.Map{}

type (
	// Domains is a list of domains.
	Domains []string
	// HostMap is a map of proxy host domains to target host domains.
	HostMap map[string]string
)

// Contains returns true if the domains contain the domain.
func (d Domains) Contains(domain string) bool {
	for _, d := range d {
		if strings.EqualFold(d, domain) {
			return true
		}
	}
	return false
}

// Base returns the base host.
func (t HostMap) Base() (base string) {
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
func (t HostMap) Get(host, def string) string {
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
func (t HostMap) Reverse() HostMap {
	reversed := make(HostMap, len(t))
	for k, v := range t {
		reversed[v] = k
	}
	return reversed
}

func configGet[T any](key string) T {
	i, _ := config.Load(key)
	v, _ := i.(T)
	return v
}

// ConfigIP2LocationApiKey returns the IP2Location API key.
func ConfigIP2LocationApiKey() string { return configGet[string](ip2locationApiKey) }

// ConfigProxyGuardPolicy returns the proxy guard rules.
func ConfigProxyGuardPolicy() Policy { return configGet[Policy](proxyGuardPolicy) }

// ConfigProxyPass returns the proxy password.
func ConfigProxyPass() string { return configGet[string](proxyPass) }

// ConfigProxyOTPSecret returns the proxy OTP secret.
func ConfigProxyOTPSecret() string { return configGet[string](proxyOTPSecret) }

// ConfigProxyPublicDomains returns the public domains.
func ConfigProxyPublicDomains() Domains { return configGet[Domains](proxyPublicDomains) }

// ConfigProxyRedirectLoginURL returns the proxy redirect login URL.
func ConfigProxyRedirectLoginURL() string { return configGet[string](proxyRedirectLoginURL) }

// ConfigProxySessionDuration returns the proxy session duration.
func ConfigProxySessionDuration() time.Duration {
	return configGet[time.Duration](proxySessionDuration)
}

// ConfigProxySessionSecret returns the CSRF secret.
func ConfigProxySessionSecret() string { return configGet[string](proxySessionSecret) }

// ConfigProxyTargetHosts returns the proxy target hosts.
func ConfigProxyTargetHosts() HostMap { return configGet[HostMap](proxyTargetHosts) }

// ConfigProxyUser returns the proxy user.
func ConfigProxyUser() string { return configGet[string](proxyUser) }

// ConfigSessionToken returns the session token.
func ConfigSessionToken() string { return configGet[string](sessionToken) }

// SetIP2LocationApiKey sets the IP2Location API key.
func SetIP2LocationApiKey(apiKey string) { config.Store(ip2locationApiKey, apiKey) }

// SetProxyGuardPolicy sets the proxy guard rules.
func SetProxyGuardPolicy(policy Policy) { config.Store(proxyGuardPolicy, policy) }

// SetProxyPass sets the proxy password.
func SetProxyPass(pass string) { config.Store(proxyPass, pass) }

// SetProxyOTPSecret sets the proxy OTP secret.
func SetProxyOTPSecret(secret string) { config.Store(proxyOTPSecret, secret) }

// SetProxyPublicDomains sets the public domains.
func SetProxyPublicDomains(domains Domains) { config.Store(proxyPublicDomains, domains) }

// SetProxyRedirectLoginURL sets the proxy redirect login URL.
func SetProxyRedirectLoginURL(url string) { config.Store(proxyRedirectLoginURL, url) }

// SetProxySessionDuration sets the proxy session duration.
func SetProxySessionDuration(duration time.Duration) { config.Store(proxySessionDuration, duration) }

// SetProxySessionSecret sets the CSRF secret.
func SetProxySessionSecret(secret string) { config.Store(proxySessionSecret, secret) }

// SetSessionToken sets the session token.
func SetSessionToken(token string) { config.Store(sessionToken, token) }

// SetProxyTargetHosts sets the proxy target hosts.
func SetProxyTargetHosts(hosts HostMap) { config.Store(proxyTargetHosts, hosts) }

// SetProxyUser sets the proxy user.
func SetProxyUser(user string) { config.Store(proxyUser, user) }
