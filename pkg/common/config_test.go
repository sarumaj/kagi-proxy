package common

import "testing"

// TestHostMapGetMirrorsUnlistedSubdomains covers the subdomains the explicit map does not
// name. Kagi keeps adding them (news, assistant, …); before this an unlisted one fell
// through to the caller's default host, so browsing news.kagi.example.com silently served
// kagi.com instead of the news site.
func TestHostMapGetMirrorsUnlistedSubdomains(t *testing.T) {
	hosts := HostMap{
		"kagi.example.com":           "kagi.com",
		"assets.kagi.example.com":    "assets.kagi.com",
		"help.kagi.example.com":      "help.kagi.com",
		"status.kagi.example.com":    "status.kagi.com",
		"translate.kagi.example.com": "translate.kagi.com",
	}

	for _, tt := range []struct {
		name string
		host string
		def  string
		want string
	}{
		{name: "apex", host: "kagi.example.com", def: "kagi.com", want: "kagi.com"},
		{name: "listed subdomain", host: "translate.kagi.example.com", def: "kagi.com", want: "translate.kagi.com"},
		{name: "unlisted news", host: "news.kagi.example.com", def: "kagi.com", want: "news.kagi.com"},
		{name: "unlisted assistant", host: "assistant.kagi.example.com", def: "kagi.com", want: "assistant.kagi.com"},
		{name: "unlisted with port", host: "news.kagi.example.com:8080", def: "kagi.com", want: "news.kagi.com"},
		{name: "nested label", host: "a.b.kagi.example.com", def: "kagi.com", want: "a.b.kagi.com"},
		// A host the proxy does not serve must still fall back, never be mirrored.
		{name: "foreign host falls back", host: "example.org", def: "kagi.com", want: "kagi.com"},
		{name: "foreign host without default", host: "example.org", def: "", want: "NXDOMAIN"},
		// Guard against a suffix match that is not a label boundary.
		{name: "lookalike suffix is foreign", host: "notkagi.example.com", def: "kagi.com", want: "kagi.com"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := hosts.Get(tt.host, tt.def); got != tt.want {
				t.Errorf("Get(%q, %q) = %q, want %q", tt.host, tt.def, got, tt.want)
			}
		})
	}
}

// TestHostMapReverseGetMirrorsUnlistedSubdomains pins the response direction, which
// re-scopes upstream cookies back onto the proxy domain.
func TestHostMapReverseGetMirrorsUnlistedSubdomains(t *testing.T) {
	reversed := HostMap{
		"kagi.example.com":        "kagi.com",
		"assets.kagi.example.com": "assets.kagi.com",
	}.Reverse()

	for host, want := range map[string]string{
		"kagi.com":           "kagi.example.com",
		"assets.kagi.com":    "assets.kagi.example.com",
		"assistant.kagi.com": "assistant.kagi.example.com",
		"news.kagi.com":      "news.kagi.example.com",
	} {
		if got := reversed.Get(host, ""); got != want {
			t.Errorf("Reverse().Get(%q) = %q, want %q", host, got, want)
		}
	}
}

// TestHostMapGetPrefersExplicitEntries keeps the map meaningful now that the configuration
// carries only the base pair: an entry is an override, taking precedence over the mirrored
// default so a proxy subdomain can be pointed at a target that is not its counterpart.
func TestHostMapGetPrefersExplicitEntries(t *testing.T) {
	hosts := HostMap{
		"kagi.example.com":        "kagi.com",
		"search.kagi.example.com": "kagi.com",
	}

	if got := hosts.Get("search.kagi.example.com", ""); got != "kagi.com" {
		t.Errorf("Get(search) = %q, want the override kagi.com rather than the mirrored search.kagi.com", got)
	}
	if got := hosts.Get("news.kagi.example.com", ""); got != "news.kagi.com" {
		t.Errorf("Get(news) = %q, want the mirrored news.kagi.com", got)
	}
}

// TestHostMapBaseOnlyMatchesFullMap records why the explicit subdomain entries were
// dropped from the configuration: with mirroring they resolve identically, so listing them
// only risks going stale against whatever the target host serves next.
func TestHostMapBaseOnlyMatchesFullMap(t *testing.T) {
	full := HostMap{
		"kagi.example.com":           "kagi.com",
		"assets.kagi.example.com":    "assets.kagi.com",
		"help.kagi.example.com":      "help.kagi.com",
		"status.kagi.example.com":    "status.kagi.com",
		"translate.kagi.example.com": "translate.kagi.com",
	}
	baseOnly := HostMap{"kagi.example.com": "kagi.com"}

	for _, host := range []string{
		"kagi.example.com", "assets.kagi.example.com", "help.kagi.example.com",
		"status.kagi.example.com", "translate.kagi.example.com",
		"news.kagi.example.com", "assistant.kagi.example.com",
		"example.org", "notkagi.example.com",
	} {
		if a, b := full.Get(host, "kagi.com"), baseOnly.Get(host, "kagi.com"); a != b {
			t.Errorf("Get(%q): full map = %q, base-only = %q", host, a, b)
		}
	}

	for _, host := range []string{"kagi.com", "assets.kagi.com", "news.kagi.com", "assistant.kagi.com"} {
		if a, b := full.Reverse().Get(host, ""), baseOnly.Reverse().Get(host, ""); a != b {
			t.Errorf("Reverse().Get(%q): full map = %q, base-only = %q", host, a, b)
		}
	}

	if a, b := full.Base(), baseOnly.Base(); a != b {
		t.Errorf("Base(): full map = %q, base-only = %q", a, b)
	}
}
