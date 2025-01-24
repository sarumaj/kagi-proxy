package common

import (
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"go.uber.org/zap"
)

const (
	Allow effect = true
	Deny  effect = false
)

const (
	// Exact matches the path exactly.
	Exact pathType = iota + 1
	// Prefix matches the path as a prefix.
	Prefix
	// Regex matches the path as an arbitrary regex.
	Regex
)

type (
	effect bool

	pathType int

	diff struct {
		Added   Ruleset
		Removed Ruleset
	}

	// Rule is an access control rule.
	Rule struct {
		// Schema is the URL schema.
		Schema string `json:"schema,omitempty"`
		// Domain is the URL domain.
		// May contain asterisks at the beginning or ending of the domain to match subdomains or superdomains.
		Domain string `json:"domain,omitempty"`
		// Path is the URL path.
		Path string `json:"path"`
		// PathType is the type of the path. It can be exact, prefix, or regex.
		PathType pathType `json:"path_type"`
		// Query is the URL query parameters.
		Query url.Values `json:"query,omitempty"`
	}

	// Ruleset is a set of rules.
	Ruleset []Rule

	// Policy is the access control policy.
	// If effect is allow, the request is allowed publicly without proxy authentication.
	// If effect is deny, the request is explicit denied and not accessible via the proxy.
	Policy map[effect]Ruleset
)

// MarshalText implements the encoding.TextMarshaler interface.
func (e effect) MarshalText() (text []byte, err error) {
	if e {
		return []byte("allow"), nil
	}
	return []byte("deny"), nil
}

// UnmarshalText implements the encoding.TextUnmarshaler interface.
func (e *effect) UnmarshalText(text []byte) error {
	switch string(text) {
	case "allow":
		*e = Allow
	case "deny":
		*e = Deny
	default:
		return fmt.Errorf("invalid effect: %s", text)
	}
	return nil
}

// MarshalText implements the encoding.TextMarshaler interface.
func (p pathType) MarshalText() (text []byte, err error) {
	switch p {
	case Exact:
		return []byte("exact"), nil
	case Prefix:
		return []byte("prefix"), nil
	case Regex:
		return []byte("regex"), nil
	default:
		return nil, fmt.Errorf("invalid path type: %d", p)
	}
}

// UnmarshalText implements the encoding.TextUnmarshaler interface.
func (p *pathType) UnmarshalText(text []byte) error {
	switch string(text) {
	case "exact":
		*p = Exact
	case "prefix":
		*p = Prefix
	case "regex":
		*p = Regex
	default:
		return fmt.Errorf("invalid path type: %s", text)
	}
	return nil
}

// Regex returns the regex representation of the rule.
// The regex is used to match the request path and query.
func (r Rule) Regex() string {
	var builder strings.Builder
	_, _ = builder.WriteString("^") // Start the regex

	if len(r.Schema) > 0 {
		_, _ = builder.WriteString(regexp.QuoteMeta(r.Schema))
		_, _ = builder.WriteString("://")
	} else if len(r.Domain) > 0 {
		_, _ = builder.WriteString("[^:]+://") // Match anything except the schema
	}

	if len(r.Domain) > 0 {
		if strings.HasPrefix(r.Domain, "*") {
			_, _ = builder.WriteString("[^/]+") // Match anything except the path or subdomain
			_, _ = builder.WriteString(regexp.QuoteMeta(r.Domain[1:]))
		} else if strings.HasSuffix(r.Domain, "*") {
			_, _ = builder.WriteString(regexp.QuoteMeta(r.Domain[:len(r.Domain)-1]))
			_, _ = builder.WriteString("[^/]+") // Match anything except the path
		} else {
			_, _ = builder.WriteString(regexp.QuoteMeta(r.Domain))
		}
	} else if len(r.Schema) > 0 {
		_, _ = builder.WriteString("[^/]+") // Match anything except the path
	}

	// Convert the path to a regex
	if r.PathType == Regex {
		_, _ = builder.WriteString(strings.ToLower(r.Path))
	} else {
		_, _ = builder.WriteString(regexp.QuoteMeta(strings.ToLower(r.Path)))
	}

	if len(r.Query) > 0 {
		if r.PathType == Prefix {
			_, _ = builder.WriteString("[^\\?]*") // Match anything except the query string
		}

		_, _ = builder.WriteString("\\?")
		groups := strings.Split(r.Query.Encode(), "&")
		for i, group := range groups {
			groups[i] = regexp.QuoteMeta(group)
		}

		// Match any number of query parameters
		_, _ = builder.WriteString("(?:[^=]+=[^&]*&)*")
		if len(groups) > 1 {
			// Match any of expected query parameters
			_, _ = builder.WriteString("(?:(?:" + strings.Join(groups, "|") + ")&){" + fmt.Sprint(len(groups)-1) + "}")
			// Match any number of query parameters
			_, _ = builder.WriteString("(?:[^=]+=[^&]*&)*")
			// Match the last query parameter
			_, _ = builder.WriteString("(?:" + strings.Join(groups, "|") + ")")
		} else if len(groups) > 0 {
			_, _ = builder.WriteString(groups[0])
		}
		// Match any number of query parameters after the last query parameter
		_, _ = builder.WriteString("(?:&[^=]+=[^&]*)*")

	} else if r.PathType == Prefix {
		_, _ = builder.WriteString(".*") // Match anything
	}

	_, _ = builder.WriteString("$") // Terminate the regex
	return builder.String()
}

// Contains returns true if the ruleset contains the rule.
func (rules Ruleset) Contains(other Rule) bool {
	for _, rule := range rules {
		if rule.Schema == other.Schema &&
			rule.Domain == other.Domain &&
			rule.Path == other.Path &&
			rule.PathType == other.PathType &&
			rule.Query.Encode() == other.Query.Encode() {

			return true
		}
	}

	return false
}

// Compare returns the difference between two rulesets.
func (rules Ruleset) Compare(other Ruleset) diff {
	var diff diff
	for _, rule := range rules {
		if !other.Contains(rule) {
			diff.Removed = append(diff.Removed, rule)
		}
	}

	for _, rule := range other {
		if !rules.Contains(rule) {
			diff.Added = append(diff.Added, rule)
		}
	}

	return diff
}

// Evaluate returns the effect of the first matching rule.
// If no rule matches, it returns noMatchEffect.
func (rules Ruleset) Evaluate(req *http.Request, noMatchEffect effect) effect {
	reqQuery := req.URL.Query()
	reqPath := strings.ToLower(req.URL.Path)
	for _, r := range rules {
		if len(r.Schema) > 0 && !strings.EqualFold(r.Schema, req.URL.Scheme) {
			continue
		}

		if len(r.Domain) > 0 {
			if strings.HasPrefix(r.Domain, "*") && !strings.HasSuffix(req.URL.Hostname(), r.Domain[1:]) {
				continue
			} else if strings.HasSuffix(r.Domain, "*") && !strings.HasPrefix(req.URL.Hostname(), r.Domain[:len(r.Domain)-1]) {
				continue
			} else if !strings.EqualFold(r.Domain, req.URL.Hostname()) {
				continue
			}
		}

		switch r.PathType {
		case Exact:
			if !strings.EqualFold(reqPath, r.Path) {
				continue
			}

		case Prefix:
			if !strings.HasPrefix(reqPath, strings.ToLower(r.Path)) {
				continue
			}

		case Regex:
			if pattern, err := regexp.Compile(strings.ToLower(r.Path)); err != nil || !pattern.MatchString(reqPath) {
				if err != nil {
					Logger().Error("Invalid regex pattern", zap.Error(err), zap.String("pattern", r.Path))
				}
				continue
			}
		}

		if len(r.Query) > 0 {
			queryMatch := true
			for key := range r.Query {
				if !reqQuery.Has(key) || reqQuery.Get(key) != r.Query.Get(key) {
					queryMatch = false
					break
				}
			}

			if !queryMatch {
				continue
			}
		}

		return !noMatchEffect
	}

	return noMatchEffect
}

// Len returns the number of rules in the ruleset.
func (rules Ruleset) Len() int { return len(rules) }

// Merge returns a new ruleset that contains all rules from both rulesets.
func (rules Ruleset) Merge(other Ruleset) Ruleset {
	for _, rule := range other {
		if !rules.Contains(rule) {
			rules = append(rules, rule)
		}
	}

	return rules
}

// RegexList returns a list of regex strings for each rule.
func (rules Ruleset) RegexList() []string {
	regexList := make([]string, 0, len(rules))
	for _, rule := range rules {
		regexList = append(regexList, rule.Regex())
	}
	return regexList
}
