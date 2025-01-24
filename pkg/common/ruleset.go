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
	Exact pathType = iota
	Prefix
	Regex
)

type (
	effect bool

	pathType int

	diff struct {
		Added   Ruleset
		Removed Ruleset
	}

	Rule struct {
		Schema   string
		Domain   string
		Path     string
		PathType pathType
		Query    url.Values
	}

	Ruleset []Rule
)

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

// RegexList returns a list of regex strings for each rule.
func (rules Ruleset) RegexList() []string {
	regexList := make([]string, 0, len(rules))
	for _, rule := range rules {
		regexList = append(regexList, rule.Regex())
	}
	return regexList
}
