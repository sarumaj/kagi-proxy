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

	Rule struct {
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

// Evaluate returns the effect of the first matching rule.
// If no rule matches, it returns noMatchEffect.
func (rules Ruleset) Evaluate(req *http.Request) effect {
	reqQuery := req.URL.Query()
	reqPath := strings.ToLower(req.URL.Path)
	for _, r := range rules {
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

		return Deny
	}

	return Allow
}

// RegexList returns a list of regex strings for each rule.
func (rules Ruleset) RegexList() []string {
	regexList := make([]string, 0, len(rules))
	for _, rule := range rules {
		regexList = append(regexList, rule.Regex())
	}
	return regexList
}
