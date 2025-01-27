package common

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

const (
	Allow Effect = true
	Deny  Effect = false
)

const (
	// Exact matches the path exactly.
	Exact PathType = iota
	// Prefix matches the path as a prefix.
	Prefix
	// Regex matches the path as an arbitrary regex.
	Regex
)

type (
	Diff struct {
		Added   Ruleset
		Removed Ruleset
	}

	Effect bool

	PathType int

	// Policy is the access control policy.
	// If effect is allow, the request is allowed publicly without proxy authentication.
	// If effect is deny, the request is explicit denied and not accessible via the proxy.
	Policy struct {
		// Allow is the list of allow rules.
		// All allowed requests are publicly accessible without proxy authentication.
		Allow Ruleset `json:"allow,omitempty"`
		// Deny is the list of deny rules.
		// All denied requests are explicitly denied and not accessible via the proxy at all.
		Deny Ruleset `json:"deny,omitempty"`
		// Override is the list of form data override rules.
		// The override rules are applied to matching form data requests
		// to ensure the form data does not get altered.
		Override Ruleset `json:"override,omitempty"`
	}

	// Rule is an access control rule.
	Rule struct {
		// FormData is the form data to patch the request with.
		FormData url.Values `json:"form_data,omitempty"`
		// JsSelectors is a list of JavaScript selectors.
		JsSelectors []string `json:"js_selectors,omitempty"`
		// Path is the URL path.
		Path string `json:"path"`
		// PathType is the type of the path. It can be exact, prefix, or regex.
		PathType PathType `json:"path_type"`
		// Query is the URL query parameters.
		Query url.Values `json:"query,omitempty"`
	}

	// Ruleset is a set of rules.
	Ruleset []Rule
)

// MarshalText implements the encoding.TextMarshaler interface.
func (e Effect) MarshalText() (text []byte, err error) {
	if e {
		return []byte("allow"), nil
	}
	return []byte("deny"), nil
}

// UnmarshalText implements the encoding.TextUnmarshaler interface.
func (e *Effect) UnmarshalText(text []byte) error {
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
func (p PathType) MarshalText() (text []byte, err error) {
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
func (p *PathType) UnmarshalText(text []byte) error {
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

// Match returns true if the rule matches the request.
func (r Rule) Match(req *http.Request) bool {
	reqPath := strings.ToLower(req.URL.Path)

	switch r.PathType {
	case Exact:
		if !strings.EqualFold(reqPath, r.Path) {
			return false
		}

	case Prefix:
		if !strings.HasPrefix(reqPath, strings.ToLower(r.Path)) {
			return false
		}

	case Regex:
		if pattern, err := regexp.Compile(strings.ToLower(r.Path)); err != nil || !pattern.MatchString(reqPath) {
			if err != nil {
				Logger().Error("Invalid regex pattern", zap.Error(err), zap.String("pattern", r.Path))
			}
			return false
		}
	}

	reqQuery := req.URL.Query()
	if len(r.Query) > 0 {
		for key := range r.Query {
			if !reqQuery.Has(key) || reqQuery.Get(key) != r.Query.Get(key) {
				return false
			}
		}

	}

	return true
}

// PatchForm patches the request form data with the rule query parameters.
// It returns true if the request form data has been patched.
func (r Rule) PatchForm(req *http.Request) (bool, error) {
	switch {
	case
		len(r.FormData) == 0,          // No form data to patch
		!r.Match(req),                 // Rule does not match the request
		req.Method != http.MethodPost, // Not a POST request
		// Not a form data request
		!strings.HasPrefix(req.Header.Get("Content-Type"), gin.MIMEPOSTForm),
		req.Body == nil: // No request body to patch

		return false, nil
	}

	var buffer bytes.Buffer
	if _, err := buffer.ReadFrom(req.Body); err != nil {
		return false, err
	}

	req.Body = Closer(bytes.NewReader(buffer.Bytes()))
	formData, err := url.ParseQuery(buffer.String())
	if err != nil {
		return false, err
	}

	for key, values := range r.FormData {
		formData[key] = values
	}

	formDataEncoded := formData.Encode()
	req.Body = io.NopCloser(strings.NewReader(formDataEncoded))
	req.ContentLength = int64(len(formDataEncoded))
	req.Header.Set("Content-Length", strconv.Itoa(len(formDataEncoded)))
	return true, nil
}

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

// Contains returns true if the ruleset contains the rule.
func (rules Ruleset) Contains(other Rule) bool {
	for _, rule := range rules {
		if rule.Path == other.Path &&
			rule.PathType == other.PathType &&
			rule.FormData.Encode() == other.FormData.Encode() &&
			rule.Query.Encode() == other.Query.Encode() &&
			strings.Join(rule.JsSelectors, ",") == strings.Join(other.JsSelectors, ",") {

			return true
		}
	}

	return false
}

// Compare returns the difference between two rulesets.
func (rules Ruleset) Compare(other Ruleset) Diff {
	var diff Diff
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
func (rules Ruleset) Evaluate(req *http.Request, noMatchEffect Effect) Effect {
	for _, r := range rules {
		if r.Match(req) {
			return !noMatchEffect
		}
	}

	return noMatchEffect
}

// JsSelectors returns a list of JavaScript selectors for all rules.
func (rules Ruleset) JsSelectors() []string {
	var selectors []string
	for _, rule := range rules {
		selectors = append(selectors, rule.JsSelectors...)
	}
	return selectors
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

// LoadPolicyFromFile loads a policy from a file.
// If the path is empty, it returns an empty policy.
func LoadPolicyFromFile(path string) (*Policy, error) {
	if len(path) == 0 {
		return &Policy{}, nil
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	defer file.Close()

	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()

	var policy Policy
	if err := decoder.Decode(&policy); err != nil {
		return nil, err
	}

	return &policy, nil
}
