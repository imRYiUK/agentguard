package snapshot

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/imRYiUK/agentguard/core/internal/jsonpath"
)

// The Collector never writes a secret value into a Snapshot. This check is
// defence in depth: it rejects a Snapshot that looks like it holds one, so a
// Collector bug or a hand-edited file cannot carry a secret into analysis.
//
// A finding names the field's JSONPath and the kind of secret, never the
// value, so rejecting a Snapshot does not leak the secret into a log.

// secretFieldNames are normalized field names (lower case, no '_', '-', or
// spaces) whose non-empty string value is treated as a secret.
var secretFieldNames = []string{
	"secretaccesskey", "awssecretaccesskey", "secretkey",
	"sessiontoken", "awssessiontoken", "securitytoken",
	"privatekey", "password", "passwd", "secret", "clientsecret",
	"apikey", "accesstoken", "authtoken", "bearertoken", "token",
}

type secretPattern struct {
	kind string
	re   *regexp.Regexp
}

// secretPatterns are checked against every string value, in order.
var secretPatterns = []secretPattern{
	{"a private key", regexp.MustCompile(`-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----`)},
	{"an AWS secret access key", regexp.MustCompile(`(?i)secret_?access_?key["']?\s*[:=]\s*["']?[A-Za-z0-9/+]{16,}`)},
	{"an AWS access key ID", regexp.MustCompile(`\b(?:AKIA|ASIA)[A-Z2-7]{16}\b`)},
	{"an AWS session token", regexp.MustCompile(`(?:IQoJb3JpZ2lu|FwoGZXIvYXdz|FQoDYXdz)[A-Za-z0-9/+=]{16,}|^[A-Za-z0-9/+=]{200,}$`)},
	{"a GitHub token", regexp.MustCompile(`\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{22,})`)},
	{"a Slack token", regexp.MustCompile(`\bxox[abprs]-[A-Za-z0-9-]{10,}`)},
	{"an API key", regexp.MustCompile(`\b(?:sk-[A-Za-z0-9_-]{20,}|AIza[0-9A-Za-z_-]{35}|[sr]k_live_[0-9A-Za-z]{20,})`)},
	{"a JSON Web Token", regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`)},
}

// A bare AWS secret access key is 40 base64 characters. To keep hashes and
// identifiers out, it must mix upper case, lower case, and digits.
var (
	bareSecretKey = regexp.MustCompile(`^[A-Za-z0-9/+]{40}$`)
	upper         = regexp.MustCompile(`[A-Z]`)
	lower         = regexp.MustCompile(`[a-z]`)
	digit         = regexp.MustCompile(`[0-9]`)
)

// rejectSecrets returns an error if doc, a decoded JSON document, looks like
// it holds a secret value.
func rejectSecrets(source string, doc any) error {
	if path, kind := findSecret("$", doc); path != "" {
		return fmt.Errorf("%s: Snapshot rejected: %s looks like %s; a Snapshot never holds a secret value", source, path, kind)
	}
	return nil
}

// findSecret returns the JSONPath and kind of the first suspicious value in
// v, visiting object keys in sorted order so the result is deterministic.
func findSecret(path string, v any) (foundPath, kind string) {
	switch v := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		for _, k := range keys {
			if kind := secretKind(k); kind != "" {
				return path + " (a field name)", kind
			}
			child := jsonpath.Key(path, k)
			if isSecretFieldName(k) && hasValue(v[k]) {
				return child, "a secret value (the field name says it holds a secret)"
			}
			if p, kind := findSecret(child, v[k]); p != "" {
				return p, kind
			}
		}
	case []any:
		for i, e := range v {
			if p, kind := findSecret(fmt.Sprintf("%s[%d]", path, i), e); p != "" {
				return p, kind
			}
		}
	case string:
		if kind := secretKind(v); kind != "" {
			return path, kind
		}
	}
	return "", ""
}

// hasValue reports whether a JSON value holds anything: a non-empty string,
// a number, or a non-empty list or object.
func hasValue(v any) bool {
	switch v := v.(type) {
	case string:
		return v != ""
	case float64:
		return true
	case []any:
		return len(v) > 0
	case map[string]any:
		return len(v) > 0
	}
	return false
}

func isSecretFieldName(name string) bool {
	n := strings.NewReplacer("_", "", "-", "", " ", "").Replace(strings.ToLower(name))
	return slices.Contains(secretFieldNames, n)
}

func secretKind(s string) string {
	for _, p := range secretPatterns {
		if p.re.MatchString(s) {
			return p.kind
		}
	}
	if bareSecretKey.MatchString(s) && upper.MatchString(s) && lower.MatchString(s) && digit.MatchString(s) {
		return "an AWS secret access key"
	}
	return ""
}
