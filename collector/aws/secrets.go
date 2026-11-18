package aws

import (
	"regexp"
	"slices"
	"strings"
)

// AgentGuard rejects a Snapshot that looks like it holds a secret value, so
// the Collector must not write one. A policy document is copied from AWS as
// it is, and an account's policies are free text, so one could hold a pasted
// key. looksSecret applies the checks AgentGuard rejects on when it reads a
// Snapshot (core/internal/snapshot/secrets.go; the two modules do not share
// code, so keep them in step), and a document that fails is left out and
// recorded as a Blind Spot instead.

// secretFieldNames are normalized field names (lower case, no '_', '-', or
// spaces) whose non-empty value is treated as a secret.
var secretFieldNames = []string{
	"secretaccesskey", "awssecretaccesskey", "secretkey",
	"sessiontoken", "awssessiontoken", "securitytoken",
	"privatekey", "password", "passwd", "secret", "clientsecret",
	"apikey", "accesstoken", "authtoken", "bearertoken", "token",
}

var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----`),
	regexp.MustCompile(`(?i)secret_?access_?key["']?\s*[:=]\s*["']?[A-Za-z0-9/+]{16,}`),
	regexp.MustCompile(`\b(?:AKIA|ASIA)[A-Z2-7]{16}\b`),
	regexp.MustCompile(`(?:IQoJb3JpZ2lu|FwoGZXIvYXdz|FQoDYXdz)[A-Za-z0-9/+=]{16,}|^[A-Za-z0-9/+=]{200,}$`),
	regexp.MustCompile(`\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{22,})`),
	regexp.MustCompile(`\bxox[abprs]-[A-Za-z0-9-]{10,}`),
	regexp.MustCompile(`\b(?:sk-[A-Za-z0-9_-]{20,}|AIza[0-9A-Za-z_-]{35}|[sr]k_live_[0-9A-Za-z]{20,})`),
	regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`),
}

// A bare AWS secret access key is 40 base64 characters. To keep hashes and
// identifiers out, it must mix upper case, lower case, and digits.
var (
	bareSecretKey = regexp.MustCompile(`^[A-Za-z0-9/+]{40}$`)
	upper         = regexp.MustCompile(`[A-Z]`)
	lower         = regexp.MustCompile(`[a-z]`)
	digit         = regexp.MustCompile(`[0-9]`)
)

// looksSecret reports whether a decoded JSON value holds something that
// looks like a secret: in a string, in an object key, or in a field whose
// name says it holds one. It checks decoded values, so a secret hidden
// behind JSON escapes is found too.
func looksSecret(v any) bool {
	switch v := v.(type) {
	case map[string]any:
		for k, child := range v {
			if secretString(k) || (isSecretFieldName(k) && hasValue(child)) || looksSecret(child) {
				return true
			}
		}
	case []any:
		return slices.ContainsFunc(v, looksSecret)
	case string:
		return secretString(v)
	}
	return false
}

func secretString(s string) bool {
	for _, re := range secretPatterns {
		if re.MatchString(s) {
			return true
		}
	}
	return bareSecretKey.MatchString(s) && upper.MatchString(s) && lower.MatchString(s) && digit.MatchString(s)
}

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
