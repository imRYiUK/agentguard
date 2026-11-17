// Package jsonpath builds the JSONPath locations used in evidence and error
// messages.
package jsonpath

import (
	"regexp"
	"strings"
)

var identifier = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// Key appends an object key to a JSONPath, using dot notation when the key
// allows it and bracket notation otherwise.
func Key(base, key string) string {
	if identifier.MatchString(key) {
		return base + "." + key
	}
	return base + "['" + strings.ReplaceAll(strings.ReplaceAll(key, `\`, `\\`), "'", `\'`) + "']"
}
