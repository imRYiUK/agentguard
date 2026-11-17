package awspolicy

import (
	"strings"
	"unicode"
)

// A pattern is a string of IAM wildcards: * matches any run of characters
// and ? matches one. covers decides whether every string one pattern can
// match is matched by another.

// covers reports whether every string that q matches, p matches too. q is
// read as a pattern, not as text: a * in q stands for any run of characters,
// so only a * in p can cover it, and a ? in q stands for any one character,
// so only a ? or a * in p can cover it. It answers false when it cannot
// prove the cover, never true wrongly. fold makes the comparison
// case-insensitive.
func covers(p, q string, fold bool, b *Budget) bool {
	pr, qr := []rune(p), []rune(q)
	pi, qi := 0, 0
	// The last * of p seen, and the position of q it is currently matching up
	// to. When a mismatch happens, the * absorbs one more token of q.
	star, mark := -1, 0
	for qi < len(qr) {
		if !b.spend() {
			return false
		}
		switch {
		case pi < len(pr) && pr[pi] == '*':
			star, mark = pi, qi
			pi++
		case pi < len(pr) && tokenCovers(pr[pi], qr[qi], fold):
			pi++
			qi++
		case star >= 0:
			mark++
			pi, qi = star+1, mark
		default:
			return false
		}
	}
	for pi < len(pr) && pr[pi] == '*' {
		pi++
	}
	return pi == len(pr)
}

// tokenCovers reports whether the pattern character pc matches every string
// the pattern character qc stands for, when neither is a *.
func tokenCovers(pc, qc rune, fold bool) bool {
	switch {
	case qc == '*':
		return false
	case pc == '?':
		return true
	case qc == '?':
		return false
	case fold:
		return unicode.ToLower(pc) == unicode.ToLower(qc)
	}
	return pc == qc
}

// hasWildcard reports whether s contains a wildcard.
func hasWildcard(s string) bool { return strings.ContainsAny(s, "*?") }
