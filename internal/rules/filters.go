package rules

import (
	"math"
	"regexp"
	"strconv"
	"strings"
)

// Entropy returns the Shannon entropy of s in bits per character.
func Entropy(s string) float64 {
	if s == "" {
		return 0
	}
	var counts [256]int
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	n := float64(len(s))
	var h float64
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}

// placeholderWords are fragments that show up in documentation, templates and
// test fixtures but practically never inside a randomly generated credential.
var placeholderWords = []string{
	"example", "sample", "dummy", "placeholder", "changeme", "change_me",
	"your_", "your-", "yourkey", "yourtoken", "yoursecret", "yourapi", "your_api",
	"insert", "replace", "redacted", "xxxxx", "*****", "....",
	"fake_", "_fake", "notreal", "not_real", "secret_here", "key_here", "token_here", "goes_here",
	"fixme", "<", ">", "${", "{{", "}}", "%s", "%(", "lorem", "foobar",
	"abcdefgh", "12345678", "00000000", "testkey", "test_key", "testtoken",
	"test_token", "testsecret", "test_secret", "mytoken", "mysecret", "mykey",
	"my_key", "my_token", "my_secret", "my_api", "api_key_here", "enter_",
	"undefined",
}

// knownExamples are published example credentials from vendor docs. They match
// every format check and are never real.
var knownExamples = map[string]bool{
	"AKIAIOSFODNN7EXAMPLE":                     true,
	"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY": true,
	"wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY": true,
	"AKIDEXAMPLE":                              true,
	"sk_test_4eC39HqLyjWDarjtT1zdp7dc":         true,
	"pk_test_TYooMQauvdEDq54NiTphI7jx":         true,
	"sk_test_BQokikJOvBiI2HlWgH4olfQ2":         true,
	"xoxb-not-a-real-token-this-will-not-work": true,
	"ghp_16C7e42F292c6912E7710c838347Ae178B4a": true,
}

// jwtExample is the sample token shown on jwt.io; it turns up in a lot of JS.
const jwtExample = "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

// PlaceholderReason returns why s looks like a placeholder, or "".
func PlaceholderReason(s string) string {
	if knownExamples[s] {
		return "published vendor example credential"
	}
	if strings.Contains(s, jwtExample) {
		return "jwt.io sample token"
	}
	low := strings.ToLower(s)
	for _, w := range placeholderWords {
		if strings.Contains(low, w) {
			return "contains placeholder text \"" + w + "\""
		}
	}
	if r := repeatedRun(s); r >= 6 {
		return "same character repeated " + strconv.Itoa(r) + " times"
	}
	if sequentialRun(low) >= 6 {
		return "contains a sequential run (abcdef/123456 style)"
	}
	return ""
}

// LowDiversity reports whether s uses too few distinct characters to be a
// generated secret.
func LowDiversity(s string) bool {
	if len(s) < 8 {
		return false
	}
	seen := map[byte]bool{}
	for i := 0; i < len(s); i++ {
		seen[s[i]] = true
	}
	need := len(s) / 4
	if need > 10 {
		need = 10
	}
	if need < 4 {
		need = 4
	}
	return len(seen) < need
}

func repeatedRun(s string) int {
	best, cur := 0, 0
	for i := 0; i < len(s); i++ {
		if i > 0 && s[i] == s[i-1] {
			cur++
		} else {
			cur = 1
		}
		if cur > best {
			best = cur
		}
	}
	return best
}

func sequentialRun(s string) int {
	best, cur := 0, 0
	for i := 0; i < len(s); i++ {
		if i > 0 && isAlnum(s[i]) && s[i] == s[i-1]+1 {
			cur++
		} else {
			cur = 1
		}
		if cur > best {
			best = cur
		}
	}
	return best
}

func isAlnum(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

// testContext matches paths and surrounding text that suggest a fixture,
// mock or example rather than live configuration.
var testContext = regexp.MustCompile(`(?i)(^|[/\\._-])(tests?|spec|specs|fixtures?|mocks?|examples?|samples?|demo|docs?|__tests__|testdata|stubs?)([/\\._-]|$)`)

// TestPath reports whether a source path looks like test or example material.
func TestPath(p string) bool {
	return testContext.MatchString(p)
}

// codeReference matches values that are clearly references to some other
// value rather than the value itself: env lookups, template variables,
// constant names, member access, function calls.
var codeReference = regexp.MustCompile(`^(process\.env|import\.meta|os\.environ|env\(|getenv|config\.|settings\.|this\.|self\.|window\.|document\.|\$|@|%|#\{|\{)|^[A-Z][A-Z0-9_]{3,}$|\(\)?$|^[a-z]+(\.[a-zA-Z_]+){1,}$`)

// IsCodeReference reports whether a captured value is a reference to a
// secret rather than the secret itself.
func IsCodeReference(v string) bool {
	return codeReference.MatchString(v)
}

// charClasses counts how many of lower/upper/digit/symbol appear in s.
func charClasses(s string) int {
	var lo, up, dg, sy bool
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z':
			lo = true
		case c >= 'A' && c <= 'Z':
			up = true
		case c >= '0' && c <= '9':
			dg = true
		default:
			sy = true
		}
	}
	n := 0
	for _, b := range []bool{lo, up, dg, sy} {
		if b {
			n++
		}
	}
	return n
}

var (
	uuidRe       = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	hashPrefixRe = regexp.MustCompile(`^(sha(1|256|384|512)-|md5-)`)
	pathLikeRe   = regexp.MustCompile(`^(\.{0,2}/|https?://|[a-zA-Z]:\\)|\.(js|css|png|jpe?g|svg|gif|html?|json|map|woff2?)$`)
	wordsOnlyRe  = regexp.MustCompile(`^[A-Za-z]+([ _-][A-Za-z]+)*$`)
	propPathRe   = regexp.MustCompile(`^[A-Za-z_$][A-Za-z0-9_$]*(\[[^\]]*\])?(\.[A-Za-z_$][A-Za-z0-9_$]*(\[[^\]]*\])?)+$`)
	camelIdentRe = regexp.MustCompile(`^[a-z]+([A-Z][a-z]+)+$`)
)
