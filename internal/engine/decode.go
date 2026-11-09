package engine

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"regexp"
	"strconv"
	"strings"
)

// view is a decoded rendering of part of a chunk. text is scanned like normal
// content; at is the offset in the original data it came from.
type view struct {
	text []byte
	at   int
	how  string
}

const maxViews = 5000

type literal struct {
	start, end int    // offsets of the opening and closing quote
	body       string // raw contents between the quotes
}

// literals finds quoted string literals. It's a lexer, not a parser: good
// enough for minified JS, JSON, config files and most source code.
func literals(data []byte) []literal {
	var out []literal
	for i := 0; i < len(data); i++ {
		q := data[i]
		if q != '"' && q != '\'' && q != '`' {
			continue
		}
		if i > 0 && data[i-1] == '\\' {
			continue
		}
		j := i + 1
		for ; j < len(data) && j-i < 8192; j++ {
			c := data[j]
			if c == '\\' {
				j++
				continue
			}
			if c == q {
				break
			}
			if c == '\n' && q != '`' {
				break
			}
		}
		if j >= len(data) || data[j] != q {
			continue
		}
		out = append(out, literal{start: i, end: j, body: string(data[i+1 : j])})
		i = j
	}
	return out
}

var assignName = regexp.MustCompile(`([A-Za-z_$][A-Za-z0-9_$.\-]*)["']?\s*(?::=|=>|[:=])[^:=]*$`)

// nameBefore recovers the variable or key a value is assigned to, so the
// decoded view still reads as `name = "value"` and generic rules work.
func nameBefore(data []byte, at int) string {
	lo := at - 80
	if lo < 0 {
		lo = 0
	}
	pre := data[lo:at]
	if i := bytes.LastIndexByte(pre, '\n'); i >= 0 {
		pre = pre[i+1:]
	}
	m := assignName.FindSubmatch(pre)
	if m == nil {
		return ""
	}
	return string(m[1])
}

func render(name, value string) []byte {
	if name == "" {
		return []byte(`"` + value + `"`)
	}
	return []byte(name + ` = "` + value + `"`)
}

var (
	b64Re      = regexp.MustCompile(`^[A-Za-z0-9+/_-]{16,}={0,2}$`)
	hexRe      = regexp.MustCompile(`^(?:[0-9a-fA-F]{2}){16,}$`)
	unquotedRe = regexp.MustCompile(`(?m)^[ \t]*([A-Za-z_][A-Za-z0-9_.\-]*)[ \t]*[:=][ \t]*([A-Za-z0-9+/]{16,}={0,2})[ \t\r]*$`)
	charCodeRe = regexp.MustCompile(`String\.fromCharCode\(\s*((?:\d{1,3}\s*,\s*){7,}\d{1,3})\s*\)`)
	joinRe     = regexp.MustCompile(`^\s*\]\s*\.\s*join\(\s*(?:""|''|\x60\x60)\s*\)`)
)

// decodedViews returns every decodable rendering of hidden content in data.
func decodedViews(data []byte) []view {
	var out []view
	add := func(v view) bool {
		out = append(out, v)
		return len(out) < maxViews
	}
	lits := literals(data)

	// Concatenated pieces: "sk_li" + "ve_..." and ["sk_li","ve_..."].join("")
	for _, sep := range []string{"+", ","} {
		for i := 0; i < len(lits); {
			j := i
			for j+1 < len(lits) && separatedBy(data[lits[j].end+1:lits[j+1].start], sep) {
				j++
			}
			if j > i && (sep == "+" || isJoinedArray(data, lits[i].start, lits[j].end+1)) {
				var b strings.Builder
				for k := i; k <= j; k++ {
					b.WriteString(unescape(lits[k].body))
				}
				how := "string concatenation"
				if sep == "," {
					how = "array join"
				}
				if !add(view{text: render(nameBefore(data, lits[i].start), b.String()), at: lits[i].start, how: how}) {
					return out
				}
			}
			i = j + 1
		}
	}

	for _, l := range lits {
		body := l.body
		var dec, how string
		switch {
		case strings.Count(body, `\x`)+strings.Count(body, `\u`) >= 4:
			dec, how = unescape(body), "escape sequences"
		case hexRe.MatchString(body):
			if raw, err := hex.DecodeString(body); err == nil && printable(raw) {
				dec, how = string(raw), "hex encoding"
			}
		case b64Re.MatchString(body):
			if raw := b64(body); raw != nil && printable(raw) {
				dec, how = string(raw), "base64"
			}
		}
		if dec == "" || dec == body {
			continue
		}
		if !add(view{text: render(nameBefore(data, l.start), dec), at: l.start, how: how}) {
			return out
		}
	}

	// Unquoted base64 values: .env files, Kubernetes Secret manifests.
	for _, m := range unquotedRe.FindAllSubmatchIndex(data, -1) {
		val := string(data[m[4]:m[5]])
		if raw := b64(val); raw != nil && printable(raw) {
			if !add(view{text: render(string(data[m[2]:m[3]]), strings.TrimRight(string(raw), "\r\n")), at: m[4], how: "base64"}) {
				return out
			}
		}
	}

	for _, m := range charCodeRe.FindAllSubmatchIndex(data, -1) {
		var b strings.Builder
		for _, n := range strings.Split(string(data[m[2]:m[3]]), ",") {
			v, err := strconv.Atoi(strings.TrimSpace(n))
			if err != nil || v > 255 {
				b.Reset()
				break
			}
			b.WriteByte(byte(v))
		}
		if b.Len() > 0 && printable([]byte(b.String())) {
			if !add(view{text: render(nameBefore(data, m[0]), b.String()), at: m[0], how: "char codes"}) {
				return out
			}
		}
	}
	return out
}

// separatedBy reports whether the bytes between two literals are only the
// given operator (and whitespace).
func separatedBy(between []byte, sep string) bool {
	return len(between) < 40 && string(bytes.TrimSpace(between)) == sep
}

// isJoinedArray reports whether the literals spanning [start,end) form an
// array literal that is immediately .join("")-ed.
func isJoinedArray(data []byte, start, end int) bool {
	before := bytes.TrimRight(data[:start], " \t\r\n")
	return len(before) > 0 && before[len(before)-1] == '[' && joinRe.Match(data[end:])
}

func b64(s string) []byte {
	s = strings.TrimRight(s, "=")
	for _, enc := range []*base64.Encoding{base64.RawStdEncoding, base64.RawURLEncoding} {
		if raw, err := enc.DecodeString(s); err == nil {
			return raw
		}
	}
	return nil
}

// printable reports whether decoded bytes look like text worth scanning.
func printable(b []byte) bool {
	if len(b) < 12 {
		return false
	}
	bad, letters := 0, 0
	for _, c := range b {
		switch {
		case c == '\n' || c == '\r' || c == '\t':
		case c < 0x20 || c > 0x7e:
			bad++
		case c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z':
			letters++
		}
	}
	return bad == 0 && letters >= 4
}

// unescape decodes JS/JSON string escapes, leaving anything unknown as is.
func unescape(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '\\' || i+1 >= len(s) {
			b.WriteByte(c)
			continue
		}
		i++
		switch e := s[i]; e {
		case 'n':
			b.WriteByte('\n')
		case 't':
			b.WriteByte('\t')
		case 'r':
			b.WriteByte('\r')
		case 'x':
			if i+2 < len(s) {
				if v, err := strconv.ParseUint(s[i+1:i+3], 16, 8); err == nil {
					b.WriteByte(byte(v))
					i += 2
					continue
				}
			}
			b.WriteString(`\x`)
		case 'u':
			if i+4 < len(s) {
				if v, err := strconv.ParseUint(s[i+1:i+5], 16, 16); err == nil {
					b.WriteRune(rune(v))
					i += 4
					continue
				}
			}
			b.WriteString(`\u`)
		default:
			b.WriteByte(e)
		}
	}
	return b.String()
}
