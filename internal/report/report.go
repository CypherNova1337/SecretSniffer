// Package report prints findings for people (text) and for pipelines (JSON
// lines).
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"

	"github.com/CypherNova1337/SecretSniffer/internal/engine"
	"github.com/CypherNova1337/SecretSniffer/internal/finding"
)

// Printer writes findings as they are decided.
type Printer struct {
	W      io.Writer
	JSON   bool
	Color  bool
	Redact bool
	File   io.Writer // optional: JSON lines copy of everything printed
	mu     sync.Mutex
}

const (
	reset  = "\033[0m"
	bold   = "\033[1m"
	red    = "\033[31m"
	yellow = "\033[33m"
	cyan   = "\033[36m"
	grey   = "\033[90m"
	green  = "\033[32m"
)

func (p *Printer) c(code, s string) string {
	if !p.Color {
		return s
	}
	return code + s + reset
}

// Redacted keeps enough of a secret to recognise it.
func Redacted(s string) string {
	if len(s) <= 12 {
		return strings.Repeat("*", len(s))
	}
	return s[:6] + strings.Repeat("*", min(len(s)-10, 20)) + s[len(s)-4:]
}

func (p *Printer) secret(s string) string {
	if p.Redact {
		return Redacted(s)
	}
	return s
}

// Print writes one finding.
func (p *Printer) Print(f *finding.Finding) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.File != nil {
		writeJSON(p.File, f, p.Redact)
	}
	if p.JSON {
		writeJSON(p.W, f, p.Redact)
		return
	}
	switch f.Status {
	case finding.Dropped:
		p.printDropped(f)
	default:
		p.printFull(f)
	}
}

func writeJSON(w io.Writer, f *finding.Finding, redact bool) {
	if redact {
		cp := *f
		cp.Secret = Redacted(f.Secret)
		cp.Context = ""
		if f.Parts != nil {
			cp.Parts = map[string]string{}
			for k, v := range f.Parts {
				cp.Parts[k] = Redacted(v)
			}
		}
		f = &cp
	}
	b, _ := json.Marshal(f)
	fmt.Fprintln(w, string(b))
}

func (p *Printer) sevColor(sev string) string {
	switch sev {
	case "critical":
		return p.c(bold+red, strings.ToUpper(sev))
	case "high":
		return p.c(red, strings.ToUpper(sev))
	case "medium":
		return p.c(yellow, strings.ToUpper(sev))
	default:
		return p.c(cyan, strings.ToUpper(sev))
	}
}

func (p *Printer) printFull(f *finding.Finding) {
	var tag string
	if f.Status == finding.Verified {
		tag = p.c(bold+green, "[VERIFIED]")
	} else {
		tag = p.c(yellow, fmt.Sprintf("[LIKELY %d]", f.Score))
	}
	w := p.W
	fmt.Fprintf(w, "%s %s  %s\n", tag, p.sevColor(f.Severity), p.c(bold, f.Name))
	row := func(k, v string) {
		if v != "" {
			fmt.Fprintf(w, "  %-9s %s\n", p.c(grey, k), v)
		}
	}
	sec := p.secret(f.Secret)
	if len(sec) > 120 { // keys and long tokens: full value is in -json / -o
		sec = strings.ReplaceAll(sec[:72], `\n`, " ") + p.c(grey, fmt.Sprintf("... (%d chars, full value in -json/-o)", len(sec)))
	}
	row("secret", sec)
	for _, k := range sortedKeys(f.Parts) {
		v := f.Parts[k]
		if v == "" {
			continue
		}
		if k == "private_key" {
			v = "(present, " + fmt.Sprint(len(v)) + " chars)"
		} else if isSensitivePart(k) {
			v = p.secret(v)
		}
		row(k, v)
	}
	row("identity", f.Identity)
	for _, k := range sortedKeys(f.Info) {
		row(strings.ReplaceAll(k, "_", " "), f.Info[k])
	}
	if len(f.Locations) > 0 {
		loc := f.Locations[0].String()
		if n := len(f.Locations) - 1; n > 0 {
			loc += p.c(grey, fmt.Sprintf("  (+%d more)", n))
		}
		row("where", loc)
		if a := f.Locations[0].Author; a != "" {
			row("commit", a+" "+f.Locations[0].Date)
		}
	}
	if len(f.Reasons) > 0 {
		row("why", strings.Join(f.Reasons, "; "))
	}
	fmt.Fprintln(w)
}

func (p *Printer) printDropped(f *finding.Finding) {
	loc := ""
	if len(f.Locations) > 0 {
		loc = f.Locations[0].String()
	}
	fmt.Fprintf(p.W, "%s %s %s %s %s\n", p.c(grey, "[DROPPED]"), f.Name, p.secret(trunc(f.Secret, 60)),
		p.c(grey, "- "+f.Drop), p.c(grey, loc))
}

func isSensitivePart(k string) bool {
	switch k {
	case "secret_key", "auth_token", "session_token":
		return true
	}
	return false
}

func trunc(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func sortedKeys(m map[string]string) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

// Summary writes the end-of-scan line showing how much noise was removed.
func Summary(w io.Writer, s engine.Stats, color bool) {
	p := &Printer{Color: color}
	fmt.Fprintf(w, "%s scanned %d sources, %d raw matches, %d unique\n",
		p.c(bold, "done:"), s.Chunks, s.Candidates, s.Unique)
	fmt.Fprintf(w, "      %s verified, %s likely, %d dropped",
		p.c(bold+green, fmt.Sprint(s.Verified)), p.c(yellow, fmt.Sprint(s.Likely)), s.Dropped)
	if len(s.DropReasons) > 0 {
		type kv struct {
			k string
			v int
		}
		var kvs []kv
		for k, v := range s.DropReasons {
			kvs = append(kvs, kv{k, v})
		}
		sort.Slice(kvs, func(i, j int) bool { return kvs[i].v > kvs[j].v || kvs[i].v == kvs[j].v && kvs[i].k < kvs[j].k })
		var parts []string
		for _, e := range kvs {
			parts = append(parts, fmt.Sprintf("%s %d", e.k, e.v))
		}
		fmt.Fprintf(w, " %s", p.c(grey, "("+strings.Join(parts, ", ")+")"))
	}
	fmt.Fprintln(w)
}
