// Package engine turns raw content into scored candidates, de-duplicates
// them, runs verification and decides what is worth reporting.
package engine

import (
	"bytes"
	"sort"
	"strings"

	"github.com/CypherNova1337/SecretSniffer/internal/finding"
	"github.com/CypherNova1337/SecretSniffer/internal/rules"
)

// Chunk is a piece of content to scan.
type Chunk struct {
	Loc   finding.Location // base location; Line is filled per match
	Data  []byte
	Lines []int // optional: original line number of each line in Data (git diffs)
	Local bool  // from disk or a repo, where test/example paths mean something
}

var exampleWords = [][]byte{[]byte("example"), []byte("sample"), []byte("dummy"), []byte("placeholder"), []byte("fake"), []byte("mock"), []byte("e.g.")}

// Detect runs every rule over a chunk and returns scored candidates. Dropped
// candidates are returned too, with Drop set, so the caller can account for
// them. Besides the raw content it scans decoded views of it: base64 and hex
// blobs, escaped strings, char-code arrays and concatenated string pieces.
func Detect(ch Chunk) []*finding.Candidate {
	nl := newlineIndex(ch.Data)
	testPath := false
	if ch.Local {
		p := ch.Loc.Source
		if ch.Loc.File != "" {
			p = ch.Loc.File
		}
		testPath = rules.TestPath(p)
	}

	out := scanData(ch.Data, func(off int) finding.Location { return locate(ch, nl, off) }, "", testPath)
	for _, v := range decodedViews(ch.Data) {
		loc := locate(ch, nl, v.at)
		out = append(out, scanData(v.text, func(int) finding.Location { return loc }, v.how, testPath)...)
	}
	return preferSpecific(out)
}

func scanData(data []byte, loc func(int) finding.Location, how string, testPath bool) []*finding.Candidate {
	lower := bytes.ToLower(data)
	var out []*finding.Candidate
	for _, r := range rules.All() {
		if !hasAny(lower, r.Keywords) {
			continue
		}
		for _, m := range r.Re.FindAllSubmatchIndex(data, -1) {
			gs, ge := m[2*r.Group], m[2*r.Group+1]
			if gs < 0 {
				continue
			}
			if r.Boundary && !bounded(data, gs, ge) {
				continue
			}
			groups := make([]string, len(m)/2)
			for i := range groups {
				if m[2*i] >= 0 {
					groups[i] = string(data[m[2*i]:m[2*i+1]])
				}
			}
			base := &finding.Candidate{
				RuleID: r.ID,
				Secret: string(data[gs:ge]),
				Groups: groups,
				Loc:    loc(gs),
				Score:  r.Base,
			}
			base.Context = snippet(data, gs, ge)

			preFilter(r, base)

			for _, c := range withCompanions(r, base, data, m[0], m[1]) {
				if c.Drop == "" && r.Check != nil {
					r.Check(c)
				}
				if c.Drop == "" {
					if how != "" {
						if c.Info == nil {
							c.Info = map[string]string{}
						}
						c.Info["hidden_by"] = how
						c.Reasons = append(c.Reasons, "hidden by "+how+" - deliberately obscured")
					}
					if testPath {
						c.Score -= 20
						c.Reasons = append(c.Reasons, "found in a test/example path")
					}
					if nearExampleWords(lower, gs) {
						c.Score -= 15
						c.Reasons = append(c.Reasons, "surrounded by example/placeholder wording")
					}
				}
				out = append(out, c)
			}
		}
	}
	return out
}

// preFilter applies the checks every rule shares.
func preFilter(r *rules.Rule, c *finding.Candidate) {
	if !r.SkipWordFilter {
		if why := rules.PlaceholderReason(c.Secret); why != "" {
			c.Drop = why
			return
		}
	}
	if !r.SkipWordFilter && rules.LowDiversity(c.Secret) {
		c.Drop = "too few distinct characters to be generated"
		return
	}
	if r.MinEntropy > 0 && rules.Entropy(c.Secret) < r.MinEntropy {
		c.Drop = "entropy too low"
	}
}

// withCompanions finds the values a credential needs and fans out one
// candidate per plausible pairing.
func withCompanions(r *rules.Rule, base *finding.Candidate, data []byte, ms, me int) []*finding.Candidate {
	if len(r.Companions) == 0 || base.Drop != "" {
		return []*finding.Candidate{base}
	}
	single := map[string]string{}
	var fanName string
	var fanVals []string
	for i, comp := range r.Companions {
		vals := findCompanion(comp, data, ms, me, base.Secret)
		if len(vals) == 0 {
			if i == 0 && r.RequireCompanion {
				base.Drop = r.NoCompanionNote
				return []*finding.Candidate{base}
			}
			continue
		}
		if comp.Max > 1 && fanName == "" {
			fanName, fanVals = comp.Name, vals
		} else {
			single[comp.Name] = vals[0]
		}
	}
	if fanName == "" {
		fanVals = []string{""}
	}
	out := make([]*finding.Candidate, 0, len(fanVals))
	for _, v := range fanVals {
		c := *base
		c.Parts = map[string]string{}
		for k, sv := range single {
			c.Parts[k] = sv
		}
		if fanName != "" {
			c.Parts[fanName] = v
		}
		c.Reasons = append([]string(nil), base.Reasons...)
		out = append(out, &c)
	}
	return out
}

func findCompanion(comp rules.Companion, data []byte, ms, me int, primary string) []string {
	lo, hi := ms-comp.Window, me+comp.Window
	if lo < 0 {
		lo = 0
	}
	if hi > len(data) {
		hi = len(data)
	}
	region := data[lo:hi]
	type hit struct {
		v    string
		dist int
	}
	var hits []hit
	seen := map[string]bool{}
	for _, m := range comp.Re.FindAllSubmatchIndex(region, -1) {
		s, e := m[2*comp.Group], m[2*comp.Group+1]
		if s < 0 {
			continue
		}
		abs := lo + s
		if abs >= ms && abs < me { // inside the primary match itself
			continue
		}
		v := string(region[s:e])
		if seen[v] || v == primary || strings.Contains(primary, v) || strings.Contains(v, primary) {
			continue
		}
		if comp.Valid != nil && !comp.Valid(v) {
			continue
		}
		seen[v] = true
		d := abs - ms
		if d < 0 {
			d = -d
		}
		hits = append(hits, hit{v, d})
	}
	// Closest first: the value written next to the key is the likeliest pair.
	sort.Slice(hits, func(i, j int) bool { return hits[i].dist < hits[j].dist })
	max := comp.Max
	if max <= 0 {
		max = 1
	}
	var vals []string
	for _, h := range hits {
		if len(vals) == max {
			break
		}
		vals = append(vals, h.v)
	}
	return vals
}

// preferSpecific drops generic matches whose value is already covered by a
// vendor-specific rule, so one secret isn't reported twice.
func preferSpecific(cs []*finding.Candidate) []*finding.Candidate {
	var specific []string
	for _, c := range cs {
		if r := rules.ByID(c.RuleID); r != nil && !r.Generic {
			specific = append(specific, c.Secret)
			for _, g := range c.Groups {
				if len(g) >= 8 {
					specific = append(specific, g)
				}
			}
			for _, p := range c.Parts {
				if len(p) >= 8 {
					specific = append(specific, p)
				}
			}
		}
	}
	if len(specific) == 0 {
		return cs
	}
	out := cs[:0]
	for _, c := range cs {
		if r := rules.ByID(c.RuleID); r != nil && r.Generic {
			covered := false
			for _, s := range specific {
				if strings.Contains(s, c.Secret) || strings.Contains(c.Secret, s) {
					covered = true
					break
				}
			}
			if covered {
				continue
			}
		}
		out = append(out, c)
	}
	return out
}

func hasAny(lower []byte, kws []string) bool {
	if len(kws) == 0 {
		return true
	}
	for _, k := range kws {
		if bytes.Contains(lower, []byte(k)) {
			return true
		}
	}
	return false
}

func isWordByte(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

func bounded(data []byte, s, e int) bool {
	if s > 0 && isWordByte(data[s-1]) {
		return false
	}
	if e < len(data) && isWordByte(data[e]) {
		return false
	}
	return true
}

func nearExampleWords(lower []byte, at int) bool {
	lo := at - 80
	if lo < 0 {
		lo = 0
	}
	win := lower[lo:at]
	for _, w := range exampleWords {
		if bytes.Contains(win, w) {
			return true
		}
	}
	return false
}

func newlineIndex(data []byte) []int {
	var idx []int
	for i, b := range data {
		if b == '\n' {
			idx = append(idx, i)
		}
	}
	return idx
}

func locate(ch Chunk, nl []int, off int) finding.Location {
	loc := ch.Loc
	line := sort.SearchInts(nl, off) // number of newlines before off
	if ch.Lines != nil {
		if line < len(ch.Lines) {
			loc.Line = ch.Lines[line]
		}
	} else {
		loc.Line = line + 1
	}
	return loc
}

func snippet(data []byte, s, e int) string {
	const pad = 50
	lo, hi := s-pad, e+pad
	if lo < 0 {
		lo = 0
	}
	if hi > len(data) {
		hi = len(data)
	}
	if e-s > 200 { // long secrets (keys): show only the start
		hi = s + 80
	}
	out := strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' {
			return ' '
		}
		return r
	}, string(data[lo:hi]))
	return strings.ToValidUTF8(strings.TrimSpace(out), "?")
}
