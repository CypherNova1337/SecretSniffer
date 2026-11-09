// Package finding holds the types shared between detection, verification and
// reporting.
package finding

import (
	"sort"
	"strconv"
	"strings"
)

// Location is one place a secret was seen.
type Location struct {
	Source string `json:"source"`           // URL, file path, or repo path
	Line   int    `json:"line,omitempty"`   // 1-based line number, 0 if unknown
	Commit string `json:"commit,omitempty"` // git only
	Author string `json:"author,omitempty"` // git only
	Date   string `json:"date,omitempty"`   // git only
	File   string `json:"file,omitempty"`   // git only: path inside the repo
	// Archived is the capture date when the content came from the Wayback
	// Machine rather than the live site.
	Archived string `json:"archived,omitempty"`
}

func (l Location) String() string {
	var b strings.Builder
	if l.Commit != "" {
		short := l.Commit
		if len(short) > 10 {
			short = short[:10]
		}
		b.WriteString(l.Source)
		b.WriteString("@")
		b.WriteString(short)
		b.WriteString(":")
		b.WriteString(l.File)
	} else {
		b.WriteString(l.Source)
	}
	if l.Line > 0 {
		b.WriteString(":")
		b.WriteString(strconv.Itoa(l.Line))
	}
	if l.Archived != "" {
		b.WriteString(" (archived " + l.Archived + ")")
	}
	return b.String()
}

// Status is where a finding ended up after filtering and verification.
type Status string

const (
	// Verified means the provider confirmed the credential works right now.
	Verified Status = "verified"
	// Likely means it could not be verified (no API, verification off, or the
	// check was inconclusive) but it passed every filter and scored above the
	// threshold.
	Likely Status = "likely"
	// Dropped means it was discarded: dead key, placeholder, public-by-design,
	// low score, and so on. Only shown with -show-dropped.
	Dropped Status = "dropped"
)

// Candidate is a single raw match produced by a detector, before
// de-duplication and verification.
type Candidate struct {
	RuleID  string
	Secret  string
	Parts   map[string]string // companion values, e.g. "secret_key", "shop"
	Loc     Location
	Context string
	Score   int
	Reasons []string
	Info    map[string]string // details recovered offline (key type, account id, ...)
	Drop    string            // non-empty means a filter discarded it, with the reason

	// Severity overrides the rule's severity when set (e.g. a Stripe test key).
	Severity string
	// Groups holds the regex submatches of the primary match.
	Groups []string
}

// Key identifies a unique credential: same rule, same secret, same companions.
func (c *Candidate) Key() string {
	var b strings.Builder
	b.WriteString(c.RuleID)
	b.WriteByte(0)
	b.WriteString(c.Secret)
	keys := make([]string, 0, len(c.Parts))
	for k := range c.Parts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		b.WriteByte(0)
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(c.Parts[k])
	}
	return b.String()
}

// Finding is a de-duplicated credential with its final verdict.
type Finding struct {
	RuleID    string            `json:"rule"`
	Name      string            `json:"name"`
	Severity  string            `json:"severity"`
	Status    Status            `json:"status"`
	Score     int               `json:"score"`
	Secret    string            `json:"secret"`
	Parts     map[string]string `json:"parts,omitempty"`
	Identity  string            `json:"identity,omitempty"` // who/what the key belongs to, per the provider
	Access    []string          `json:"access,omitempty"`   // what a live key can reach, from enrichment
	Evidence  *Evidence         `json:"evidence,omitempty"` // how to reproduce the verification
	Reasons   []string          `json:"reasons,omitempty"`
	Info      map[string]string `json:"info,omitempty"`
	Drop      string            `json:"drop_reason,omitempty"`
	Context   string            `json:"context,omitempty"`
	Locations []Location        `json:"locations"`
}

// Evidence is what a triager needs to confirm a finding without trusting the
// tool: a command that reproduces the check and what the provider answered.
type Evidence struct {
	Command  string `json:"command"`
	Request  string `json:"request,omitempty"`
	Status   int    `json:"status,omitempty"`
	Response string `json:"response,omitempty"`
	Time     string `json:"time"`
}
