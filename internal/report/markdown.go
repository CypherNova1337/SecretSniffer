package report

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/CypherNova1337/SecretSniffer/internal/engine"
	"github.com/CypherNova1337/SecretSniffer/internal/finding"
)

var sevRank = map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

// Markdown writes a report of verified and likely findings, ready to paste
// into a bug bounty submission or a ticket.
func Markdown(w io.Writer, fs []*finding.Finding, st engine.Stats, redact bool) {
	var keep []*finding.Finding
	for _, f := range fs {
		if f.Status == finding.Dropped {
			continue
		}
		if redact {
			f = redactFinding(f)
		}
		keep = append(keep, f)
	}
	sort.SliceStable(keep, func(i, j int) bool {
		a, b := keep[i], keep[j]
		if a.Status != b.Status {
			return a.Status == finding.Verified
		}
		if sevRank[a.Severity] != sevRank[b.Severity] {
			return sevRank[a.Severity] < sevRank[b.Severity]
		}
		return a.Score > b.Score
	})

	fmt.Fprintf(w, "# Secret findings\n\n")
	fmt.Fprintf(w, "%d verified, %d likely. Scanned %d sources: %d raw matches, %d unique credentials, %d discarded as noise or dead.\n\n",
		st.Verified, st.Likely, st.Chunks, st.Candidates, st.Unique, st.Dropped)
	if len(keep) == 0 {
		fmt.Fprintln(w, "Nothing worth reporting was found.")
		return
	}
	fmt.Fprintln(w, "| # | Severity | Type | Status | Where |")
	fmt.Fprintln(w, "|---|---|---|---|---|")
	for i, f := range keep {
		status := "verified"
		if f.Status == finding.Likely {
			status = fmt.Sprintf("likely (%d)", f.Score)
		}
		fmt.Fprintf(w, "| %d | %s | %s | %s | %s |\n", i+1, f.Severity, f.Name, status, mdCell(firstLoc(f)))
	}
	for i, f := range keep {
		fmt.Fprintf(w, "\n## %d. %s - %s (%s)\n\n", i+1, strings.ToUpper(f.Severity), f.Name, f.Status)
		if len(f.Secret) > 120 || strings.Contains(f.Secret, "\n") {
			fmt.Fprintf(w, "- **Secret:**\n\n```\n%s\n```\n\n", strings.ReplaceAll(f.Secret, `\n`, "\n"))
		} else {
			fmt.Fprintf(w, "- **Secret:** `%s`\n", f.Secret)
		}
		for _, k := range sortedKeys(f.Parts) {
			if k == "private_key" {
				continue
			}
			fmt.Fprintf(w, "- **%s:** `%s`\n", k, f.Parts[k])
		}
		if f.Identity != "" {
			fmt.Fprintf(w, "- **Belongs to:** %s\n", f.Identity)
		}
		for _, k := range sortedKeys(f.Info) {
			fmt.Fprintf(w, "- **%s:** %s\n", strings.ReplaceAll(k, "_", " "), f.Info[k])
		}
		if len(f.Access) > 0 {
			fmt.Fprintf(w, "\n**What it can access**\n\n")
			for _, a := range f.Access {
				fmt.Fprintf(w, "- %s\n", a)
			}
		}
		fmt.Fprintf(w, "\n**Found at**\n\n")
		for _, l := range f.Locations {
			line := "- `" + l.String() + "`"
			if l.Author != "" {
				line += " - committed by " + l.Author + " on " + l.Date
			}
			fmt.Fprintln(w, line)
		}
		if f.Context != "" {
			fmt.Fprintf(w, "\n```\n%s\n```\n", f.Context)
		}
		if ev := f.Evidence; ev != nil {
			fmt.Fprintf(w, "\n**Reproduce**\n\n```bash\n%s\n```\n", ev.Command)
			if ev.Status != 0 {
				fmt.Fprintf(w, "\nVerified %s - `%s` returned HTTP %d:\n\n```\n%s\n```\n", ev.Time, ev.Request, ev.Status, ev.Response)
			}
		}
		if len(f.Reasons) > 0 {
			fmt.Fprintf(w, "\n**Why it was kept:** %s\n", strings.Join(f.Reasons, "; "))
		}
	}
}

func firstLoc(f *finding.Finding) string {
	if len(f.Locations) == 0 {
		return ""
	}
	s := f.Locations[0].String()
	if n := len(f.Locations) - 1; n > 0 {
		s += fmt.Sprintf(" (+%d)", n)
	}
	return s
}

func mdCell(s string) string {
	return strings.ReplaceAll(s, "|", `\|`)
}
