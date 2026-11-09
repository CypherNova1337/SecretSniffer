package verify

import (
	"sort"

	"github.com/CypherNova1337/SecretSniffer/internal/finding"

	"strings"
	"time"
)

// Evidence is defined with the other shared types.
type Evidence = finding.Evidence

// shq single-quotes s for a POSIX shell.
func shq(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func buildEvidence(t Target, rec []exchange) *Evidence {
	ev := &Evidence{Time: time.Now().UTC().Format(time.RFC3339)}
	// The confirming exchange is the last successful one (some checks try
	// several regions or endpoints before one answers).
	var ex *exchange
	for i := len(rec) - 1; i >= 0; i-- {
		if rec[i].status >= 200 && rec[i].status < 300 {
			ex = &rec[i]
			break
		}
	}
	if ex == nil && len(rec) > 0 {
		ex = &rec[len(rec)-1]
	}
	if ex != nil {
		ev.Request = ex.method + " " + ex.url
		ev.Status = ex.status
		ev.Response = snippetOf(ex.resp, 400)
		ev.Time = ex.at.Format(time.RFC3339)
	}

	// Signed requests can't be replayed with curl (the signature expires),
	// so give the vendor's own CLI instead.
	switch t.RuleID {
	case "aws-access-key":
		cmd := "AWS_ACCESS_KEY_ID=" + shq(t.Secret) + " AWS_SECRET_ACCESS_KEY=" + shq(t.Parts["secret_key"])
		if tok := t.Parts["session_token"]; tok != "" {
			cmd += " AWS_SESSION_TOKEN=" + shq(tok)
		}
		ev.Command = cmd + " aws sts get-caller-identity"
	case "azure-storage-key":
		ev.Command = "az storage container list --account-name " + shq(t.Parts["account"]) + " --account-key " + shq(t.Secret) + " -o table"
	case "gcp-service-account":
		ev.Command = "# save the leaked service account JSON as key.json, then:\ngcloud auth activate-service-account --key-file key.json && gcloud projects list"
	default:
		if ex != nil {
			ev.Command = curlFor(*ex)
		}
	}
	return ev
}

func curlFor(ex exchange) string {
	var b strings.Builder
	b.WriteString("curl -s")
	if ex.method != "GET" {
		b.WriteString(" -X " + ex.method)
	}
	b.WriteString(" " + shq(ex.url))
	keys := make([]string, 0, len(ex.headers))
	for k := range ex.headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		b.WriteString(" -H " + shq(k+": "+ex.headers[k]))
	}
	if ex.body != "" {
		b.WriteString(" --data " + shq(ex.body))
	}
	return b.String()
}

func snippetOf(b []byte, n int) string {
	s := strings.Join(strings.Fields(string(b)), " ")
	if len(s) > n {
		s = s[:n] + "..."
	}
	return s
}
