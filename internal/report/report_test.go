package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/CypherNova1337/SecretSniffer/internal/engine"
	"github.com/CypherNova1337/SecretSniffer/internal/finding"
)

func sample() *finding.Finding {
	return &finding.Finding{
		RuleID: "stripe-key", Name: "Stripe secret key", Severity: "critical", Status: finding.Verified, Score: 100,
		Secret:    "sk_live_0123456789abcdefABCDEFGH",
		Identity:  "acct_1 (ops@target.tld)",
		Access:    []string{"account \"Acme\" (US), charges enabled"},
		Locations: []finding.Location{{Source: "https://target.tld/app.js", Line: 3}},
		Evidence: &finding.Evidence{
			Command: "curl -s 'https://api.stripe.com/v1/account' -u sk_live_0123456789abcdefABCDEFGH:",
			Request: "GET https://api.stripe.com/v1/account", Status: 200,
			Response: `{"id":"acct_1"}`, Time: "2026-11-09T10:00:00Z",
		},
	}
}

func TestMarkdownReport(t *testing.T) {
	var b bytes.Buffer
	dropped := &finding.Finding{Name: "Google API key", Status: finding.Dropped}
	Markdown(&b, []*finding.Finding{dropped, sample()}, engine.Stats{Verified: 1}, false)
	out := b.String()
	for _, want := range []string{"| 1 | critical | Stripe secret key | verified |", "**What it can access**", "```bash\ncurl -s", "returned HTTP 200"} {
		if !strings.Contains(out, want) {
			t.Errorf("report missing %q\n%s", want, out)
		}
	}
	if strings.Contains(out, "Google API key") {
		t.Error("dropped findings don't belong in the report")
	}
}

func TestRedactionCoversEvidence(t *testing.T) {
	var b bytes.Buffer
	Markdown(&b, []*finding.Finding{sample()}, engine.Stats{}, true)
	if strings.Contains(b.String(), "sk_live_0123456789abcdefABCDEFGH") {
		t.Fatal("secret leaked through the redacted report")
	}
	var j bytes.Buffer
	writeJSON(&j, sample(), true)
	if strings.Contains(j.String(), "sk_live_0123456789abcdefABCDEFGH") {
		t.Fatal("secret leaked through redacted JSON evidence")
	}
}
