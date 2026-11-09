package engine

import (
	"encoding/base64"
	"testing"

	"github.com/CypherNova1337/SecretSniffer/internal/finding"
	"github.com/CypherNova1337/SecretSniffer/internal/rules"
	. "github.com/CypherNova1337/SecretSniffer/internal/testutil"
	"github.com/CypherNova1337/SecretSniffer/internal/verify"
)

// Every new provider rule must find a token of its documented shape and keep
// it (not drop it as noise).
func TestNewProviderFormats(t *testing.T) {
	lower := "abcdefghijklmnopqrstuvwxyz"
	upnum := "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	guid := func() string {
		return Rand(Hex, 8) + "-" + Rand(Hex, 4) + "-" + Rand(Hex, 4) + "-" + Rand(Hex, 4) + "-" + Rand(Hex, 12)
	}
	sentryPayload := base64.RawStdEncoding.EncodeToString([]byte(`{"iat":1700000000,"url":"https://sentry.io","region_url":"https://us.sentry.io","org":"acme"}`))
	grafanaPayload := base64.StdEncoding.EncodeToString([]byte(`{"o":"123456","n":"deploy-` + Rand(lower, 6) + `","k":"` + Rand(Alnum, 24) + `","m":{"r":"prod-us-east-0"}}`))
	intercom := base64.StdEncoding.EncodeToString([]byte("tok:" + guid() + ":" + Rand(Alnum, 12)))

	cases := map[string]string{
		"azure-ad-client-secret": `AZURE_CLIENT_SECRET="` + Rand(Alnum, 3) + "8Q~" + Rand(Alnum, 34) + `"`,
		"okta-token":             `okta_api_token = "00` + Rand(Alnum, 40) + `"`,
		"vault-token":            `VAULT_TOKEN="` + J("hv", "s.") + Rand(Alnum, 95) + `"`,
		"terraform-cloud-token":  `token = "` + Rand(Alnum, 14) + J(".atlas", "v1.") + Rand(Alnum, 67) + `"`,
		"doppler-token":          `DOPPLER_TOKEN=` + J("dp.", "st.") + Rand(Alnum, 43),
		"pulumi-token":           `PULUMI_ACCESS_TOKEN=` + J("pul", "-") + Rand(Hex, 40),
		"netlify-token":          `NETLIFY_AUTH_TOKEN=` + J("nf", "p_") + Rand(Alnum, 36),
		"render-key":             `RENDER_API_KEY=` + J("rn", "d_") + Rand(Alnum, 32),
		"cloudflare-token":       `CLOUDFLARE_API_TOKEN="` + Rand(Alnum, 40) + `"`,
		"supabase-secret-key":    `const s="` + J("sb_", "secret_") + Rand(Alnum, 36) + `"`,
		"firebase-database":      `databaseURL:"https://acme-prod-` + Rand(lower, 5) + `.firebaseio.com"`,
		"atlassian-token":        `JIRA_TOKEN=` + J("ATAT", "T3") + Rand(Alnum, 186),
		"bitbucket-app-password": `pw = "` + J("AT", "BB") + Rand(Alnum, 32) + `"`,
		"jfrog-token":            `ARTIFACTORY_API_KEY=` + J("AK", "Cp") + Rand(Alnum, 69),
		"sentry-token":           `SENTRY_AUTH_TOKEN=` + J("sntr", "ys_") + sentryPayload + "_" + Rand(Alnum, 43),
		"grafana-token":          `GRAFANA_TOKEN=` + J("gl", "sa_") + Rand(Alnum, 32) + "_" + Rand(Hex, 8),
		"grafana-cloud-token":    `GRAFANA_CLOUD=` + J("gl", "c_") + grafanaPayload,
		"circleci-token":         `CIRCLE_TOKEN=` + J("CCI", "PAT_") + Rand(Alnum, 22) + "_" + Rand(Hex, 40),
		"buildkite-token":        `BUILDKITE_TOKEN=` + J("bku", "a_") + Rand(Hex, 40),
		"datadog-key":            `DD_API_KEY=` + Rand(Hex, 32),
		"newrelic-key":           `NEW_RELIC_API_KEY=` + J("NR", "AK-") + Rand(upnum, 27),
		"pagerduty-key":          `pagerduty_token: "` + Rand(Alnum, 20) + `"`,
		"zendesk-token":          `ZENDESK_API_TOKEN="` + Rand(Alnum, 40) + `"`,
		"airtable-token":         `AIRTABLE=` + J("pa", "t") + Rand(Alnum, 14) + "." + Rand(Hex, 64),
		"asana-token":            `ASANA=` + "2/" + Rand("123456789", 16) + "/" + Rand("123456789", 16) + ":" + Rand(Alnum, 32),
		"figma-token":            `FIGMA=` + J("fig", "d_") + Rand(Alnum, 40),
		"typeform-token":         `TYPEFORM=` + J("tf", "p_") + Rand(Alnum, 44),
		"contentful-token":       `CONTENTFUL=` + J("CFP", "AT-") + Rand(Alnum, 43),
		"hubspot-token":          `HUBSPOT=` + J("pat-", "na1-") + guid(),
		"brevo-key":              `BREVO=` + J("xkey", "sib-") + Rand(Hex, 64) + "-" + Rand(Alnum, 16),
		"intercom-token":         `INTERCOM="` + intercom + `"`,
		"stripe-webhook-secret":  `STRIPE_WEBHOOK=` + J("wh", "sec_") + Rand(Alnum, 32),
		"razorpay-key":           `RAZORPAY_KEY_ID="` + J("rzp_", "live_") + Rand(Alnum, 14) + `"; RAZORPAY_KEY_SECRET="` + Rand(Alnum, 24) + `"`,
		"shippo-token":           `SHIPPO=` + J("shippo_", "live_") + Rand(Hex, 40),
		"groq-key":               `GROQ=` + J("gs", "k_") + Rand(Alnum, 52),
		"replicate-token":        `REPLICATE=` + J("r", "8_") + Rand(Alnum, 37),
		"xai-key":                `XAI=` + J("xa", "i-") + Rand(Alnum, 80),
		"elevenlabs-key":         `ELEVEN=` + J("s", "k_") + Rand(Hex, 48),
		"pinecone-key":           `PINECONE=` + J("pc", "sk_") + Rand(Alnum, 60),
		"langsmith-key":          `LANGSMITH=` + J("lsv2_", "pt_") + Rand(Hex, 32) + "_" + Rand(Hex, 10),
	}
	for rule, src := range cases {
		var got *finding.Candidate
		for _, c := range Detect(Chunk{Loc: finding.Location{Source: "config.env"}, Data: []byte("\n" + src + "\n")}) {
			if c.RuleID == rule {
				got = c
				break
			}
		}
		if got == nil {
			t.Errorf("%s: not detected in %q", rule, src)
			continue
		}
		if got.Drop != "" {
			t.Errorf("%s: dropped: %s", rule, got.Drop)
		}
	}
}

func TestVerifiableRulesHaveChecks(t *testing.T) {
	for _, r := range rules.All() {
		if r.Verifiable && !verify.Supports(r.ID) {
			t.Errorf("%s is marked verifiable but has no provider check", r.ID)
		}
		if !r.Verifiable && verify.Supports(r.ID) {
			t.Errorf("%s has a provider check but is not marked verifiable", r.ID)
		}
	}
}
