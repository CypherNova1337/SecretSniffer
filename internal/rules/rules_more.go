package rules

import (
	"encoding/base64"
	"encoding/json"
	"strings"

	"github.com/CypherNova1337/SecretSniffer/internal/finding"
)

// Shared companion patterns.
var (
	guid       = `[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`
	compTenant = Companion{Name: "tenant_id", Re: re(`(?i)(?:tenant|directory)[\w-]*["']?\s*[:=]\s*["']?(` + guid + `)`), Group: 1, Window: 2000, Max: 1}
	compClient = Companion{Name: "client_id", Re: re(`(?i)(?:client|app(?:lication)?)[_-]?id["']?\s*[:=]\s*["']?(` + guid + `)`), Group: 1, Window: 2000, Max: 1}
	compEmail  = Companion{Name: "email", Re: re(`([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})`), Group: 1, Window: 1500, Max: 2,
		Valid: func(v string) bool { return PlaceholderReason(v) == "" }}
)

func init() {
	// Insert before the generic rule so specific rules take precedence in
	// listings; de-duplication doesn't depend on order.
	n := len(all)
	all = append(all[:n-1:n-1], append(more, all[n-1])...)
	for _, r := range more {
		if _, dup := byID[r.ID]; dup {
			panic("duplicate rule id " + r.ID)
		}
		byID[r.ID] = r
	}
}

var more = []*Rule{
	// ------------------------------------------------------ identity / cloud
	{
		ID: "azure-ad-client-secret", Name: "Azure AD (Entra ID) client secret", Severity: Critical,
		Keywords: []string{"q~"},
		Re:       re(`[A-Za-z0-9_~.\-]{3}[0-9]Q~[A-Za-z0-9_~.\-]{31,34}`), Boundary: true,
		Base: 70, Verifiable: true,
		Companions: []Companion{compTenant, compClient},
	},
	{
		ID: "okta-token", Name: "Okta API token", Severity: Critical,
		Keywords: []string{"okta", "ssws"},
		Re:       re(`(?i)(?:ssws\s+|okta[\w.-]*(?:token|key)["']?\s*[:=]\s*["'])(00[A-Za-z0-9_-]{40})`),
		Group:    1,
		Base:     70, Verifiable: true,
		Companions: []Companion{{Name: "domain", Re: re(`([a-z0-9-]+\.(?:okta|oktapreview|okta-emea)\.com)`), Group: 1, Window: 3000, Max: 2}},
	},
	{
		ID: "vault-token", Name: "HashiCorp Vault token", Severity: Critical,
		Keywords: []string{"hvs.", "hvb."},
		Re:       re(`hv[sb]\.[A-Za-z0-9_-]{90,300}`), Boundary: true,
		Base: 75, Verifiable: true,
		Companions: []Companion{{Name: "addr", Re: re(`(?i)(?:vault[_-]?addr(?:ess)?["']?\s*[:=]\s*["']?)?(https?://[a-z0-9.-]+(?::8200)?)(?:/v1|["'\s]|$)`), Group: 1, Window: 3000, Max: 1,
			Valid: func(v string) bool { return strings.Contains(v, "vault") || strings.HasSuffix(v, ":8200") }}},
	},
	{
		ID: "terraform-cloud-token", Name: "Terraform Cloud token", Severity: Critical,
		Keywords: []string{".atlasv1."},
		Re:       re(`[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9_-]{60,70}`), Boundary: true,
		Base: 80, Verifiable: true,
	},
	{
		ID: "doppler-token", Name: "Doppler token", Severity: Critical,
		Keywords: []string{"dp.pt.", "dp.st.", "dp.sa.", "dp.ct.", "dp.scim.", "dp.audit."},
		Re:       re(`dp\.(?:pt|st|sa|ct|scim|audit)\.[A-Za-z0-9]{40,44}`), Boundary: true,
		Base: 80, Verifiable: true,
	},
	{
		ID: "pulumi-token", Name: "Pulumi access token", Severity: High,
		Keywords: []string{"pul-"},
		Re:       re(`pul-[a-f0-9]{40}`), Boundary: true,
		Base: 75, Verifiable: true,
	},
	{
		ID: "netlify-token", Name: "Netlify access token", Severity: High,
		Keywords: []string{"nfp_"},
		Re:       re(`nfp_[A-Za-z0-9]{36}`), Boundary: true,
		Base: 75, Verifiable: true,
	},
	{
		ID: "render-key", Name: "Render API key", Severity: High,
		Keywords: []string{"rnd_"},
		Re:       re(`rnd_[A-Za-z0-9]{32}`), Boundary: true,
		Base: 75, Verifiable: true,
	},
	{
		ID: "cloudflare-token", Name: "Cloudflare API token", Severity: Critical,
		Keywords: []string{"cloudflare", "cf_api"},
		Re:       re(`(?i)(?:cloudflare|cf)[\w.-]*(?:api)?[_-]?(?:token|key)["']?\s*[:=]\s*["']([A-Za-z0-9_-]{40})["']`),
		Group:    1,
		Base:     60, Verifiable: true,
	},
	{
		ID: "supabase-secret-key", Name: "Supabase secret key", Severity: Critical,
		Keywords: []string{"sb_secret_"},
		Re:       re(`sb_secret_[A-Za-z0-9_-]{31,64}`), Boundary: true,
		Base: 80, Verifiable: true,
		Companions: []Companion{{Name: "project", Re: re(`https://([a-z0-9]{20})\.supabase\.co`), Group: 1, Window: 4000, Max: 1}},
	},
	{
		ID: "firebase-database", Name: "Firebase Realtime Database", Severity: Critical,
		Keywords: []string{"firebaseio.com", "firebasedatabase.app"},
		Re:       re(`https://([a-z0-9-]+(?:-default-rtdb)?)\.(?:firebaseio\.com|[a-z0-9-]+\.firebasedatabase\.app)`),
		// A database URL is public by design; it only matters if the
		// security rules let anyone read it, which only the check can tell.
		Base: 10, Verifiable: true,
	},

	// ------------------------------------------------------- dev tooling
	{
		ID: "atlassian-token", Name: "Atlassian API token", Severity: High,
		Keywords: []string{"atatt3"},
		Re:       re(`ATATT3[A-Za-z0-9_\-=]{150,250}`), Boundary: true,
		Base: 75, Verifiable: true,
		Companions: []Companion{{Name: "site", Re: re(`([a-z0-9-]+\.atlassian\.net)`), Group: 1, Window: 3000, Max: 1}, compEmail},
	},
	{
		ID: "bitbucket-app-password", Name: "Bitbucket app password", Severity: High,
		Keywords: []string{"atbb"},
		Re:       re(`ATBB[A-Za-z0-9_=.\-]{32}`), Boundary: true,
		Base: 75, Verifiable: true,
		Companions: []Companion{{Name: "username", Re: re(`(?i)(?:bitbucket|bb)[\w.-]*user(?:name)?["']?\s*[:=]\s*["']([A-Za-z0-9_.\-]{2,40})["']`), Group: 1, Window: 2000, Max: 1}},
	},
	{
		ID: "jfrog-token", Name: "JFrog Artifactory credential", Severity: Critical,
		Keywords: []string{"akcp", "cmvmd"},
		Re:       re(`(?:AKCp[A-Za-z0-9]{69}|cmVmd[A-Za-z0-9]{59})`), Boundary: true,
		Base: 75, Verifiable: true,
		Companions: []Companion{{Name: "host", Re: re(`([a-z0-9-]+\.jfrog\.io)`), Group: 1, Window: 4000, Max: 1}},
	},
	{
		ID: "sentry-token", Name: "Sentry auth token", Severity: High,
		Keywords: []string{"sntrys_", "sntryu_"},
		Re:       re(`(?:sntrys_eyJ[A-Za-z0-9+/=_-]{60,400}|sntryu_[a-f0-9]{64})`), Boundary: true,
		Base: 75, Verifiable: true,
		Check: checkSentry,
	},
	{
		ID: "grafana-token", Name: "Grafana service account token", Severity: High,
		Keywords: []string{"glsa_"},
		Re:       re(`glsa_[A-Za-z0-9]{32}_[a-f0-9]{8}`), Boundary: true,
		Base: 75, Verifiable: true,
		Companions: []Companion{{Name: "instance", Re: re(`(https://[a-z0-9-]+\.grafana\.net)`), Group: 1, Window: 4000, Max: 1}},
	},
	{
		ID: "grafana-cloud-token", Name: "Grafana Cloud token", Severity: High,
		Keywords: []string{"glc_"},
		Re:       re(`glc_[A-Za-z0-9+/]{32,400}={0,2}`), Boundary: true,
		Base:  70,
		Check: checkGrafanaCloud,
	},
	{
		ID: "circleci-token", Name: "CircleCI personal token", Severity: High,
		Keywords: []string{"ccipat_"},
		Re:       re(`CCIPAT_[A-Za-z0-9]{22}_[a-f0-9]{40}`), Boundary: true,
		Base: 80, Verifiable: true,
	},
	{
		ID: "buildkite-token", Name: "Buildkite API token", Severity: High,
		Keywords: []string{"bkua_"},
		Re:       re(`bkua_[a-f0-9]{40}`), Boundary: true,
		Base: 80, Verifiable: true,
	},

	// ------------------------------------------------------- monitoring
	{
		ID: "datadog-key", Name: "Datadog API key", Severity: High,
		Keywords: []string{"datadog", "dd_api", "dd-api"},
		Re:       re(`(?i)(?:datadog|dd)[\w.-]*api[_-]?key["']?\s*[:=]\s*["']?([a-f0-9]{32})\b`),
		Group:    1,
		Base:     60, Verifiable: true,
	},
	{
		ID: "newrelic-key", Name: "New Relic user API key", Severity: High,
		Keywords: []string{"nrak-"},
		Re:       re(`NRAK-[A-Z0-9]{27}`), Boundary: true,
		Base: 80, Verifiable: true,
	},
	{
		ID: "pagerduty-key", Name: "PagerDuty API key", Severity: High,
		Keywords: []string{"pagerduty"},
		Re:       re(`(?i)pagerduty[\w.-]*(?:token|key)["']?\s*[:=]\s*["']([A-Za-z0-9_+\-]{20})["']`),
		Group:    1,
		Base:     60, Verifiable: true,
	},

	// ------------------------------------------------------- SaaS
	{
		ID: "zendesk-token", Name: "Zendesk API token", Severity: High,
		Keywords: []string{"zendesk"},
		Re:       re(`(?i)zendesk[\w.-]*(?:api)?[_-]?token["']?\s*[:=]\s*["']([A-Za-z0-9]{40})["']`),
		Group:    1,
		Base:     65, Verifiable: true,
		Companions: []Companion{{Name: "subdomain", Re: re(`([a-z0-9-]+)\.zendesk\.com`), Group: 1, Window: 3000, Max: 1}, compEmail},
	},
	{
		ID: "airtable-token", Name: "Airtable personal access token", Severity: High,
		Keywords: []string{"pat"},
		Re:       re(`pat[A-Za-z0-9]{14}\.[a-f0-9]{64}`), Boundary: true,
		Base: 80, Verifiable: true,
	},
	{
		ID: "asana-token", Name: "Asana personal access token", Severity: High,
		Keywords: []string{"asana", "/1", "/2"},
		Re:       re(`[12]/[0-9]{13,19}(?:/[0-9]{13,19})?:[A-Za-z0-9]{32}`), Boundary: true,
		Base: 70, Verifiable: true,
	},
	{
		ID: "figma-token", Name: "Figma access token", Severity: Medium,
		Keywords: []string{"figd_"},
		Re:       re(`figd_[A-Za-z0-9_-]{40,60}`), Boundary: true,
		Base: 80, Verifiable: true,
	},
	{
		ID: "typeform-token", Name: "Typeform access token", Severity: Medium,
		Keywords: []string{"tfp_"},
		Re:       re(`tfp_[A-Za-z0-9_-]{40,60}`), Boundary: true,
		Base: 80, Verifiable: true,
	},
	{
		ID: "contentful-token", Name: "Contentful management token", Severity: High,
		Keywords: []string{"cfpat-"},
		Re:       re(`CFPAT-[A-Za-z0-9_-]{43}`), Boundary: true,
		Base: 80, Verifiable: true,
	},
	{
		ID: "hubspot-token", Name: "HubSpot private app token", Severity: High,
		Keywords: []string{"pat-na1-", "pat-eu1-"},
		Re:       re(`pat-(?:na1|eu1)-` + guid), Boundary: true,
		Base: 80, Verifiable: true,
	},
	{
		ID: "brevo-key", Name: "Brevo (Sendinblue) API key", Severity: High,
		Keywords: []string{"xkeysib-"},
		Re:       re(`xkeysib-[a-f0-9]{64}-[A-Za-z0-9]{16}`), Boundary: true,
		Base: 80, Verifiable: true,
	},
	{
		ID: "intercom-token", Name: "Intercom access token", Severity: High,
		Keywords: []string{"dg9ro"},
		Re:       re(`dG9rO[A-Za-z0-9+/]{50,120}={0,2}`), Boundary: true,
		Base: 65, Verifiable: true,
		Check: checkIntercom,
	},
	{
		ID: "stripe-webhook-secret", Name: "Stripe webhook signing secret", Severity: Medium,
		Keywords: []string{"whsec_"},
		Re:       re(`whsec_[A-Za-z0-9]{32,64}`), Boundary: true,
		Base: 70,
	},
	{
		ID: "razorpay-key", Name: "Razorpay API key", Severity: Critical,
		Keywords: []string{"rzp_live_"},
		Re:       re(`rzp_live_[A-Za-z0-9]{14}`), Boundary: true,
		Base: 50, Verifiable: true,
		Companions:       []Companion{{Name: "key_secret", Re: re(`(?i)(?:razorpay|rzp|key)[\w.-]*secret["']?\s*[:=]\s*["']([A-Za-z0-9]{24})["']`), Group: 1, Window: 1500, Max: 1}},
		RequireCompanion: true,
		NoCompanionNote:  "Razorpay key ID on its own is public; the key secret wasn't found",
	},
	{
		ID: "shippo-token", Name: "Shippo live token", Severity: High,
		Keywords: []string{"shippo_live_"},
		Re:       re(`shippo_live_[a-f0-9]{40}`), Boundary: true,
		Base: 80, Verifiable: true,
	},

	// ------------------------------------------------------------- AI
	{
		ID: "groq-key", Name: "Groq API key", Severity: High,
		Keywords: []string{"gsk_"},
		Re:       re(`gsk_[A-Za-z0-9]{52}`), Boundary: true,
		Base: 80, Verifiable: true,
	},
	{
		ID: "replicate-token", Name: "Replicate API token", Severity: High,
		Keywords: []string{"r8_"},
		Re:       re(`r8_[A-Za-z0-9]{37}`), Boundary: true,
		Base: 75, Verifiable: true,
	},
	{
		ID: "xai-key", Name: "xAI API key", Severity: High,
		Keywords: []string{"xai-"},
		Re:       re(`xai-[A-Za-z0-9]{80}`), Boundary: true,
		Base: 80, Verifiable: true,
	},
	{
		ID: "elevenlabs-key", Name: "ElevenLabs API key", Severity: Medium,
		Keywords: []string{"sk_"},
		Re:       re(`sk_[a-f0-9]{48}`), Boundary: true,
		Base: 70, Verifiable: true,
	},
	{
		ID: "pinecone-key", Name: "Pinecone API key", Severity: High,
		Keywords: []string{"pcsk_"},
		Re:       re(`pcsk_[A-Za-z0-9_]{50,100}`), Boundary: true,
		Base: 80, Verifiable: true,
	},
	{
		ID: "langsmith-key", Name: "LangSmith API key", Severity: Medium,
		Keywords: []string{"lsv2_"},
		Re:       re(`lsv2_(?:pt|sk)_[a-f0-9]{32}_[a-f0-9]{10}`), Boundary: true,
		Base: 80, Verifiable: true,
	},
}

// ------------------------------------------------------------- checks

func b64JSON(s string) map[string]any {
	s = strings.TrimRight(s, "=")
	for _, enc := range []*base64.Encoding{base64.RawStdEncoding, base64.RawURLEncoding} {
		if raw, err := enc.DecodeString(s); err == nil {
			var m map[string]any
			if json.Unmarshal(raw, &m) == nil {
				return m
			}
		}
	}
	return nil
}

// Sentry org tokens embed their region URL and organisation.
func checkSentry(c *finding.Candidate) {
	if !strings.HasPrefix(c.Secret, "sntrys_") {
		return
	}
	body := strings.TrimPrefix(c.Secret, "sntrys_")
	if i := strings.IndexByte(body, '_'); i > 0 {
		body = body[:i]
	}
	m := b64JSON(body)
	if m == nil {
		c.Drop = "Sentry org token payload does not decode"
		return
	}
	if u, _ := m["url"].(string); u != "" {
		setPart(c, "url", strings.TrimRight(u, "/"))
	}
	if org, _ := m["org"].(string); org != "" {
		setPart(c, "org", org)
		setInfo(c, "org", org)
	}
}

// Grafana Cloud tokens embed the org and region they belong to.
func checkGrafanaCloud(c *finding.Candidate) {
	m := b64JSON(strings.TrimPrefix(c.Secret, "glc_"))
	if m == nil {
		c.Drop = "Grafana Cloud token payload does not decode"
		return
	}
	if o, ok := m["o"].(string); ok {
		setInfo(c, "org_id", o)
	}
	if n, ok := m["n"].(string); ok {
		setInfo(c, "token_name", n)
	}
	because(c, 10, "payload decodes to a Grafana Cloud token")
}

// Intercom tokens are base64 of "tok:<uuid>:...".
func checkIntercom(c *finding.Candidate) {
	raw, err := base64.StdEncoding.DecodeString(c.Secret)
	if err != nil {
		raw, err = base64.RawStdEncoding.DecodeString(strings.TrimRight(c.Secret, "="))
	}
	if err != nil || !strings.HasPrefix(string(raw), "tok:") {
		c.Drop = "does not decode to an Intercom token"
		return
	}
	because(c, 10, "decodes to an Intercom token")
}
