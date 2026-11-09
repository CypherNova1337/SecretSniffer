// Package rules defines what a credential looks like for each provider, how to
// pair it with the values it needs (an AWS key ID needs its secret, a Shopify
// token needs its shop), and the offline checks that decide whether a match is
// worth anyone's time before a single request is sent.
package rules

import (
	"regexp"

	"github.com/CypherNova1337/SecretSniffer/internal/finding"
)

// Companion is a second value a credential needs before it can be used or
// verified, searched for near the primary match.
type Companion struct {
	Name   string
	Re     *regexp.Regexp
	Group  int // capture group holding the value (0 = whole match)
	Window int // bytes either side of the primary match to search
	Max    int // most companion values to try
	// Valid rejects companion values that cannot be right (optional).
	Valid func(v string) bool
}

// Rule describes one kind of credential.
type Rule struct {
	ID       string
	Name     string
	Severity string // severity if confirmed live
	Keywords []string
	Re       *regexp.Regexp
	Group    int  // capture group holding the secret (0 = whole match)
	Boundary bool // secret must not be glued to other alphanumerics

	MinEntropy float64
	Base       int  // score when it cannot be verified
	Verifiable bool // a read-only provider check exists

	Companions       []Companion
	RequireCompanion bool   // without the companion the match is useless
	NoCompanionNote  string // reason recorded when RequireCompanion drops it

	// Check runs offline validation and enrichment. It can set c.Drop, move
	// c.Score, and add to c.Reasons and c.Info.
	Check func(c *finding.Candidate)

	// SkipWordFilter turns off the placeholder word list for formats that are
	// validated by parsing instead (keys, JWTs), where long random bodies
	// could contain a listed word by chance.
	SkipWordFilter bool

	// Generic rules match on variable names rather than a vendor format.
	// They get stricter filtering and lose to any specific rule.
	Generic bool
}

const (
	Critical = "critical"
	High     = "high"
	Medium   = "medium"
	Low      = "low"
	Info     = "info"
)

func re(s string) *regexp.Regexp { return regexp.MustCompile(s) }

// All returns every rule. Specific vendor rules come first; generic rules last.
func All() []*Rule { return all }

// ByID looks up a rule.
func ByID(id string) *Rule { return byID[id] }

var byID = map[string]*Rule{}

func init() {
	for _, r := range all {
		if _, dup := byID[r.ID]; dup {
			panic("duplicate rule id " + r.ID)
		}
		byID[r.ID] = r
	}
}

var all = []*Rule{
	// ---------------------------------------------------------------- cloud
	{
		ID: "aws-access-key", Name: "AWS access key", Severity: Critical,
		Keywords: []string{"akia", "asia", "abia", "acca"},
		Re:       re(`(?:AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16}`), Boundary: true,
		Base: 40, Verifiable: true,
		Companions: []Companion{{
			Name:   "secret_key",
			Re:     re(`(?:^|[^A-Za-z0-9/+])([A-Za-z0-9/+]{40})(?:[^A-Za-z0-9/+=]|$)`),
			Group:  1,
			Window: 600, Max: 6,
			Valid: validAWSSecret,
		}, {
			Name:   "session_token",
			Re:     re(`(?i)(?:session[_-]?token|security[_-]?token)["']?\s*[:=]\s*["']?([A-Za-z0-9/+=]{100,})`),
			Group:  1,
			Window: 2000, Max: 1,
		}},
		Check: checkAWS,
	},
	{
		ID: "gcp-service-account", Name: "Google Cloud service account key", Severity: Critical,
		Keywords: []string{"service_account"},
		Re:       re(`"type"\s*:\s*"service_account"`),
		Base:     40, Verifiable: true,
		Companions: []Companion{{
			Name:   "private_key",
			Re:     re(`"private_key"\s*:\s*"(-----BEGIN PRIVATE KEY-----[^"]+-----END PRIVATE KEY-----(?:\\n)?)"`),
			Group:  1,
			Window: 4000, Max: 1,
		}, {
			Name:   "client_email",
			Re:     re(`"client_email"\s*:\s*"([^"@]+@[^"]+\.iam\.gserviceaccount\.com)"`),
			Group:  1,
			Window: 4000, Max: 1,
		}},
		RequireCompanion: true,
		NoCompanionNote:  "service account JSON without a private key",
		Check:            checkGCPServiceAccount,
	},
	{
		ID: "azure-storage-key", Name: "Azure storage account key", Severity: Critical,
		Keywords: []string{"accountkey"},
		Re:       re(`(?i)AccountName=([a-z0-9]{3,24});\s*AccountKey=([A-Za-z0-9+/]{86}==)`),
		Group:    2,
		Base:     80, Verifiable: true,
		Check: checkAzureStorage,
	},
	{
		ID: "digitalocean-token", Name: "DigitalOcean token", Severity: Critical,
		Keywords: []string{"dop_v1_", "doo_v1_", "dor_v1_"},
		Re:       re(`do[opr]_v1_[a-f0-9]{64}`), Boundary: true,
		Base: 80, Verifiable: true,
	},
	{
		ID: "heroku-key", Name: "Heroku API key", Severity: Critical,
		Keywords: []string{"hrku-"},
		Re:       re(`HRKU-AA[0-9A-Za-z_-]{58}`), Boundary: true,
		Base: 80, Verifiable: true,
	},

	// ------------------------------------------------------------ source code
	{
		ID: "github-token", Name: "GitHub token", Severity: Critical,
		Keywords: []string{"ghp_", "gho_", "ghu_", "ghs_", "ghr_"},
		Re:       re(`gh[pousr]_[A-Za-z0-9]{36}`), Boundary: true,
		Base: 75, Verifiable: true,
	},
	{
		ID: "github-fine-grained", Name: "GitHub fine-grained token", Severity: Critical,
		Keywords: []string{"github_pat_"},
		Re:       re(`github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}`), Boundary: true,
		Base: 80, Verifiable: true,
	},
	{
		ID: "gitlab-token", Name: "GitLab token", Severity: Critical,
		Keywords: []string{"glpat-", "gldt-", "glrt-", "glcbt-", "glptt-"},
		Re:       re(`gl(?:pat|dt|rt|cbt|ptt)-[0-9A-Za-z_.\-]{20,64}`), Boundary: true,
		Base: 75, Verifiable: true,
		Companions: []Companion{{
			Name:   "host",
			Re:     re(`https?://(gitlab\.[a-z0-9.-]+\.[a-z]{2,}|[a-z0-9.-]*gitlab[a-z0-9.-]*\.[a-z]{2,})`),
			Group:  1,
			Window: 2000, Max: 2,
		}},
	},
	{
		ID: "npm-token", Name: "npm access token", Severity: High,
		Keywords: []string{"npm_"},
		Re:       re(`npm_[A-Za-z0-9]{36}`), Boundary: true,
		Base: 75, Verifiable: true,
	},
	{
		ID: "pypi-token", Name: "PyPI upload token", Severity: High,
		Keywords: []string{"pypi-ageichlwas5vcmc"},
		Re:       re(`pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}`), Boundary: true,
		Base:  80,
		Check: checkPyPI,
	},

	// ------------------------------------------------------------- payments
	{
		ID: "stripe-key", Name: "Stripe secret key", Severity: Critical,
		Keywords: []string{"sk_live_", "rk_live_", "sk_test_", "rk_test_"},
		Re:       re(`[sr]k_(?:live|test)_[0-9a-zA-Z]{24,247}`), Boundary: true,
		Base: 75, Verifiable: true,
		Check: checkStripe,
	},
	{
		ID: "square-token", Name: "Square access token", Severity: Critical,
		Keywords: []string{"eaaa", "sq0atp-"},
		Re:       re(`(?:EAAA[A-Za-z0-9_-]{60}|sq0atp-[0-9A-Za-z_-]{22})`), Boundary: true,
		Base: 70, Verifiable: true,
	},
	{
		ID: "square-oauth-secret", Name: "Square OAuth secret", Severity: High,
		Keywords: []string{"sq0csp-"},
		Re:       re(`sq0csp-[0-9A-Za-z_-]{43}`), Boundary: true,
		Base: 75,
	},
	{
		ID: "shopify-token", Name: "Shopify access token", Severity: Critical,
		Keywords: []string{"shpat_", "shpca_", "shppa_"},
		Re:       re(`shp(?:at|ca|pa)_[a-fA-F0-9]{32}`), Boundary: true,
		Base: 75, Verifiable: true,
		Companions: []Companion{{
			Name:   "shop",
			Re:     re(`([a-z0-9][a-z0-9-]*\.myshopify\.com)`),
			Group:  1,
			Window: 3000, Max: 3,
		}},
	},
	{
		ID: "shopify-shared-secret", Name: "Shopify shared secret", Severity: High,
		Keywords: []string{"shpss_"},
		Re:       re(`shpss_[a-fA-F0-9]{32}`), Boundary: true,
		Base: 75,
	},

	// -------------------------------------------------------- communication
	{
		ID: "slack-token", Name: "Slack token", Severity: High,
		Keywords: []string{"xoxb-", "xoxp-", "xoxa-", "xoxr-", "xoxs-", "xoxe-"},
		Re:       re(`xox(?:[bpars]|e(?:\.xox[bp])?)-[0-9A-Za-z-]{10,250}`), Boundary: true,
		Base: 70, Verifiable: true,
	},
	{
		ID: "slack-webhook", Name: "Slack incoming webhook", Severity: Medium,
		Keywords: []string{"hooks.slack.com"},
		Re:       re(`https://hooks\.slack\.com/(?:services|workflows|triggers)/[A-Za-z0-9+/_-]{20,}`),
		Base:     65, Verifiable: true,
	},
	{
		ID: "discord-webhook", Name: "Discord webhook", Severity: Medium,
		Keywords: []string{"discord.com/api/webhooks", "discordapp.com/api/webhooks"},
		Re:       re(`https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d{17,20}/[A-Za-z0-9_-]{60,70}`),
		Base:     65, Verifiable: true,
	},
	{
		ID: "discord-bot-token", Name: "Discord bot token", Severity: High,
		Keywords: []string{"discord", "bot"},
		Re:       re(`[MNO][A-Za-z0-9_-]{23,27}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,40}`), Boundary: true,
		Base: 55, Verifiable: true,
		Check: checkDiscordBot,
	},
	{
		ID: "telegram-bot-token", Name: "Telegram bot token", Severity: High,
		Keywords: []string{":aa"},
		Re:       re(`\d{8,10}:AA[A-Za-z0-9_-]{33}`), Boundary: true,
		Base: 70, Verifiable: true,
	},
	{
		ID: "twilio-credentials", Name: "Twilio account credentials", Severity: Critical,
		Keywords: []string{"twilio", "ac"},
		Re:       re(`AC[a-f0-9]{32}`), Boundary: true,
		Base: 70, Verifiable: true,
		Companions: []Companion{{
			Name:   "auth_token",
			Re:     re(`(?:^|[^a-f0-9])([a-f0-9]{32})(?:[^a-f0-9]|$)`),
			Group:  1,
			Window: 400, Max: 4,
			Valid: validHexSecret,
		}},
		RequireCompanion: true,
		NoCompanionNote:  "account SID on its own is an identifier, not a secret",
	},
	{
		ID: "sendgrid-key", Name: "SendGrid API key", Severity: High,
		Keywords: []string{"sg."},
		Re:       re(`SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}`), Boundary: true,
		Base: 80, Verifiable: true,
	},
	{
		ID: "mailgun-key", Name: "Mailgun API key", Severity: High,
		Keywords: []string{"key-"},
		Re:       re(`key-[0-9a-f]{32}`), Boundary: true,
		Base: 60, Verifiable: true,
	},
	{
		ID: "mailchimp-key", Name: "Mailchimp API key", Severity: High,
		Keywords: []string{"-us"},
		Re:       re(`[0-9a-f]{32}-us[0-9]{1,2}`), Boundary: true,
		Base: 70, Verifiable: true,
	},

	// ------------------------------------------------------------------- AI
	{
		ID: "openai-key", Name: "OpenAI API key", Severity: High,
		Keywords: []string{"t3blbkfj"},
		Re:       re(`sk-(?:proj-|svcacct-|admin-|None-)?[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,}`), Boundary: true,
		Base: 80, Verifiable: true,
	},
	{
		ID: "anthropic-key", Name: "Anthropic API key", Severity: High,
		Keywords: []string{"sk-ant-"},
		Re:       re(`sk-ant-(?:api03|admin01)-[A-Za-z0-9_-]{93}AA`), Boundary: true,
		Base: 80, Verifiable: true,
	},
	{
		ID: "huggingface-token", Name: "Hugging Face token", Severity: High,
		Keywords: []string{"hf_"},
		Re:       re(`hf_[A-Za-z]{34}`), Boundary: true,
		Base: 70, Verifiable: true,
	},

	// --------------------------------------------------------- SaaS / misc
	{
		ID: "google-api-key", Name: "Google API key", Severity: Low,
		Keywords: []string{"aiza"},
		Re:       re(`AIza[0-9A-Za-z_-]{35}`), Boundary: true,
		// Usually shipped to browsers on purpose (Maps, Firebase). Not worth
		// showing unless it is proven usable.
		Base: 35, Verifiable: true,
	},
	{
		ID: "algolia-key", Name: "Algolia API key", Severity: High,
		Keywords: []string{"algolia"},
		Re:       re(`(?i)(?:algolia[\w.-]*?(?:api)?[_-]?key|x-algolia-api-key)["']?\s*[:=,]\s*["']([a-f0-9]{32})["']`),
		Group:    1,
		Base:     40, Verifiable: true,
		Companions: []Companion{{
			Name:   "app_id",
			Re:     re(`(?i)(?:app(?:lication)?[_-]?id|x-algolia-application-id)["']?\s*[:=,]\s*["']([A-Z0-9]{10})["']`),
			Group:  1,
			Window: 3000, Max: 2,
		}},
		RequireCompanion: true,
		NoCompanionNote:  "Algolia key without an application ID can't be used",
	},
	{
		ID: "mapbox-secret-token", Name: "Mapbox secret token", Severity: Medium,
		Keywords: []string{"sk.eyj"},
		Re:       re(`sk\.eyJ[A-Za-z0-9_-]{50,}\.[A-Za-z0-9_-]{20,}`), Boundary: true,
		Base: 75, Verifiable: true,
	},
	{
		ID: "facebook-token", Name: "Facebook access token", Severity: High,
		Keywords: []string{"eaa"},
		Re:       re(`EAA[B-Z0-9][A-Za-z0-9]{80,250}`), Boundary: true,
		Base: 60, Verifiable: true,
	},
	{
		ID: "dropbox-token", Name: "Dropbox access token", Severity: High,
		Keywords: []string{"sl."},
		Re:       re(`sl\.[A-Za-z0-9_-]{130,160}`), Boundary: true,
		Base: 65, Verifiable: true,
	},
	{
		ID: "notion-token", Name: "Notion integration token", Severity: High,
		Keywords: []string{"secret_", "ntn_"},
		Re:       re(`(?:secret_[A-Za-z0-9]{43}|ntn_[0-9]{11}[A-Za-z0-9]{35})`), Boundary: true,
		Base: 65, Verifiable: true,
	},
	{
		ID: "linear-key", Name: "Linear API key", Severity: High,
		Keywords: []string{"lin_api_"},
		Re:       re(`lin_api_[A-Za-z0-9]{40}`), Boundary: true,
		Base: 80, Verifiable: true,
	},
	{
		ID: "postman-key", Name: "Postman API key", Severity: High,
		Keywords: []string{"pmak-"},
		Re:       re(`PMAK-[a-f0-9]{24}-[a-f0-9]{34}`), Boundary: true,
		Base: 80, Verifiable: true,
	},
	{
		ID: "cloudinary-url", Name: "Cloudinary credentials", Severity: High,
		Keywords: []string{"cloudinary://"},
		Re:       re(`cloudinary://([0-9]{6,20}):([A-Za-z0-9_-]{20,40})@([a-z0-9_-]+)`),
		Group:    2,
		Base:     75, Verifiable: true,
		Check: checkCloudinary,
	},

	// ----------------------------------------------------- structured secrets
	{
		ID: "private-key", Name: "Private key", Severity: Critical,
		Keywords: []string{"private key"},
		Re:       re(`-----BEGIN ((?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?)-----[\s\S]{20,}?-----END (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----`),
		Base:     55,
		Check:    checkPrivateKey, SkipWordFilter: true,
	},
	{
		ID: "jwt", Name: "JSON Web Token", Severity: Medium,
		Keywords: []string{"eyj"},
		Re:       re(`eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{16,}`), Boundary: true,
		Base: 45, Verifiable: true, // only Supabase service keys are checked
		Check: checkJWT, SkipWordFilter: true,
	},
	{
		ID: "database-uri", Name: "Database connection string", Severity: Critical,
		Keywords: []string{"://"},
		Re:       re(`(?i)\b((?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqps?|mssql|sqlserver|cockroachdb)://([^:@/\s"'<>]+):([^@\s"'<>]+)@([^/\s"'<>:?]+)[^\s"'<>]*)`),
		Group:    1,
		Base:     70,
		Check:    checkURI,
	},
	{
		ID: "url-credentials", Name: "Credentials in URL", Severity: High,
		Keywords: []string{"://"},
		Re:       re(`(?i)\b(https?|ftp|ftps|smtp|smtps|ldaps?)://([^:@/\s"'<>]{1,64}):([^@\s"'<>/]{3,128})@([a-z0-9.-]+\.[a-z]{2,}|\d{1,3}(?:\.\d{1,3}){3})`),
		Base:     50,
		Check:    checkURI,
	},
	{
		ID: "basic-auth-header", Name: "Hardcoded Basic auth header", Severity: High,
		Keywords: []string{"basic "},
		Re:       re(`(?i)authorization["']?\s*[:=,]\s*["']Basic ([A-Za-z0-9+/]{8,}={0,2})["']`),
		Group:    1,
		Base:     55, Verifiable: true,
		Check: checkBasicAuth,
	},

	// --------------------------------------------------------------- generic
	{
		ID: "generic-secret", Name: "Hardcoded secret", Severity: Medium,
		Keywords: []string{"key", "secret", "token", "passw", "pwd", "auth", "credential"},
		Re:       re(`(?i)["']?([a-z0-9_.-]*(?:api[_-]?key|apikey|secret|token|passw(?:or)?d|pwd|client[_-]?secret|access[_-]?key|private[_-]?key|auth[_-]?key|credential)[a-z0-9_-]*)["']?\s*(?::=|=>|[:=])\s*["'\x60]([^"'\x60\s]{8,200})["'\x60]`),
		Group:    2,
		Base:     40, Verifiable: true,
		Generic: true,
		Check:   checkGeneric,
	},
}
