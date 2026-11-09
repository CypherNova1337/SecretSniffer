# SecretSniffer

Finds secrets in JavaScript, files and git history — then proves which ones are real.

![license](https://img.shields.io/badge/license-MIT-blue?style=flat-square)
![go](https://img.shields.io/badge/go-1.22%2B-00ADD8?style=flat-square)
![release](https://img.shields.io/badge/release-v1.2.0-brightgreen?style=flat-square)

## What it does

Run a regex-based secret finder over a site's JavaScript and you get a wall of
"API keys". Almost none of them matter. Most are documentation examples,
placeholders like `YOUR_API_KEY`, test fixtures, keys that were revoked years
ago, or values that were always meant to be public — a Google Maps key locked
to the site's domain, a Stripe publishable key, an Algolia search key. Somewhere
in the pile there might be one live credential, and you have to dig through the
rest by hand to find it.

SecretSniffer does that digging for you. Every match goes through three stages
before you see it:

1. **Is it even a secret?** Offline checks throw out placeholders, published
   vendor examples, low-entropy strings, variable references
   (`process.env.KEY`), property paths, UUIDs, integrity hashes and the like.
   Structured secrets are parsed rather than pattern-matched: a private key has
   to actually decode as a key, a JWT has to decode and not be expired, a
   Discord token's first segment has to decode to a user ID.
2. **Is it complete?** Credentials that come in pairs are paired. An AWS key ID
   is useless without its secret, so the secret is searched for next to it; a
   Shopify token is matched with its `*.myshopify.com` store; a Twilio SID with
   its auth token.
3. **Does it work right now?** Each credential is sent to the provider that
   issued it, using a single read-only call — `GetCallerIdentity` for AWS,
   `auth.test` for Slack, `GET /v1/account` for Stripe. Dead keys are
   dropped. Live ones come back with who they belong to.
4. **What can it reach?** For live keys, a few more read-only calls map the
   real access — the IAM policies on an AWS key, the scopes and private repos
   behind a GitHub token, the npm packages a token can publish — and severity
   is set from that, not from the key type.

What you're left with is split into two groups: **verified** (the provider
confirmed it works, with a command to reproduce it) and **likely** (no provider
check exists, such as a database password or a private key, but it passed
every filter and carries a confidence score with the reasons behind it).

## Why you'd use it

- **Verifies as it finds.** A dead key is not a finding, so it never reaches
  your screen.
- **Knows what's public by design.** Referrer-locked Google keys, search-only
  Algolia keys and Supabase `anon` keys are recognised and dropped instead of
  being reported as leaks.
- **Sees the whole app, not just the entry script.** Lazily loaded chunks are
  pulled from Next.js build manifests, webpack runtime maps and Vite import
  lists. On a typical single-page app that's several times more code than the
  `<script>` tags reference — and it's where the admin routes live.
- **Reads source maps**, including ones the site deployed but never referenced,
  so findings point at `src/config/billing.ts:14` instead of column 90,000 of a
  minified bundle.
- **Sees through hiding.** Keys split into concatenated strings, base64 or hex
  blobs, `\x` escapes, `String.fromCharCode` arrays and Kubernetes Secret
  manifests are decoded before scanning.
- **Looks back in time.** `-wayback` scans archived versions of the target's
  JavaScript. Keys removed from the site last year are often still archived,
  and still valid.
- **Digs through git history.** Secrets "deleted" in a later commit are still
  in the repository, and still found.
- **Tests keys for the site's own APIs.** Most keys in web bundles belong to
  the target's API, not a known vendor. When a key sits next to an API host
  (API Gateway, APIM, Cloud Run, `api.*`, or the site itself), the API is asked
  the same question with no key, a made-up key and the real key. Only a real
  key that gets a different answer from both is reported as verified.
- **Report-ready.** Every verified finding comes with a command that
  reproduces the check and the provider's response; `-md` writes it all up as
  a Markdown report.
- **Built for monitoring.** `-state` remembers what was already reported, so a
  scheduled scan only tells you what's new.
- **Shows its working.** Every finding says why it was kept; `-show-dropped`
  lists everything that was thrown away and why.
- **Single binary**, no runtime dependencies.

## Install

```bash
go install github.com/CypherNova1337/SecretSniffer/cmd/secretsniffer@latest
```

Or from a checkout:

```bash
git clone https://github.com/CypherNova1337/SecretSniffer
cd SecretSniffer
go build -o secretsniffer ./cmd/secretsniffer
```

Needs Go 1.22 or newer. Git history scanning needs `git` on your `PATH`.

## Usage

Point it at a site:

```bash
secretsniffer https://example.com
```

It fetches the page, follows its scripts (and the scripts those scripts load),
pulls source maps, scans everything, verifies what it finds and prints the
results.

**Pipe in URLs from your recon**

```bash
cat js-urls.txt | secretsniffer
katana -u https://example.com -em js -silent | secretsniffer
```

**Scan files or a directory**

```bash
secretsniffer ./downloaded-js/ ./decompiled-apk/
```

**Scan a repository's entire history**

```bash
secretsniffer -git https://github.com/org/repo
secretsniffer -git ./local-checkout
```

**Authenticated pages, through Burp**

```bash
secretsniffer https://app.example.com/dashboard \
  -H "Cookie: session=..." -proxy http://127.0.0.1:8080
```

The proxy and headers apply to fetching the target only. Verification calls go
straight to the providers.

**Include archived JavaScript**

```bash
secretsniffer https://example.com -wayback
```

**Write a report for a submission**

```bash
secretsniffer https://example.com -md findings.md
```

**Monitor a target on a schedule**

```bash
secretsniffer -l scope.txt -wayback -state target.state -md new-findings.md
```

Run the same command daily; each run reports only credentials that weren't
reported before (or that went from likely to verified). The state file holds
fingerprints, not secrets.

**Stay passive**

```bash
secretsniffer https://example.com -no-verify
```

Nothing is sent to any provider. Findings are scored offline instead.

**See what was thrown away**

```bash
secretsniffer https://example.com -show-dropped
```

**Save for later or feed another tool**

```bash
secretsniffer -l targets.txt -o findings.jsonl
secretsniffer -l targets.txt -json | jq 'select(.status=="verified")'
```

## Options

| Flag | Default | What it does |
|---|---|---|
| `target ...` | stdin | URLs, bare domains, files or directories |
| `-l` | — | File of targets, one per line (`#` comments allowed) |
| `-git` | — | Scan a repository's full history; path or clone URL, repeatable |
| `-no-verify` | off | Don't contact providers; offline scoring only |
| `-no-enrich` | off | Confirm keys are live, but skip the calls that map their access |
| `-wayback` | off | Also scan archived JS, source maps and JSON from the Wayback Machine |
| `-wayback-limit` | `500` | Most archived file versions to fetch per host |
| `-state` | — | Remember findings in this file; later runs show only new ones |
| `-md` | — | Write a Markdown report of verified and likely findings, with evidence |
| `-show-dropped` | off | Also print discarded findings and the reason for each |
| `-min-score` | `50` | Lowest score an unverified finding needs to be shown |
| `-json` | off | Print findings as JSON lines |
| `-o` | — | Also write findings to a file as JSON lines |
| `-H` | — | Header for fetching targets, e.g. `"Cookie: a=b"`; repeatable |
| `-proxy` | — | Proxy for fetching targets (not used for verification) |
| `-k` | off | Skip TLS verification when fetching targets |
| `-t` | `20` | Concurrent fetches |
| `-vt` | `10` | Concurrent verifications |
| `-rl` | `0` | Max fetches per second (`0` = unlimited) |
| `-timeout` | `15` | Request timeout, in seconds |
| `-depth` | `2` | Levels of script references to follow from a page |
| `-third-party` | off | Also scan scripts from public CDNs and analytics vendors |
| `-no-maps` | off | Don't fetch or probe source maps |
| `-max-size` | `15` | Skip files and responses larger than this many MB |
| `-redact` | off | Mask secrets in output |
| `-q` | off | Findings only — no banner or summary |
| `-v` | off | Log fetch errors and skipped files |
| `-no-color` | off | Disable coloured output |
| `-version` | — | Print version and exit |

## Reading the results

```
[VERIFIED] CRITICAL  AWS access key
  secret    AKIA................
  secret_key wJal....................................
  identity  arn:aws:iam::123456789012:user/deploy-bot
  access    IAM policies: AdministratorAccess
  access    can list 14 S3 buckets: prod-backups, customer-uploads, logs, ...
  repro     AWS_ACCESS_KEY_ID='AKIA...' AWS_SECRET_ACCESS_KEY='wJal...' aws sts get-caller-identity
  proof     HTTP 200 at 2026-11-09T10:42:17Z: <GetCallerIdentityResponse ...
  account id 123456789012
  where     https://example.com/static/js/812.4f2a91.chunk.js:1
  why       paired with a secret access key

[LIKELY 90] CRITICAL  Private key
  secret    -----BEGIN RSA PRIVATE KEY----- MIIEpQIBAAKCAQEA3iPTzDmz+h89cWpbXJ1U/g/... (1704 chars, full value in -json/-o)
  key type  RSA 2048-bit private key
  where     https://example.com/static/js/main.4f2a.js.map -> webpack://app/src/lib/sign.ts:7
  why       parses as a real, unencrypted RSA 2048-bit private key; no provider check exists for this type

[LIKELY 85] CRITICAL  Database connection string
  secret    postgres://billing:MnWw...@db-prod.internal.example.io:5432/billing
  host      db-prod.internal.example.io
  user      billing
  where     https://example.com/static/js/main.4f2a.js.map -> webpack://app/src/db.ts:3
  why       strong password; no provider check exists for this type

done: scanned 41 sources, 312 raw matches, 27 unique
      1 verified, 2 likely, 24 dropped (dead (rejected by provider) 9, placeholder/example 8, not a secret 4, real but harmless 3)
```

**Verified** means the provider accepted the credential at scan time.
`identity` shows who it belongs to, `access` what it can reach, and `repro`
is a command anyone can run to confirm it. That's the finding.

**Likely** means no provider check exists for that kind of secret, or the check
was inconclusive (a timeout, a rate limit). The score is out of 100 and the
`why` line explains it. Things that raise it: a private key that parses, a
paired secret, high entropy, a strongly named variable. Things that lower it:
a test or example path, example wording nearby, a database URL pointing at
`localhost`, an archived copy rather than the live site.

Findings marked `hidden by` were obscured on purpose — split, encoded or
escaped — which is itself worth mentioning in a report.

The summary line shows how much noise was removed and why.

## What gets checked

Verified with a read-only call:

| Provider | Check |
|---|---|
| AWS access key + secret | STS `GetCallerIdentity`; access: root check, IAM policies, S3 buckets |
| Google Cloud service account | Signs a token request with the key; access: visible projects |
| Google API key | Lists Gemini models (free) and reads the reason Google gives |
| Azure storage key | Lists containers |
| Azure AD (Entra ID) client secret, with tenant + client ID | Client-credentials token; access: Graph app permissions |
| GitHub classic / fine-grained tokens | `GET /user`; access: scopes, private repos, orgs |
| GitLab personal tokens | `GET /api/v4/user` (gitlab.com or the instance found nearby); access: admin flag, scopes |
| npm tokens | `whoami`; access: packages it can publish |
| Stripe secret / restricted keys | `GET /v1/account`; access: business, charges/payouts enabled |
| Square | `GET /v2/locations` |
| Shopify (with store domain) | `GET /admin/api/.../shop.json`; access: granted scopes |
| Slack tokens | `auth.test`; access: scopes |
| Slack incoming webhooks | Empty message, rejected before anything is posted |
| Discord webhooks / bot tokens | `GET` webhook metadata / `GET /users/@me` |
| Telegram bot tokens | `getMe` |
| Twilio SID + auth token | `GET /Accounts/{sid}` |
| SendGrid, Mailgun, Mailchimp | Scopes / domains / account root |
| OpenAI, Anthropic, Hugging Face | List models / whoami |
| Algolia (with app ID) | Reads the key's ACL — search-only keys are dropped |
| Supabase `service_role` JWT | `GET /rest/v1/` |
| Keys for the target's own API (`x-api-key` and similar, hardcoded `Basic` auth) next to an API host | Three-way GET comparison on the API root and safe endpoint paths found next to the key |
| Firebase Realtime Database | Unauthenticated shallow read — reported only if the rules allow public reads |
| Okta (with org domain), HashiCorp Vault (with address), Atlassian (with site + email), Bitbucket (with username), JFrog (with host), Grafana (with instance), Zendesk (with subdomain + email), Supabase secret keys (with project) | Identity endpoint on the instance found nearby |
| Sentry | Organisation endpoint (region and org decoded from the token) |
| Datadog | `validate` on every Datadog site |
| New Relic | GraphQL `actor` query, US and EU |
| Razorpay (key ID + secret) | List one payment |
| DigitalOcean, Heroku, Mapbox, Facebook, Dropbox, Notion, Linear, Postman, Cloudinary, Terraform Cloud, Doppler, Pulumi, Netlify, Render, Cloudflare, CircleCI, Buildkite, PagerDuty, Airtable, Asana, Figma, Typeform, Contentful, HubSpot, Brevo, Intercom, Shippo, Groq, Replicate, xAI, ElevenLabs, Pinecone, LangSmith | Account / identity endpoint |

Detected and scored, but not verified (no safe check exists): private keys
(RSA, EC, Ed25519, OpenSSH, PGP), PyPI tokens (scope decoded from the token),
database connection strings, credentials in URLs, hardcoded `Basic` auth
headers with no API nearby, Square and Shopify shared secrets, Stripe webhook secrets, Grafana
Cloud tokens (org decoded), other JWTs, and generic `secret = "..."`
assignments.

Deliberately not reported, because they're meant to be public: Stripe
publishable keys, Mapbox public tokens, Firebase web config, Sentry DSNs,
reCAPTCHA site keys, Algolia search-only keys and Supabase `anon` keys.

## Good to know

- **Verification uses the credential.** Every check is read-only and creates,
  changes or sends nothing, but it is still an authenticated request made with
  somebody else's key. Some programmes have rules about that. `-no-verify` if
  yours does.
- **Nothing billable is sent.** Where a check could cost the key owner money
  (Google APIs), a free endpoint is used instead. A Google key that's real and
  unrestricted but has no free API enabled is shown as likely, not verified.
- **Own-API keys are tested against the target.** Unlike vendor checks, this
  talks to the program's infrastructure: GET only, at most the API root plus
  three endpoint paths found next to the key, spaced out, and never a path
  whose name suggests an action (export, delete, send, create, upload, reset,
  pay, login and the like). Three requests per path: no key, a made-up key of
  the same shape, the real key. If the API answers all three the same, the
  result is inconclusive — never "verified". `-no-verify` turns it off along
  with every other check. These requests don't go through `-proxy`.
- **The API host comes from the code.** API gateway and `api.*` URLs near the
  key are used first; if the bundle only calls relative paths, the site that
  served it is the API. The host, paths and header are shown on the finding so
  you can test by hand too.
- **Access mapping makes a few more calls.** All read-only (listing policies,
  scopes, buckets, orgs), but more than one request per key. `-no-enrich` to
  keep it to the single confirming call.
- **A 401 from one host isn't proof everywhere.** A GitLab token is checked
  against gitlab.com unless a self-hosted instance is referenced nearby, and a
  Shopify token can only be checked if its store domain appears near it.
- **Azure keys are never dropped on a 403.** A wrong key and a rejected request
  look the same, so it stays as likely rather than risk throwing away a real
  key.
- **Library scripts are skipped by default.** Code from public CDNs and
  analytics vendors is the same on every site. `-third-party` to include it.
- **Bundled `node_modules` sources inside source maps are skipped** for the same
  reason.
- **`-wayback` is slow on purpose.** The archive throttles hard, so fetching
  runs with a few workers and backs off. Cap it with `-wayback-limit`.
- **An archived key isn't necessarily still live.** Verification decides; an
  unverified archived match scores a little lower than one on the live site.
- **The state file never contains secrets** — only SHA-256 fingerprints and
  dates. Deleting it makes the next run report everything again.
- **Git scanning reads every added line on every branch.** On a large repository
  that's a lot of history; it still runs in one pass.

## Authorised use

Run it against sites, files and repositories you own or that are in scope for
an engagement or bounty programme you're part of. Verifying a credential is
using it; only do that where you're permitted to.

## License

MIT — see [LICENSE](LICENSE).
