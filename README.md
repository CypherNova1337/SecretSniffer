# SecretSniffer

Finds secrets in JavaScript, files and git history — then proves which ones are real.

![license](https://img.shields.io/badge/license-MIT-blue?style=flat-square)
![go](https://img.shields.io/badge/go-1.22%2B-00ADD8?style=flat-square)
![release](https://img.shields.io/badge/release-v1.0.0-brightgreen?style=flat-square)

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

What you're left with is split into two groups: **verified** (the provider
confirmed it works) and **likely** (no provider check exists, such as a database
password or a private key, but it passed every filter and carries a confidence
score with the reasons behind it).

## Why you'd use it

- **Verifies as it finds.** A dead key is not a finding, so it never reaches
  your screen.
- **Knows what's public by design.** Referrer-locked Google keys, search-only
  Algolia keys and Supabase `anon` keys are recognised and dropped instead of
  being reported as leaks.
- **Reads source maps**, including ones the site deployed but never referenced,
  so findings point at `src/config/billing.ts:14` instead of column 90,000 of a
  minified bundle.
- **Digs through git history.** Secrets "deleted" in a later commit are still
  in the repository, and still found.
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
  account id 123456789012
  where     https://example.com/static/js/main.4f2a.js:1
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

**Verified** means the provider accepted the credential at scan time, and
`identity` shows who it belongs to. That's the finding.

**Likely** means no provider check exists for that kind of secret, or the check
was inconclusive (a timeout, a rate limit). The score is out of 100 and the
`why` line explains it. Things that raise it: a private key that parses, a
paired secret, high entropy, a strongly named variable. Things that lower it:
a test or example path, example wording nearby, a database URL pointing at
`localhost`.

The summary line shows how much noise was removed and why.

## What gets checked

Verified with a read-only call:

| Provider | Check |
|---|---|
| AWS access key + secret | STS `GetCallerIdentity` |
| Google Cloud service account | Signs a token request with the key |
| Google API key | Lists Gemini models (free) and reads the reason Google gives |
| Azure storage key | Lists containers |
| GitHub classic / fine-grained tokens | `GET /user` |
| GitLab personal tokens | `GET /api/v4/user` (gitlab.com or the instance found nearby) |
| npm tokens | `whoami` |
| Stripe secret / restricted keys | `GET /v1/account` |
| Square | `GET /v2/locations` |
| Shopify (with store domain) | `GET /admin/api/.../shop.json` |
| Slack tokens | `auth.test` |
| Slack incoming webhooks | Empty message, rejected before anything is posted |
| Discord webhooks / bot tokens | `GET` webhook metadata / `GET /users/@me` |
| Telegram bot tokens | `getMe` |
| Twilio SID + auth token | `GET /Accounts/{sid}` |
| SendGrid, Mailgun, Mailchimp | Scopes / domains / account root |
| OpenAI, Anthropic, Hugging Face | List models / whoami |
| Algolia (with app ID) | Reads the key's ACL — search-only keys are dropped |
| Supabase `service_role` JWT | `GET /rest/v1/` |
| DigitalOcean, Heroku, Mapbox, Facebook, Dropbox, Notion, Linear, Postman, Cloudinary | Account / identity endpoint |

Detected and scored, but not verified (no safe check exists): private keys
(RSA, EC, Ed25519, OpenSSH, PGP), PyPI tokens (scope decoded from the token),
database connection strings, credentials in URLs, hardcoded `Basic` auth
headers, Square and Shopify shared secrets, other JWTs, and generic
`secret = "..."` assignments.

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
- **Git scanning reads every added line on every branch.** On a large repository
  that's a lot of history; it still runs in one pass.

## Authorised use

Run it against sites, files and repositories you own or that are in scope for
an engagement or bounty programme you're part of. Verifying a credential is
using it; only do that where you're permitted to.

## License

MIT — see [LICENSE](LICENSE).
