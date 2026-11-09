package verify

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var funcs = map[string]Func{
	"aws-access-key":      verifyAWS,
	"gcp-service-account": verifyGCP,
	"azure-storage-key":   verifyAzure,
	"digitalocean-token":  bearerJSON("https://api.digitalocean.com/v2/account", nil, "account.email"),
	"heroku-key": bearerJSON("https://api.heroku.com/account",
		map[string]string{"Accept": "application/vnd.heroku+json; version=3"}, "email"),
	"github-token":        verifyGitHub,
	"github-fine-grained": verifyGitHub,
	"gitlab-token":        verifyGitLab,
	"npm-token":           bearerJSON("https://registry.npmjs.org/-/whoami", nil, "username"),
	"stripe-key":          verifyStripe,
	"square-token":        bearerJSON("https://connect.squareup.com/v2/locations", nil, "locations.0.business_name"),
	"shopify-token":       verifyShopify,
	"slack-token":         verifySlack,
	"slack-webhook":       verifySlackWebhook,
	"discord-webhook":     verifyDiscordWebhook,
	"discord-bot-token":   verifyDiscordBot,
	"telegram-bot-token":  verifyTelegram,
	"twilio-credentials":  verifyTwilio,
	"sendgrid-key":        verifySendGrid,
	"mailgun-key":         verifyMailgun,
	"mailchimp-key":       verifyMailchimp,
	"openai-key":          verifyOpenAI,
	"anthropic-key":       verifyAnthropic,
	"huggingface-token":   bearerJSON("https://huggingface.co/api/whoami-v2", nil, "name"),
	"google-api-key":      verifyGoogleKey,
	"algolia-key":         verifyAlgolia,
	"mapbox-secret-token": verifyMapbox,
	"facebook-token":      verifyFacebook,
	"dropbox-token":       verifyDropbox,
	"notion-token": bearerJSON("https://api.notion.com/v1/users/me",
		map[string]string{"Notion-Version": "2022-06-28"}, "name"),
	"linear-key":     verifyLinear,
	"postman-key":    verifyPostman,
	"cloudinary-url": verifyCloudinary,
	"jwt":            verifySupabase,
}

// ------------------------------------------------------------ helpers

// jsonPath pulls a dotted path ("a.b.0.c") out of a JSON body as a string.
func jsonPath(body []byte, path string) string {
	var v any
	if json.Unmarshal(body, &v) != nil {
		return ""
	}
	for _, p := range strings.Split(path, ".") {
		switch t := v.(type) {
		case map[string]any:
			v = t[p]
		case []any:
			i := 0
			for _, c := range p {
				i = i*10 + int(c-'0')
			}
			if i >= len(t) {
				return ""
			}
			v = t[i]
		default:
			return ""
		}
	}
	switch t := v.(type) {
	case string:
		return t
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case bool:
		if t {
			return "true"
		}
		return "false"
	}
	return ""
}

func identity(path string) func(*Response) Result {
	return func(r *Response) Result {
		return Result{State: Live, Identity: jsonPath(r.Body, path)}
	}
}

func bearerJSON(endpoint string, extra map[string]string, idPath string) Func {
	return func(ctx context.Context, h *HTTP, t Target) Result {
		hdr := map[string]string{"Authorization": "Bearer " + t.Secret}
		for k, v := range extra {
			hdr[k] = v
		}
		r, err := h.Do(ctx, "GET", endpoint, hdr, "")
		if err != nil {
			return unknownErr(err)
		}
		if r.Status == 403 {
			return Result{State: Live, Note: "accepted, but lacks permission for the identity call"}
		}
		return byStatus(r, identity(idPath))
	}
}

func basic(user, pass string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
}

// ---------------------------------------------------------------- AWS

var arnRe = regexp.MustCompile(`<Arn>([^<]+)</Arn>`)

func verifyAWS(ctx context.Context, h *HTTP, t Target) Result {
	secret := t.Parts["secret_key"]
	if secret == "" {
		return Result{State: Skip, Note: "no secret access key to pair with"}
	}
	token := t.Parts["session_token"]
	if strings.HasPrefix(t.Secret, "ASIA") && token == "" {
		return Result{State: Skip, Note: "temporary key needs its session token"}
	}
	const body = "Action=GetCallerIdentity&Version=2011-06-15"
	now := time.Now()
	hdrs := map[string]string{
		"content-type": "application/x-www-form-urlencoded; charset=utf-8",
		"host":         "sts.amazonaws.com",
		"x-amz-date":   now.UTC().Format("20060102T150405Z"),
	}
	if token != "" {
		hdrs["x-amz-security-token"] = token
	}
	auth := sigV4("POST", "/", "", hdrs, body, t.Secret, secret, "us-east-1", "sts", now)
	send := map[string]string{"Authorization": auth}
	for k, v := range hdrs {
		if k != "host" {
			send[k] = v
		}
	}
	r, err := h.Do(ctx, "POST", "https://sts.amazonaws.com/", send, body)
	if err != nil {
		return unknownErr(err)
	}
	b := string(r.Body)
	switch {
	case r.Status == 200:
		id := ""
		if m := arnRe.FindStringSubmatch(b); m != nil {
			id = m[1]
		}
		return Result{State: Live, Identity: id, raw: r}
	case strings.Contains(b, "InvalidClientTokenId"):
		return Result{State: Dead, Note: "access key ID does not exist or was deleted"}
	case strings.Contains(b, "SignatureDoesNotMatch"):
		return Result{State: Dead, Note: "secret key does not belong to this key ID"}
	case strings.Contains(b, "ExpiredToken"):
		return Result{State: Dead, Note: "temporary credentials expired"}
	}
	return byStatus(r, nil)
}

// ---------------------------------------------------------- Google

func verifyGCP(ctx context.Context, h *HTTP, t Target) Result {
	email, key := t.Parts["client_email"], strings.ReplaceAll(t.Parts["private_key"], `\n`, "\n")
	if email == "" || key == "" {
		return Result{State: Skip, Note: "incomplete service account JSON"}
	}
	const aud = "https://oauth2.googleapis.com/token"
	jwt, err := googleAssertion(email, key, aud, time.Now())
	if err != nil {
		return Result{State: Skip, Note: "could not sign with the key: " + err.Error()}
	}
	form := url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"}, "assertion": {jwt}}
	r, err := h.Do(ctx, "POST", aud, map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, form.Encode())
	if err != nil {
		return unknownErr(err)
	}
	if r.Status == 200 {
		return Result{State: Live, Identity: email, raw: r}
	}
	if r.Status == 400 || r.Status == 401 {
		desc := jsonPath(r.Body, "error_description")
		if desc == "" {
			desc = jsonPath(r.Body, "error")
		}
		return Result{State: Dead, Note: "Google refused the key: " + desc}
	}
	return byStatus(r, nil)
}

// googleErrorReason pulls error.details[].reason (e.g. API_KEY_INVALID) out
// of a Google API error body.
func googleErrorReason(body []byte) (reason, msg string) {
	var v struct {
		Error struct {
			Message string `json:"message"`
			Status  string `json:"status"`
			Details []struct {
				Reason string `json:"reason"`
			} `json:"details"`
		} `json:"error"`
	}
	_ = json.Unmarshal(body, &v)
	for _, d := range v.Error.Details {
		if d.Reason != "" {
			return d.Reason, v.Error.Message
		}
	}
	return v.Error.Status, v.Error.Message
}

func verifyGoogleKey(ctx context.Context, h *HTTP, t Target) Result {
	// Listing Gemini models is free, and Google's front end answers with a
	// precise reason: invalid key, key locked to referrers/IPs/APIs, or a real
	// key whose project simply hasn't enabled the API. No billable call is
	// ever made.
	r, err := h.Do(ctx, "GET", "https://generativelanguage.googleapis.com/v1beta/models?pageSize=1&key="+url.QueryEscape(t.Secret), nil, "")
	if err != nil {
		return unknownErr(err)
	}
	if r.Status == 200 {
		return Result{State: Live, Severity: "high",
			Identity: "Gemini API enabled - anyone with this key can run paid AI requests on the owner's bill"}
	}
	reason, msg := googleErrorReason(r.Body)
	switch reason {
	case "API_KEY_INVALID", "API_KEY_EXPIRED":
		return Result{State: Dead, Note: strings.ToLower(strings.TrimPrefix(reason, "API_KEY_"))}
	case "API_KEY_HTTP_REFERRER_BLOCKED", "API_KEY_IP_ADDRESS_BLOCKED",
		"API_KEY_ANDROID_APP_BLOCKED", "API_KEY_IOS_APP_BLOCKED":
		return Result{State: Harmless, Note: "real key, locked to specific referrers/IPs/apps"}
	case "API_KEY_SERVICE_BLOCKED":
		return Result{State: Harmless, Note: "real key, restricted to an allow-list of APIs"}
	case "SERVICE_DISABLED", "ACCESS_TOKEN_SCOPE_INSUFFICIENT", "PERMISSION_DENIED":
		return Result{State: Unknown, Boost: 20,
			Note: "real key with no API restrictions; which paid APIs it reaches wasn't tested (that would bill the owner)"}
	}
	if r.Status == 400 && strings.Contains(strings.ToLower(msg), "api key not valid") {
		return Result{State: Dead, Note: "invalid"}
	}
	return byStatus(r, nil)
}

// ----------------------------------------------------------- Azure

func verifyAzure(ctx context.Context, h *HTTP, t Target) Result {
	acct := t.Parts["account"]
	date := time.Now().UTC().Format(time.RFC1123)
	date = strings.Replace(date, "UTC", "GMT", 1)
	const ver = "2021-08-06"
	auth, err := azureSharedKey(acct, t.Secret, date, ver, "/"+acct+"/\ncomp:list")
	if err != nil {
		return Result{State: Skip, Note: "key is not base64"}
	}
	r, err := h.Do(ctx, "GET", "https://"+acct+".blob.core.windows.net/?comp=list", map[string]string{
		"Authorization": auth, "x-ms-date": date, "x-ms-version": ver, "Accept": "application/xml",
	}, "")
	if err != nil {
		if noSuchHost(err) {
			return Result{State: Dead, Note: "storage account no longer exists"}
		}
		return unknownErr(err)
	}
	if r.Status == 200 {
		return Result{State: Live, Identity: "storage account " + acct + " (can list containers)"}
	}
	if r.Status == 403 {
		// Wrong key and a rejected signature look identical; keep it rather
		// than risk throwing away a real key.
		return Result{State: Unknown, Note: "authentication failed - key rotated, or the request was rejected"}
	}
	return byStatus(r, nil)
}

// ------------------------------------------------------- source code

func verifyGitHub(ctx context.Context, h *HTTP, t Target) Result {
	r, err := h.Do(ctx, "GET", "https://api.github.com/user", map[string]string{
		"Authorization": "token " + t.Secret, "Accept": "application/vnd.github+json",
	}, "")
	if err != nil {
		return unknownErr(err)
	}
	switch {
	case r.Status == 200:
		id := "user " + jsonPath(r.Body, "login")
		return Result{State: Live, Identity: id, raw: r}
	case r.Status == 403 && r.Header.Get("X-RateLimit-Remaining") == "0":
		return Result{State: Unknown, Note: "GitHub rate limit hit"}
	case r.Status == 403:
		// App installation tokens can't read /user but are accepted.
		return Result{State: Live, Identity: "app/installation token", Note: "accepted, cannot read /user"}
	}
	return byStatus(r, nil)
}

func verifyGitLab(ctx context.Context, h *HTTP, t Target) Result {
	if !strings.HasPrefix(t.Secret, "glpat-") {
		return Result{State: Skip, Note: "only personal/project access tokens can be checked without side effects"}
	}
	host := t.Parts["host"]
	if host == "" {
		host = "gitlab.com"
	}
	r, err := h.Do(ctx, "GET", "https://"+host+"/api/v4/user", map[string]string{"PRIVATE-TOKEN": t.Secret}, "")
	if err != nil {
		return unknownErr(err)
	}
	if r.Status == 403 {
		return Result{State: Live, Identity: host, Note: "accepted, but lacks read_user scope"}
	}
	return byStatus(r, func(r *Response) Result {
		return Result{State: Live, Identity: jsonPath(r.Body, "username") + " @ " + host}
	})
}

// --------------------------------------------------------- payments

func verifyStripe(ctx context.Context, h *HTTP, t Target) Result {
	r, err := h.Do(ctx, "GET", "https://api.stripe.com/v1/account", map[string]string{"Authorization": basic(t.Secret, "")}, "")
	if err != nil {
		return unknownErr(err)
	}
	if r.Status == 403 {
		return Result{State: Live, Note: "restricted key without account read permission"}
	}
	return byStatus(r, func(r *Response) Result {
		id := jsonPath(r.Body, "id")
		if e := jsonPath(r.Body, "email"); e != "" {
			id += " (" + e + ")"
		}
		return Result{State: Live, Identity: id}
	})
}

func verifyShopify(ctx context.Context, h *HTTP, t Target) Result {
	shop := t.Parts["shop"]
	if shop == "" {
		return Result{State: Skip, Note: "no *.myshopify.com domain found nearby to check against"}
	}
	r, err := h.Do(ctx, "GET", "https://"+shop+"/admin/api/2024-10/shop.json", map[string]string{"X-Shopify-Access-Token": t.Secret}, "")
	if err != nil {
		if noSuchHost(err) {
			return Result{State: Dead, Note: "shop no longer exists"}
		}
		return unknownErr(err)
	}
	if r.Status == 403 {
		return Result{State: Live, Identity: shop, Note: "accepted, lacks read access to shop details"}
	}
	return byStatus(r, func(r *Response) Result {
		return Result{State: Live, Identity: jsonPath(r.Body, "shop.name") + " (" + shop + ")"}
	})
}

// ---------------------------------------------------- communication

func verifySlack(ctx context.Context, h *HTTP, t Target) Result {
	r, err := h.Do(ctx, "POST", "https://slack.com/api/auth.test", map[string]string{
		"Authorization": "Bearer " + t.Secret, "Content-Type": "application/x-www-form-urlencoded",
	}, "")
	if err != nil {
		return unknownErr(err)
	}
	if jsonPath(r.Body, "ok") == "true" {
		return Result{State: Live, Identity: jsonPath(r.Body, "user") + " @ " + jsonPath(r.Body, "team"), raw: r}
	}
	switch e := jsonPath(r.Body, "error"); e {
	case "invalid_auth", "token_revoked", "account_inactive", "not_authed", "token_expired", "invalid_token":
		return Result{State: Dead, Note: e}
	case "":
		return byStatus(r, nil)
	default:
		return Result{State: Unknown, Note: e}
	}
}

func verifySlackWebhook(ctx context.Context, h *HTTP, t Target) Result {
	if !strings.Contains(t.Secret, "/services/") {
		return Result{State: Skip, Note: "workflow webhooks can't be checked without triggering the workflow"}
	}
	// An empty message is rejected before anything is posted; the error tells
	// us whether the webhook exists.
	r, err := h.Do(ctx, "POST", t.Secret, map[string]string{"Content-Type": "application/json"}, `{"text":""}`)
	if err != nil {
		return unknownErr(err)
	}
	b := strings.TrimSpace(string(r.Body))
	switch {
	case r.Status == 400 && (strings.Contains(b, "no_text") || strings.Contains(b, "missing_text")):
		return Result{State: Live, Identity: "can post to a channel"}
	case strings.Contains(b, "invalid_token") || strings.Contains(b, "no_service") ||
		strings.Contains(b, "no_team") || strings.Contains(b, "channel_is_archived") ||
		strings.Contains(b, "channel_not_found") || r.Status == 404 || r.Status == 410 || r.Status == 403:
		return Result{State: Dead, Note: "webhook disabled or removed (" + b + ")"}
	}
	return byStatus(r, nil)
}

func verifyDiscordWebhook(ctx context.Context, h *HTTP, t Target) Result {
	r, err := h.Do(ctx, "GET", t.Secret, nil, "") // GET returns metadata, posts nothing
	if err != nil {
		return unknownErr(err)
	}
	if r.Status == 404 {
		return Result{State: Dead, Note: "webhook deleted"}
	}
	return byStatus(r, func(r *Response) Result {
		return Result{State: Live, Identity: "webhook \"" + jsonPath(r.Body, "name") + "\" in guild " + jsonPath(r.Body, "guild_id")}
	})
}

func verifyDiscordBot(ctx context.Context, h *HTTP, t Target) Result {
	r, err := h.Do(ctx, "GET", "https://discord.com/api/v10/users/@me", map[string]string{"Authorization": "Bot " + t.Secret}, "")
	if err != nil {
		return unknownErr(err)
	}
	return byStatus(r, identity("username"))
}

func verifyTelegram(ctx context.Context, h *HTTP, t Target) Result {
	r, err := h.Do(ctx, "GET", "https://api.telegram.org/bot"+t.Secret+"/getMe", nil, "")
	if err != nil {
		return unknownErr(err)
	}
	if r.Status == 404 {
		return Result{State: Dead, Note: "token rejected"}
	}
	return byStatus(r, func(r *Response) Result {
		return Result{State: Live, Identity: "@" + jsonPath(r.Body, "result.username")}
	})
}

func verifyTwilio(ctx context.Context, h *HTTP, t Target) Result {
	tok := t.Parts["auth_token"]
	if tok == "" {
		return Result{State: Skip, Note: "no auth token"}
	}
	r, err := h.Do(ctx, "GET", "https://api.twilio.com/2010-04-01/Accounts/"+t.Secret+".json",
		map[string]string{"Authorization": basic(t.Secret, tok)}, "")
	if err != nil {
		return unknownErr(err)
	}
	return byStatus(r, func(r *Response) Result {
		return Result{State: Live, Identity: jsonPath(r.Body, "friendly_name") + " (" + jsonPath(r.Body, "status") + ")"}
	})
}

func verifySendGrid(ctx context.Context, h *HTTP, t Target) Result {
	r, err := h.Do(ctx, "GET", "https://api.sendgrid.com/v3/scopes", map[string]string{"Authorization": "Bearer " + t.Secret}, "")
	if err != nil {
		return unknownErr(err)
	}
	if r.Status == 403 {
		return Result{State: Live, Note: "accepted, restricted scopes"}
	}
	return byStatus(r, func(r *Response) Result {
		var v struct{ Scopes []string }
		_ = json.Unmarshal(r.Body, &v)
		id := ""
		for _, s := range v.Scopes {
			if s == "mail.send" {
				id = "can send email as the account"
			}
		}
		if id == "" {
			id = strconv.Itoa(len(v.Scopes)) + " scopes"
		}
		return Result{State: Live, Identity: id}
	})
}

func verifyMailgun(ctx context.Context, h *HTTP, t Target) Result {
	var last *Response
	for _, host := range []string{"api.mailgun.net", "api.eu.mailgun.net"} {
		r, err := h.Do(ctx, "GET", "https://"+host+"/v3/domains", map[string]string{"Authorization": basic("api", t.Secret)}, "")
		if err != nil {
			return unknownErr(err)
		}
		if r.Status == 200 {
			return Result{State: Live, Identity: jsonPath(r.Body, "items.0.name")}
		}
		if r.Status == 403 {
			return Result{State: Live, Note: "accepted, restricted"}
		}
		last = r
		if r.Status != 401 {
			break
		}
	}
	return byStatus(last, nil)
}

var mailchimpDC = regexp.MustCompile(`-(us[0-9]{1,2})$`)

func verifyMailchimp(ctx context.Context, h *HTTP, t Target) Result {
	m := mailchimpDC.FindStringSubmatch(t.Secret)
	if m == nil {
		return Result{State: Skip}
	}
	r, err := h.Do(ctx, "GET", "https://"+m[1]+".api.mailchimp.com/3.0/", map[string]string{"Authorization": basic("anystring", t.Secret)}, "")
	if err != nil {
		return unknownErr(err)
	}
	return byStatus(r, identity("account_name"))
}

// ---------------------------------------------------------------- AI

func verifyOpenAI(ctx context.Context, h *HTTP, t Target) Result {
	r, err := h.Do(ctx, "GET", "https://api.openai.com/v1/models", map[string]string{"Authorization": "Bearer " + t.Secret}, "")
	if err != nil {
		return unknownErr(err)
	}
	switch r.Status {
	case 429:
		if strings.Contains(string(r.Body), "insufficient_quota") {
			return Result{State: Live, Note: "valid, but the account has no quota", Severity: "low"}
		}
	case 403:
		return Result{State: Live, Note: "accepted, lacks permission to list models"}
	}
	return byStatus(r, nil)
}

func verifyAnthropic(ctx context.Context, h *HTTP, t Target) Result {
	endpoint := "https://api.anthropic.com/v1/models?limit=1"
	if strings.HasPrefix(t.Secret, "sk-ant-admin") {
		endpoint = "https://api.anthropic.com/v1/organizations/users?limit=1"
	}
	r, err := h.Do(ctx, "GET", endpoint, map[string]string{"x-api-key": t.Secret, "anthropic-version": "2023-06-01"}, "")
	if err != nil {
		return unknownErr(err)
	}
	if r.Status == 403 {
		return Result{State: Live, Note: "accepted, lacks permission for this call"}
	}
	return byStatus(r, nil)
}

// -------------------------------------------------------- SaaS / misc

var algoliaWrite = []string{"addObject", "deleteObject", "deleteIndex", "editSettings", "logs", "seeUnretrievableAttributes", "analytics", "usage", "inference"}

func verifyAlgolia(ctx context.Context, h *HTTP, t Target) Result {
	app := t.Parts["app_id"]
	if app == "" {
		return Result{State: Skip, Note: "no application ID"}
	}
	hdr := map[string]string{"X-Algolia-Application-Id": app, "X-Algolia-API-Key": t.Secret}
	base := "https://" + strings.ToLower(app) + "-dsn.algolia.net"
	r, err := h.Do(ctx, "GET", base+"/1/keys/"+t.Secret, hdr, "")
	if err != nil {
		if noSuchHost(err) {
			return Result{State: Dead, Note: "application ID does not exist"}
		}
		return unknownErr(err)
	}
	if r.Status == 200 {
		var v struct {
			ACL []string `json:"acl"`
		}
		_ = json.Unmarshal(r.Body, &v)
		var risky []string
		for _, a := range v.ACL {
			for _, w := range algoliaWrite {
				if a == w {
					risky = append(risky, a)
				}
			}
		}
		if len(risky) == 0 {
			return Result{State: Harmless, Note: "search-only key (acl: " + strings.Join(v.ACL, ",") + ") - public by design"}
		}
		return Result{State: Live, Identity: "app " + app + ", acl: " + strings.Join(v.ACL, ",")}
	}
	// The admin key is not listed under /1/keys/{key}; it is the only key
	// that can list all keys.
	r2, err := h.Do(ctx, "GET", base+"/1/keys", hdr, "")
	if err != nil {
		return unknownErr(err)
	}
	if r2.Status == 200 {
		return Result{State: Live, Identity: "admin API key for app " + app, Severity: "critical"}
	}
	if strings.Contains(string(r2.Body), "Invalid Application-ID or API key") || strings.Contains(string(r.Body), "Invalid Application-ID or API key") {
		return Result{State: Dead, Note: "invalid application ID or key"}
	}
	return byStatus(r2, nil)
}

func verifyMapbox(ctx context.Context, h *HTTP, t Target) Result {
	r, err := h.Do(ctx, "GET", "https://api.mapbox.com/tokens/v2?access_token="+url.QueryEscape(t.Secret), nil, "")
	if err != nil {
		return unknownErr(err)
	}
	switch jsonPath(r.Body, "code") {
	case "TokenValid":
		return Result{State: Live, Identity: jsonPath(r.Body, "token.user")}
	case "TokenInvalid", "TokenExpired", "TokenRevoked", "TokenMalformed":
		return Result{State: Dead, Note: jsonPath(r.Body, "code")}
	}
	return byStatus(r, nil)
}

func verifyFacebook(ctx context.Context, h *HTTP, t Target) Result {
	r, err := h.Do(ctx, "GET", "https://graph.facebook.com/me?access_token="+url.QueryEscape(t.Secret), nil, "")
	if err != nil {
		return unknownErr(err)
	}
	if r.Status == 400 && jsonPath(r.Body, "error.code") == "190" {
		return Result{State: Dead, Note: jsonPath(r.Body, "error.message")}
	}
	return byStatus(r, func(r *Response) Result {
		return Result{State: Live, Identity: jsonPath(r.Body, "name") + " (" + jsonPath(r.Body, "id") + ")"}
	})
}

func verifyDropbox(ctx context.Context, h *HTTP, t Target) Result {
	r, err := h.Do(ctx, "POST", "https://api.dropboxapi.com/2/users/get_current_account", map[string]string{
		"Authorization": "Bearer " + t.Secret, "Content-Type": "application/json",
	}, "null")
	if err != nil {
		return unknownErr(err)
	}
	return byStatus(r, identity("email"))
}

func verifyLinear(ctx context.Context, h *HTTP, t Target) Result {
	r, err := h.Do(ctx, "POST", "https://api.linear.app/graphql", map[string]string{
		"Authorization": t.Secret, "Content-Type": "application/json",
	}, `{"query":"{ viewer { name email } }"}`)
	if err != nil {
		return unknownErr(err)
	}
	if e := jsonPath(r.Body, "data.viewer.email"); e != "" {
		return Result{State: Live, Identity: e}
	}
	if strings.Contains(strings.ToLower(string(r.Body)), "authentication") {
		return Result{State: Dead, Note: "authentication failed"}
	}
	return byStatus(r, nil)
}

func verifyPostman(ctx context.Context, h *HTTP, t Target) Result {
	r, err := h.Do(ctx, "GET", "https://api.getpostman.com/me", map[string]string{"X-Api-Key": t.Secret}, "")
	if err != nil {
		return unknownErr(err)
	}
	return byStatus(r, identity("user.username"))
}

func verifyCloudinary(ctx context.Context, h *HTTP, t Target) Result {
	r, err := h.Do(ctx, "GET", "https://api.cloudinary.com/v1_1/"+t.Parts["cloud"]+"/usage",
		map[string]string{"Authorization": basic(t.Parts["api_key"], t.Secret)}, "")
	if err != nil {
		return unknownErr(err)
	}
	if r.Status == 404 {
		return Result{State: Dead, Note: "cloud name not found"}
	}
	return byStatus(r, func(r *Response) Result {
		return Result{State: Live, Identity: t.Parts["cloud"] + " (plan: " + jsonPath(r.Body, "plan") + ")"}
	})
}

func verifySupabase(ctx context.Context, h *HTTP, t Target) Result {
	ref := t.Parts["supabase_ref"]
	if ref == "" {
		return Result{State: Skip, Note: "no check for generic JWTs"}
	}
	r, err := h.Do(ctx, "GET", "https://"+ref+".supabase.co/rest/v1/", map[string]string{
		"apikey": t.Secret, "Authorization": "Bearer " + t.Secret,
	}, "")
	if err != nil {
		if noSuchHost(err) {
			return Result{State: Dead, Note: "Supabase project no longer exists"}
		}
		return unknownErr(err)
	}
	if r.Status == 200 {
		return Result{State: Live, Identity: "service_role on project " + ref}
	}
	return byStatus(r, nil)
}
