package verify

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
)

func init() {
	for id, sp := range specs {
		funcs[id] = sp.Func()
	}
	for id, f := range moreFuncs {
		funcs[id] = f
	}
}

var specs = map[string]spec{
	"okta-token": {URL: "https://{domain}/api/v1/users/me", Need: []string{"domain"},
		Headers: map[string]string{"Authorization": "SSWS {secret}"}, ID: "profile.login", Live403: true},
	"vault-token": {URL: "{addr}/v1/auth/token/lookup-self", Need: []string{"addr"},
		Headers: map[string]string{"X-Vault-Token": "{secret}"}, ID: "data.display_name", Dead403: true},
	"terraform-cloud-token": {URL: "https://app.terraform.io/api/v2/account/details",
		Headers: map[string]string{"Authorization": "Bearer {secret}"}, ID: "data.attributes.username"},
	"doppler-token": {URL: "https://api.doppler.com/v3/me",
		Headers: map[string]string{"Authorization": "Bearer {secret}"}, ID: "workplace.name", Live403: true},
	"pulumi-token": {URL: "https://api.pulumi.com/api/user",
		Headers: map[string]string{"Authorization": "token {secret}"}, ID: "githubLogin"},
	"netlify-token": {URL: "https://api.netlify.com/api/v1/user",
		Headers: map[string]string{"Authorization": "Bearer {secret}"}, ID: "email"},
	"render-key": {URL: "https://api.render.com/v1/owners?limit=1",
		Headers: map[string]string{"Authorization": "Bearer {secret}"}, ID: "0.owner.email"},
	"cloudflare-token": {URL: "https://api.cloudflare.com/client/v4/user/tokens/verify",
		Headers: map[string]string{"Authorization": "Bearer {secret}"}, ID: "result.status",
		DeadBody: []string{"Invalid API Token", "Invalid request headers"}},
	"supabase-secret-key": {URL: "https://{project}.supabase.co/rest/v1/", Need: []string{"project"},
		Headers: map[string]string{"apikey": "{secret}"}},
	"atlassian-token": {URL: "https://{site}/rest/api/3/myself", Need: []string{"site", "email"},
		Headers: map[string]string{"Authorization": "basic:{email}:{secret}"}, ID: "displayName"},
	"bitbucket-app-password": {URL: "https://api.bitbucket.org/2.0/user", Need: []string{"username"},
		Headers: map[string]string{"Authorization": "basic:{username}:{secret}"}, ID: "display_name", Live403: true},
	"jfrog-token": {URL: "https://{host}/artifactory/api/security/encryptedPassword", Need: []string{"host"},
		Headers: map[string]string{"X-JFrog-Art-Api": "{secret}"}, Dead403: true},
	"grafana-token": {URL: "{instance}/api/org", Need: []string{"instance"},
		Headers: map[string]string{"Authorization": "Bearer {secret}"}, ID: "name", Live403: true},
	"circleci-token": {URL: "https://circleci.com/api/v2/me",
		Headers: map[string]string{"Circle-Token": "{secret}"}, ID: "login"},
	"buildkite-token": {URL: "https://api.buildkite.com/v2/access-token",
		Headers: map[string]string{"Authorization": "Bearer {secret}"}, ID: "scopes.0"},
	"pagerduty-key": {URL: "https://api.pagerduty.com/abilities",
		Headers: map[string]string{"Authorization": "Token token={secret}", "Accept": "application/vnd.pagerduty+json;version=2"}, Live403: true},
	"zendesk-token": {URL: "https://{subdomain}.zendesk.com/api/v2/users/me.json", Need: []string{"subdomain", "email"},
		Headers: map[string]string{"Authorization": "basic:{email}/token:{secret}"}, ID: "user.email",
		LiveCheck: func(r *Response) bool { return jsonPath(r.Body, "user.id") != "" }}, // anonymous gets a user with no id
	"airtable-token": {URL: "https://api.airtable.com/v0/meta/whoami",
		Headers: map[string]string{"Authorization": "Bearer {secret}"}, ID: "email"},
	"asana-token": {URL: "https://app.asana.com/api/1.0/users/me",
		Headers: map[string]string{"Authorization": "Bearer {secret}"}, ID: "data.email"},
	"figma-token": {URL: "https://api.figma.com/v1/me",
		Headers: map[string]string{"X-Figma-Token": "{secret}"}, ID: "email", Dead403: true},
	"typeform-token": {URL: "https://api.typeform.com/me",
		Headers: map[string]string{"Authorization": "Bearer {secret}"}, ID: "email", DeadBody: []string{"AUTHENTICATION_FAILED"}},
	"contentful-token": {URL: "https://api.contentful.com/users/me",
		Headers: map[string]string{"Authorization": "Bearer {secret}"}, ID: "email"},
	"hubspot-token": {URL: "https://api.hubapi.com/account-info/v3/details",
		Headers: map[string]string{"Authorization": "Bearer {secret}"}, ID: "portalId", Live403: true},
	"brevo-key": {URL: "https://api.brevo.com/v3/account",
		Headers: map[string]string{"api-key": "{secret}"}, ID: "email"},
	"intercom-token": {URL: "https://api.intercom.io/me",
		Headers: map[string]string{"Authorization": "Bearer {secret}"}, ID: "email", Live403: true},
	"razorpay-key": {URL: "https://api.razorpay.com/v1/payments?count=1", Need: []string{"key_secret"},
		Headers: map[string]string{"Authorization": "basic:{secret}:{key_secret}"}},
	"shippo-token": {URL: "https://api.goshippo.com/addresses/?results=1",
		Headers: map[string]string{"Authorization": "ShippoToken {secret}"}},
	"groq-key": {URL: "https://api.groq.com/openai/v1/models",
		Headers: map[string]string{"Authorization": "Bearer {secret}"}, Live403: true},
	"replicate-token": {URL: "https://api.replicate.com/v1/account",
		Headers: map[string]string{"Authorization": "Bearer {secret}"}, ID: "username"},
	"xai-key": {URL: "https://api.x.ai/v1/api-key",
		Headers: map[string]string{"Authorization": "Bearer {secret}"}, ID: "name", DeadBody: []string{"Incorrect API key", "invalid-argument"}},
	"elevenlabs-key": {URL: "https://api.elevenlabs.io/v1/user",
		Headers: map[string]string{"xi-api-key": "{secret}"}, ID: "subscription.tier", DeadBody: []string{"invalid_api_key"}},
	"pinecone-key": {URL: "https://api.pinecone.io/indexes",
		Headers: map[string]string{"Api-Key": "{secret}", "X-Pinecone-API-Version": "2024-07"}, Live403: true},
	"langsmith-key": {URL: "https://api.smith.langchain.com/api/v1/sessions?limit=1",
		Headers: map[string]string{"x-api-key": "{secret}"}, Dead403: true},
}

var moreFuncs = map[string]Func{
	"azure-ad-client-secret": verifyAzureAD,
	"firebase-database":      verifyFirebaseDB,
	"datadog-key":            verifyDatadog,
	"newrelic-key":           verifyNewRelic,
	"sentry-token":           verifySentry,
}

// Azure AD: ask the tenant for an app-only token with the client
// credentials. Minting a token changes nothing.
func verifyAzureAD(ctx context.Context, h *HTTP, t Target) Result {
	tenant, client := t.Parts["tenant_id"], t.Parts["client_id"]
	if tenant == "" || client == "" {
		return Result{State: Skip, Note: "needs the tenant ID and client ID found next to it"}
	}
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {client},
		"client_secret": {t.Secret},
		"scope":         {"https://graph.microsoft.com/.default"},
	}
	r, err := h.Do(ctx, "POST", "https://login.microsoftonline.com/"+tenant+"/oauth2/v2.0/token",
		map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, form.Encode())
	if err != nil {
		return unknownErr(err)
	}
	if r.Status == 200 {
		return Result{State: Live, Identity: "app " + client + " in tenant " + tenant, raw: r}
	}
	desc := jsonPath(r.Body, "error_description")
	for _, code := range []string{"AADSTS7000215", "AADSTS7000222", "AADSTS700016", "AADSTS90002", "AADSTS900023"} {
		if strings.Contains(desc, code) {
			return Result{State: Dead, Note: code + " (invalid/expired secret, or app/tenant not found)"}
		}
	}
	return byStatus(r, nil)
}

// Firebase: an unauthenticated shallow read shows whether the database's
// rules let anyone read it.
func verifyFirebaseDB(ctx context.Context, h *HTTP, t Target) Result {
	base := strings.TrimRight(t.Secret, "/")
	r, err := h.Do(ctx, "GET", base+"/.json?shallow=true", nil, "")
	if err != nil {
		if noSuchHost(err) {
			return Result{State: Dead, Note: "database no longer exists"}
		}
		return unknownErr(err)
	}
	body := strings.TrimSpace(string(r.Body))
	switch {
	case r.Status == 200 && body != "null":
		res := Result{State: Live, Identity: "readable by anyone - no authentication required"}
		var top map[string]any
		if json.Unmarshal(r.Body, &top) == nil && len(top) > 0 {
			keys := make([]string, 0, len(top))
			for k := range top {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			res.Access = append(res.Access, fmt.Sprintf("%d top-level nodes readable: %s", len(keys), listN(keys, 10)))
		}
		return res
	case r.Status == 200:
		return Result{State: Harmless, Note: "readable but empty"}
	case r.Status == 401 || r.Status == 403:
		return Result{State: Harmless, Note: "security rules deny public reads"}
	case r.Status == 404 || r.Status == 423:
		return Result{State: Dead, Note: "database deleted or deactivated"}
	}
	return byStatus(r, nil)
}

func verifyDatadog(ctx context.Context, h *HTTP, t Target) Result {
	var last *Response
	for _, site := range []string{"datadoghq.com", "datadoghq.eu", "us3.datadoghq.com", "us5.datadoghq.com", "ap1.datadoghq.com"} {
		r, err := h.Do(ctx, "GET", "https://api."+site+"/api/v1/validate", map[string]string{"DD-API-KEY": t.Secret}, "")
		if err != nil {
			return unknownErr(err)
		}
		if r.Status == 200 && jsonPath(r.Body, "valid") == "true" {
			return Result{State: Live, Identity: "Datadog org on " + site}
		}
		last = r
		if r.Status != 403 && r.Status != 401 {
			break
		}
	}
	if last.Status == 403 || last.Status == 401 {
		return Result{State: Dead, Note: "rejected on every Datadog site"}
	}
	return byStatus(last, nil)
}

func verifyNewRelic(ctx context.Context, h *HTTP, t Target) Result {
	const q = `{"query":"{ actor { user { email } } }"}`
	var last *Response
	for _, host := range []string{"api.newrelic.com", "api.eu.newrelic.com"} {
		r, err := h.Do(ctx, "POST", "https://"+host+"/graphql", map[string]string{"API-Key": t.Secret, "Content-Type": "application/json"}, q)
		if err != nil {
			return unknownErr(err)
		}
		if e := jsonPath(r.Body, "data.actor.user.email"); e != "" {
			return Result{State: Live, Identity: e}
		}
		last = r
	}
	if last.Status == 401 || last.Status == 403 || strings.Contains(string(last.Body), "nvalid") {
		return Result{State: Dead, Note: "rejected in US and EU regions"}
	}
	return byStatus(last, nil)
}

func verifySentry(ctx context.Context, h *HTTP, t Target) Result {
	base, endpoint := "https://sentry.io", "/api/0/organizations/"
	if u := t.Parts["url"]; u != "" {
		base = u
	}
	if org := t.Parts["org"]; org != "" {
		endpoint = "/api/0/organizations/" + org + "/"
	}
	r, err := h.Do(ctx, "GET", base+endpoint, map[string]string{"Authorization": "Bearer " + t.Secret}, "")
	if err != nil {
		return unknownErr(err)
	}
	if r.Status == 403 {
		return Result{State: Live, Note: "accepted, limited scopes"}
	}
	return byStatus(r, func(r *Response) Result {
		id := jsonPath(r.Body, "slug")
		if id == "" {
			id = jsonPath(r.Body, "0.slug")
		}
		return Result{State: Live, Identity: "org " + id}
	})
}
