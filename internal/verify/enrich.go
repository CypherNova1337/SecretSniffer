package verify

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// An enricher runs after a credential verifies, using only read-only calls,
// to work out what it can actually reach. It adds to res.Access and may
// raise or lower res.Severity to match real access rather than key type.
type enricher func(ctx context.Context, h *HTTP, t Target, res *Result)

var enrichers = map[string]enricher{
	"aws-access-key":         enrichAWS,
	"github-token":           enrichGitHub,
	"github-fine-grained":    enrichGitHub,
	"gitlab-token":           enrichGitLab,
	"slack-token":            enrichSlack,
	"stripe-key":             enrichStripe,
	"shopify-token":          enrichShopify,
	"npm-token":              enrichNPM,
	"azure-ad-client-secret": enrichAzureAD,
	"gcp-service-account":    enrichGCP,
	"twilio-credentials":     enrichTwilio,
}

func listN(items []string, n int) string {
	if len(items) <= n {
		return strings.Join(items, ", ")
	}
	return strings.Join(items[:n], ", ") + fmt.Sprintf(" (+%d more)", len(items)-n)
}

func anyMatch(items []string, re *regexp.Regexp) bool {
	for _, i := range items {
		if re.MatchString(i) {
			return true
		}
	}
	return false
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// ---------------------------------------------------------------- AWS

var (
	policyNameRe = regexp.MustCompile(`<PolicyName>([^<]+)</PolicyName>`)
	bucketRe     = regexp.MustCompile(`<Bucket><Name>([^<]+)</Name>`)
	adminPolicy  = regexp.MustCompile(`(?i)^(AdministratorAccess|PowerUserAccess|IAMFullAccess|.*FullAccess)$`)
)

// awsGet signs and sends a GET to an AWS query or REST endpoint.
func awsGet(ctx context.Context, h *HTTP, t Target, host, service, path string, query url.Values) (*Response, error) {
	q := strings.ReplaceAll(query.Encode(), "+", "%20")
	now := time.Now()
	hdrs := map[string]string{
		"host":                 host,
		"x-amz-date":           now.UTC().Format("20060102T150405Z"),
		"x-amz-content-sha256": sha256Hex(""),
	}
	if tok := t.Parts["session_token"]; tok != "" {
		hdrs["x-amz-security-token"] = tok
	}
	auth := sigV4("GET", path, q, hdrs, "", t.Secret, t.Parts["secret_key"], "us-east-1", service, now)
	send := map[string]string{"Authorization": auth}
	for k, v := range hdrs {
		if k != "host" {
			send[k] = v
		}
	}
	u := "https://" + host + path
	if q != "" {
		u += "?" + q
	}
	return h.Do(ctx, "GET", u, send, "")
}

func enrichAWS(ctx context.Context, h *HTTP, t Target, res *Result) {
	arn := res.Identity
	switch {
	case strings.HasSuffix(arn, ":root"):
		res.Access = append(res.Access, "ROOT account credentials - unrestricted control of the whole AWS account")
		res.Severity = "critical"
	case strings.Contains(arn, ":user/"):
		name := arn[strings.LastIndex(arn, "/")+1:]
		r, err := awsGet(ctx, h, t, "iam.amazonaws.com", "iam", "/", url.Values{
			"Action": {"ListAttachedUserPolicies"}, "UserName": {name}, "Version": {"2010-05-08"},
		})
		if err == nil && r.Status == 200 {
			var names []string
			for _, m := range policyNameRe.FindAllStringSubmatch(string(r.Body), -1) {
				names = append(names, m[1])
			}
			if len(names) == 0 {
				res.Access = append(res.Access, "no managed policies attached (may still have inline or group policies)")
			} else {
				res.Access = append(res.Access, "IAM policies: "+listN(names, 8))
				if anyMatch(names, adminPolicy) {
					res.Severity = "critical"
				}
			}
		} else if err == nil {
			res.Access = append(res.Access, "cannot read its own IAM policies")
		}
	}
	r, err := awsGet(ctx, h, t, "s3.amazonaws.com", "s3", "/", url.Values{})
	if err == nil && r.Status == 200 {
		var buckets []string
		for _, m := range bucketRe.FindAllStringSubmatch(string(r.Body), -1) {
			buckets = append(buckets, m[1])
		}
		res.Access = append(res.Access, fmt.Sprintf("can list %d S3 buckets: %s", len(buckets), listN(buckets, 6)))
	}
}

// ------------------------------------------------------------- GitHub

var githubPowerful = regexp.MustCompile(`^(repo|public_repo|admin:org|write:org|workflow|delete_repo|admin:repo_hook|admin:org_hook|write:packages|admin:enterprise|site_admin)$`)

func enrichGitHub(ctx context.Context, h *HTTP, t Target, res *Result) {
	if res.raw == nil || res.raw.Status != 200 {
		return
	}
	scopes := splitList(res.raw.Header.Get("X-OAuth-Scopes"))
	if len(scopes) > 0 {
		res.Access = append(res.Access, "scopes: "+strings.Join(scopes, ", "))
		if anyMatch(scopes, githubPowerful) {
			res.Severity = "critical"
		} else {
			res.Severity = "medium"
		}
	}
	if n := jsonPath(res.raw.Body, "total_private_repos"); n != "" && n != "0" {
		res.Access = append(res.Access, "private repositories: "+n)
	}
	if jsonPath(res.raw.Body, "site_admin") == "true" {
		res.Access = append(res.Access, "GitHub Enterprise site admin")
		res.Severity = "critical"
	}
	r, err := h.Do(ctx, "GET", "https://api.github.com/user/orgs?per_page=100", map[string]string{
		"Authorization": "token " + t.Secret, "Accept": "application/vnd.github+json",
	}, "")
	if err == nil && r.Status == 200 {
		var orgs []struct{ Login string }
		if json.Unmarshal(r.Body, &orgs) == nil && len(orgs) > 0 {
			names := make([]string, len(orgs))
			for i, o := range orgs {
				names[i] = o.Login
			}
			res.Access = append(res.Access, "member of orgs: "+listN(names, 8))
		}
	}
}

// ------------------------------------------------------------- GitLab

func enrichGitLab(ctx context.Context, h *HTTP, t Target, res *Result) {
	if res.raw != nil && jsonPath(res.raw.Body, "is_admin") == "true" {
		res.Access = append(res.Access, "GitLab instance ADMINISTRATOR")
		res.Severity = "critical"
	}
	host := t.Parts["host"]
	if host == "" {
		host = "gitlab.com"
	}
	r, err := h.Do(ctx, "GET", "https://"+host+"/api/v4/personal_access_tokens/self", map[string]string{"PRIVATE-TOKEN": t.Secret}, "")
	if err == nil && r.Status == 200 {
		var v struct {
			Scopes    []string `json:"scopes"`
			ExpiresAt string   `json:"expires_at"`
		}
		if json.Unmarshal(r.Body, &v) == nil && len(v.Scopes) > 0 {
			line := "scopes: " + strings.Join(v.Scopes, ", ")
			if v.ExpiresAt != "" {
				line += " (expires " + v.ExpiresAt + ")"
			}
			res.Access = append(res.Access, line)
			if anyMatch(v.Scopes, regexp.MustCompile(`^(api|write_repository|sudo|admin_mode|write_registry)$`)) {
				res.Severity = "critical"
			}
		}
	}
}

// -------------------------------------------------------------- Slack

func enrichSlack(_ context.Context, _ *HTTP, _ Target, res *Result) {
	if res.raw == nil {
		return
	}
	scopes := splitList(res.raw.Header.Get("X-Oauth-Scopes"))
	if len(scopes) > 0 {
		res.Access = append(res.Access, "scopes: "+listN(scopes, 12))
		switch {
		case anyMatch(scopes, regexp.MustCompile(`^admin`)):
			res.Severity = "critical"
		case anyMatch(scopes, regexp.MustCompile(`^(channels:history|groups:history|im:history|mpim:history|files:read|users:read\.email)$`)):
			res.Severity = "high"
		}
	}
	if jsonPath(res.raw.Body, "is_enterprise_install") == "true" {
		res.Access = append(res.Access, "Enterprise Grid install")
	}
}

// ------------------------------------------------------------- Stripe

func enrichStripe(_ context.Context, _ *HTTP, t Target, res *Result) {
	if res.raw == nil || res.raw.Status != 200 {
		return
	}
	b := res.raw.Body
	name := jsonPath(b, "business_profile.name")
	if name == "" {
		name = jsonPath(b, "settings.dashboard.display_name")
	}
	line := "account"
	if name != "" {
		line += " \"" + name + "\""
	}
	if c := jsonPath(b, "country"); c != "" {
		line += " (" + c + ")"
	}
	if jsonPath(b, "charges_enabled") == "true" {
		line += ", charges enabled"
	}
	if jsonPath(b, "payouts_enabled") == "true" {
		line += ", payouts enabled"
	}
	res.Access = append(res.Access, line)
	if strings.Contains(t.Secret, "_live_") && jsonPath(b, "charges_enabled") == "true" {
		res.Severity = "critical"
	}
}

// ------------------------------------------------------------ Shopify

func enrichShopify(ctx context.Context, h *HTTP, t Target, res *Result) {
	r, err := h.Do(ctx, "GET", "https://"+t.Parts["shop"]+"/admin/oauth/access_scopes.json",
		map[string]string{"X-Shopify-Access-Token": t.Secret}, "")
	if err != nil || r.Status != 200 {
		return
	}
	var v struct {
		Scopes []struct{ Handle string } `json:"access_scopes"`
	}
	if json.Unmarshal(r.Body, &v) != nil {
		return
	}
	var hs []string
	for _, s := range v.Scopes {
		hs = append(hs, s.Handle)
	}
	if len(hs) > 0 {
		res.Access = append(res.Access, "scopes: "+listN(hs, 12))
		if anyMatch(hs, regexp.MustCompile(`^(write_|read_customers|read_orders|read_all_orders)`)) {
			res.Severity = "critical"
		}
	}
}

// ---------------------------------------------------------------- npm

func enrichNPM(ctx context.Context, h *HTTP, _ Target, res *Result) {
	user := res.Identity
	if user == "" {
		return
	}
	// Public data - no token needed - but it's what turns a leaked token into
	// a supply-chain finding.
	r, err := h.Do(ctx, "GET", "https://registry.npmjs.org/-/v1/search?size=20&text=maintainer:"+url.QueryEscape(user), nil, "")
	if err != nil || r.Status != 200 {
		return
	}
	var v struct {
		Total   int `json:"total"`
		Objects []struct {
			Package struct{ Name string } `json:"package"`
		} `json:"objects"`
	}
	if json.Unmarshal(r.Body, &v) != nil || v.Total == 0 {
		return
	}
	names := make([]string, 0, len(v.Objects))
	for _, o := range v.Objects {
		names = append(names, o.Package.Name)
	}
	res.Access = append(res.Access, fmt.Sprintf("maintains %d npm packages (can publish new versions): %s", v.Total, listN(names, 8)))
	res.Severity = "critical"
}

// ------------------------------------------------------------ Azure AD

var graphPowerful = regexp.MustCompile(`(ReadWrite\.All|^Directory\.|^RoleManagement\.|^Mail\.|^Files\.|^Sites\.|^User\.Read\.All|^Application\.ReadWrite|^AppRoleAssignment\.ReadWrite)`)

func enrichAzureAD(_ context.Context, _ *HTTP, _ Target, res *Result) {
	if res.raw == nil {
		return
	}
	claims := jwtClaims(jsonPath(res.raw.Body, "access_token"))
	var roles []string
	if rs, ok := claims["roles"].([]any); ok {
		for _, r := range rs {
			if s, ok := r.(string); ok {
				roles = append(roles, s)
			}
		}
	}
	if len(roles) == 0 {
		res.Access = append(res.Access, "token issued, but no Microsoft Graph application permissions granted")
		res.Severity = "medium"
		return
	}
	res.Access = append(res.Access, "Microsoft Graph app permissions: "+listN(roles, 12))
	if anyMatch(roles, graphPowerful) {
		res.Severity = "critical"
	}
}

func jwtClaims(tok string) map[string]any {
	parts := strings.Split(tok, ".")
	if len(parts) < 2 {
		return nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return nil
	}
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	return m
}

// --------------------------------------------------------------- GCP

func enrichGCP(ctx context.Context, h *HTTP, _ Target, res *Result) {
	if res.raw == nil {
		return
	}
	tok := jsonPath(res.raw.Body, "access_token")
	if tok == "" {
		return
	}
	r, err := h.Do(ctx, "GET", "https://cloudresourcemanager.googleapis.com/v1/projects?pageSize=50",
		map[string]string{"Authorization": "Bearer " + tok}, "")
	if err != nil || r.Status != 200 {
		return
	}
	var v struct {
		Projects []struct {
			ProjectID string `json:"projectId"`
		} `json:"projects"`
	}
	if json.Unmarshal(r.Body, &v) != nil {
		return
	}
	ids := make([]string, len(v.Projects))
	for i, p := range v.Projects {
		ids[i] = p.ProjectID
	}
	if len(ids) > 0 {
		res.Access = append(res.Access, fmt.Sprintf("can see %d GCP projects: %s", len(ids), listN(ids, 8)))
	}
}

// ------------------------------------------------------------- Twilio

func enrichTwilio(_ context.Context, _ *HTTP, _ Target, res *Result) {
	if res.raw == nil {
		return
	}
	typ := jsonPath(res.raw.Body, "type")
	if typ == "" {
		return
	}
	res.Access = append(res.Access, "account type: "+typ)
	if typ == "Trial" {
		res.Severity = "medium"
	}
}
