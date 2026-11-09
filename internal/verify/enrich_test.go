package verify

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func enriched(t *testing.T, h http.HandlerFunc, tg Target) Result {
	t.Helper()
	v := serve(t, h)
	v.Enrich = true
	return v.Verify(context.Background(), tg.RuleID+tg.Secret, tg)
}

func hasAccess(r Result, sub string) bool {
	for _, a := range r.Access {
		if strings.Contains(a, sub) {
			return true
		}
	}
	return false
}

func TestEnrichAWSAdminUser(t *testing.T) {
	res := enriched(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "POST": // STS
			w.Write([]byte(`<Arn>arn:aws:iam::123456789012:user/deploy</Arn>`))
		case r.URL.Query().Get("Action") == "ListAttachedUserPolicies":
			if r.URL.Query().Get("UserName") != "deploy" {
				t.Errorf("wrong user %q", r.URL.Query().Get("UserName"))
			}
			w.Write([]byte(`<PolicyName>AdministratorAccess</PolicyName><PolicyName>ReadOnly</PolicyName>`))
		default: // S3 ListBuckets
			if r.Header.Get("X-Amz-Content-Sha256") == "" {
				t.Error("S3 request must carry x-amz-content-sha256")
			}
			w.Write([]byte(`<Buckets><Bucket><Name>prod-backups</Name></Bucket><Bucket><Name>logs</Name></Bucket></Buckets>`))
		}
	}, Target{RuleID: "aws-access-key", Secret: "AKIAXXXXXXXXXXXXXXXX", Parts: map[string]string{"secret_key": "s"}})
	if res.Severity != "critical" || !hasAccess(res, "AdministratorAccess") || !hasAccess(res, "2 S3 buckets: prod-backups, logs") {
		t.Fatalf("%+v", res)
	}
}

func TestEnrichAWSRoot(t *testing.T) {
	res := enriched(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			w.Write([]byte(`<Arn>arn:aws:iam::123456789012:root</Arn>`))
			return
		}
		w.WriteHeader(403)
	}, Target{RuleID: "aws-access-key", Secret: "AKIAXXXXXXXXXXXXXXXX", Parts: map[string]string{"secret_key": "s"}})
	if res.Severity != "critical" || !hasAccess(res, "ROOT") {
		t.Fatalf("%+v", res)
	}
}

func TestEnrichGitHubScopesDriveSeverity(t *testing.T) {
	for scopes, want := range map[string]string{"repo, workflow": "critical", "read:user": "medium"} {
		res := enriched(t, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/user/orgs" {
				w.Write([]byte(`[{"login":"acme"}]`))
				return
			}
			w.Header().Set("X-OAuth-Scopes", scopes)
			w.Write([]byte(`{"login":"dev","total_private_repos":12}`))
		}, Target{RuleID: "github-token", Secret: "ghp_x"})
		if res.Severity != want || !hasAccess(res, "acme") || !hasAccess(res, "private repositories: 12") {
			t.Errorf("scopes %q: %+v", scopes, res)
		}
	}
}

func TestEnrichAzureADRoles(t *testing.T) {
	claims, _ := json.Marshal(map[string]any{"roles": []string{"Mail.Read", "User.Read.All"}})
	tok := "e30." + base64.RawURLEncoding.EncodeToString(claims) + ".sig"
	res := enriched(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"access_token":"` + tok + `"}`))
	}, Target{RuleID: "azure-ad-client-secret", Secret: "s", Parts: map[string]string{"tenant_id": "t", "client_id": "c"}})
	if res.Severity != "critical" || !hasAccess(res, "Mail.Read, User.Read.All") {
		t.Fatalf("%+v", res)
	}
}

func TestEnrichNPMPackages(t *testing.T) {
	res := enriched(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.RawQuery, "maintainer") {
			w.Write([]byte(`{"total":3,"objects":[{"package":{"name":"left-pad-pro"}},{"package":{"name":"acme-sdk"}},{"package":{"name":"acme-cli"}}]}`))
			return
		}
		w.Write([]byte(`{"username":"acme-bot"}`))
	}, Target{RuleID: "npm-token", Secret: "npm_x"})
	if res.Severity != "critical" || !hasAccess(res, "maintains 3 npm packages") {
		t.Fatalf("%+v", res)
	}
}

func TestNoEnrichMakesOneCall(t *testing.T) {
	var calls int
	v := serve(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("X-OAuth-Scopes", "repo")
		w.Write([]byte(`{"login":"dev"}`))
	})
	res := v.Verify(context.Background(), "k", Target{RuleID: "github-token", Secret: "ghp_x"})
	if res.State != Live || calls != 1 || len(res.Access) != 0 {
		t.Fatalf("calls=%d res=%+v", calls, res)
	}
}
