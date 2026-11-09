package verify

import (
	"net/http"
	"strings"
	"testing"
)

func TestAzureADVerdicts(t *testing.T) {
	parts := map[string]string{"tenant_id": "t", "client_id": "c"}
	v := serve(t, func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		if r.Form.Get("grant_type") != "client_credentials" {
			t.Errorf("unexpected grant %q", r.Form.Get("grant_type"))
		}
		if r.Form.Get("client_secret") == "good" {
			w.Write([]byte(`{"access_token":"x"}`))
			return
		}
		w.WriteHeader(401)
		w.Write([]byte(`{"error":"invalid_client","error_description":"AADSTS7000215: Invalid client secret provided."}`))
	})
	if got := check(t, v, Target{RuleID: "azure-ad-client-secret", Secret: "good", Parts: parts}); got.State != Live {
		t.Errorf("good secret: %v", got.State)
	}
	if got := check(t, v, Target{RuleID: "azure-ad-client-secret", Secret: "bad", Parts: parts}); got.State != Dead {
		t.Errorf("bad secret: %v", got.State)
	}
	if got := check(t, v, Target{RuleID: "azure-ad-client-secret", Secret: "x"}); got.State != Skip {
		t.Errorf("missing tenant/client must skip, got %v", got.State)
	}
}

func TestFirebaseVerdicts(t *testing.T) {
	cases := []struct {
		status int
		body   string
		want   State
	}{
		{200, `{"users":true,"orders":true}`, Live},
		{401, `{"error":"Permission denied"}`, Harmless},
		{200, `null`, Harmless},
		{404, ``, Dead},
	}
	for _, c := range cases {
		v := serve(t, func(w http.ResponseWriter, r *http.Request) {
			if !strings.HasSuffix(r.URL.String(), "/.json?shallow=true") {
				t.Errorf("unexpected request %s", r.URL)
			}
			w.WriteHeader(c.status)
			w.Write([]byte(c.body))
		})
		if got := check(t, v, Target{RuleID: "firebase-database", Secret: "https://acme.firebaseio.com"}); got.State != c.want {
			t.Errorf("%d %s: got %v want %v", c.status, c.body, got.State, c.want)
		}
	}
}

func TestDatadogTriesEverySite(t *testing.T) {
	var hits int
	v := serve(t, func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(403)
		w.Write([]byte(`{"errors":["Forbidden"]}`))
	})
	if got := check(t, v, Target{RuleID: "datadog-key", Secret: "k"}); got.State != Dead || hits != 5 {
		t.Errorf("state %v after %d sites", got.State, hits)
	}
}

func TestZendeskAnonymousIsNotLive(t *testing.T) {
	v := serve(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"user":{"id":null,"name":"Anonymous user"}}`))
	})
	got := check(t, v, Target{RuleID: "zendesk-token", Secret: "k", Parts: map[string]string{"subdomain": "acme", "email": "a@b.co"}})
	if got.State == Live {
		t.Error("Zendesk returns an anonymous user for bad credentials; that is not live")
	}
}

func TestEveryVerifiableRuleHasACheck(t *testing.T) {
	for id := range specs {
		if funcs[id] == nil {
			t.Errorf("spec %s not registered", id)
		}
	}
}
