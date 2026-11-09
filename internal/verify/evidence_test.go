package verify

import (
	"net/http"
	"strings"
	"testing"
)

func TestEvidenceCurlReproducesCheck(t *testing.T) {
	res := enriched(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"id":"acct_1","email":"ops@target.tld"}`))
	}, Target{RuleID: "stripe-key", Secret: "sk_live_abc'def"})
	ev := res.Evidence
	if ev == nil || ev.Status != 200 || !strings.Contains(ev.Response, "acct_1") {
		t.Fatalf("%+v", ev)
	}
	want := `curl -s 'https://api.stripe.com/v1/account' -H 'Authorization: Basic `
	if !strings.HasPrefix(ev.Command, want) {
		t.Errorf("command = %s", ev.Command)
	}
	if ev.Request != "GET https://api.stripe.com/v1/account" {
		t.Errorf("request should show the real provider URL, got %s", ev.Request)
	}
}

func TestEvidenceAWSUsesCLI(t *testing.T) {
	res := enriched(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			w.Write([]byte(`<Arn>arn:aws:iam::1:user/u</Arn>`))
			return
		}
		w.WriteHeader(403)
	}, Target{RuleID: "aws-access-key", Secret: "AKIAEXAMPLEKEYID0000", Parts: map[string]string{"secret_key": "se'cret"}})
	want := `AWS_ACCESS_KEY_ID='AKIAEXAMPLEKEYID0000' AWS_SECRET_ACCESS_KEY='se'\''cret' aws sts get-caller-identity`
	if res.Evidence == nil || res.Evidence.Command != want {
		t.Fatalf("got %+v", res.Evidence)
	}
}
