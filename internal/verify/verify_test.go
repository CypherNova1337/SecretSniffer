package verify

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// AWS's published Signature V4 example (IAM ListUsers, 2015-08-30).
func TestSigV4KnownVector(t *testing.T) {
	ts := time.Date(2015, 8, 30, 12, 36, 0, 0, time.UTC)
	hdr := map[string]string{
		"content-type": "application/x-www-form-urlencoded; charset=utf-8",
		"host":         "iam.amazonaws.com",
		"x-amz-date":   "20150830T123600Z",
	}
	got := sigV4("GET", "/", "Action=ListUsers&Version=2010-05-08", hdr, "",
		"AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", "us-east-1", "iam", ts)
	want := "Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"
	if !strings.HasSuffix(got, want) {
		t.Fatalf("got %s", got)
	}
}

func serve(t *testing.T, h http.HandlerFunc) *Verifier {
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	v := New(5 * time.Second)
	v.SetRewrite(func(u string) string {
		i := strings.Index(u[8:], "/")
		return srv.URL + u[8+i:]
	})
	return v
}

func check(t *testing.T, v *Verifier, tg Target) Result {
	t.Helper()
	return v.Verify(context.Background(), tg.RuleID+tg.Secret, tg)
}

func TestSlackWebhookNeverPostsAMessage(t *testing.T) {
	var body string
	v := serve(t, func(w http.ResponseWriter, r *http.Request) {
		b := make([]byte, 100)
		n, _ := r.Body.Read(b)
		body = string(b[:n])
		w.WriteHeader(400)
		w.Write([]byte("no_text"))
	})
	res := check(t, v, Target{RuleID: "slack-webhook", Secret: "https://hooks.slack.com/services/T000/B000/xyz"})
	if res.State != Live || body != `{"text":""}` {
		t.Fatalf("state=%v body=%q", res.State, body)
	}
	wf := check(t, v, Target{RuleID: "slack-webhook", Secret: "https://hooks.slack.com/workflows/T000/A000/123/abc"})
	if wf.State != Skip {
		t.Fatalf("workflow webhooks must not be called, got %v", wf.State)
	}
}

func TestAlgoliaSearchOnlyIsHarmless(t *testing.T) {
	v := serve(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"value":"k","acl":["search"]}`))
	})
	res := check(t, v, Target{RuleID: "algolia-key", Secret: "k", Parts: map[string]string{"app_id": "ABCDEFGHIJ"}})
	if res.State != Harmless {
		t.Fatalf("got %v %s", res.State, res.Note)
	}
}

func TestAlgoliaAdminKey(t *testing.T) {
	v := serve(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/1/keys" {
			w.Write([]byte(`{"keys":[]}`))
			return
		}
		w.WriteHeader(404)
		w.Write([]byte(`{"message":"Key does not exist"}`))
	})
	res := check(t, v, Target{RuleID: "algolia-key", Secret: "k", Parts: map[string]string{"app_id": "ABCDEFGHIJ"}})
	if res.State != Live || res.Severity != "critical" {
		t.Fatalf("got %v %s", res.State, res.Note)
	}
}

func TestGoogleKeyVerdicts(t *testing.T) {
	type tc struct {
		status int
		body   string
		want   State
	}
	cases := []tc{
		{200, `{"models":[{"name":"models/gemini"}]}`, Live},
		{400, `{"error":{"code":400,"message":"API key not valid. Please pass a valid API key.","status":"INVALID_ARGUMENT","details":[{"reason":"API_KEY_INVALID"}]}}`, Dead},
		{403, `{"error":{"code":403,"status":"PERMISSION_DENIED","details":[{"reason":"API_KEY_HTTP_REFERRER_BLOCKED"}]}}`, Harmless},
		{403, `{"error":{"code":403,"status":"PERMISSION_DENIED","details":[{"reason":"API_KEY_SERVICE_BLOCKED"}]}}`, Harmless},
		{403, `{"error":{"code":403,"status":"PERMISSION_DENIED","details":[{"reason":"SERVICE_DISABLED"}]}}`, Unknown},
	}
	for _, c := range cases {
		v := serve(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(c.status); w.Write([]byte(c.body)) })
		got := check(t, v, Target{RuleID: "google-api-key", Secret: "AIzaX"})
		if got.State != c.want {
			t.Errorf("%s: got %v want %v", c.body, got.State, c.want)
		}
		if c.want == Unknown && got.Boost <= 0 {
			t.Errorf("a real unrestricted key should be boosted")
		}
	}
}

func TestStripeRestrictedKeyIsLive(t *testing.T) {
	v := serve(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(403) })
	if got := check(t, v, Target{RuleID: "stripe-key", Secret: "rk_x"}); got.State != Live {
		t.Fatalf("got %v", got.State)
	}
}

func TestAWSWrongSecretIsDead(t *testing.T) {
	v := serve(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
		w.Write([]byte(`<Error><Code>SignatureDoesNotMatch</Code></Error>`))
	})
	got := check(t, v, Target{RuleID: "aws-access-key", Secret: "AKIAXXXXXXXXXXXXXXXX", Parts: map[string]string{"secret_key": "s"}})
	if got.State != Dead {
		t.Fatalf("got %v", got.State)
	}
	tmp := check(t, v, Target{RuleID: "aws-access-key", Secret: "ASIAXXXXXXXXXXXXXXXX", Parts: map[string]string{"secret_key": "s"}})
	if tmp.State != Skip {
		t.Fatalf("temporary key without session token must not be judged, got %v", tmp.State)
	}
}

func TestRateLimitIsUnknownNotDead(t *testing.T) {
	v := serve(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(429) })
	if got := check(t, v, Target{RuleID: "npm-token", Secret: "npm_x"}); got.State != Unknown {
		t.Fatalf("got %v", got.State)
	}
}

func TestAzure403IsNotDead(t *testing.T) {
	v := serve(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(403) })
	got := check(t, v, Target{RuleID: "azure-storage-key", Secret: "AAAA", Parts: map[string]string{"account": "acct"}})
	if got.State == Dead {
		t.Fatal("an Azure 403 is ambiguous and must not drop the key")
	}
}
