package engine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/CypherNova1337/SecretSniffer/internal/finding"
	. "github.com/CypherNova1337/SecretSniffer/internal/testutil"
	"github.com/CypherNova1337/SecretSniffer/internal/verify"
)

var (
	awsID     = J("AKIA", Rand(Upper, 16))
	awsSecret = Rand(Alnum, 30) + "/" + Rand(Alnum, 9)
	stripeKey = J("sk_", "live_", Rand(Alnum, 24))
	slackTok  = J("xox", "b-", Rand("0123456789", 10), "-", Rand("0123456789", 13), "-", Rand(Alnum, 24))
	googleKey = J("AI", "za", "Sy", Rand(Alnum, 33))
	twilioSID = J("A", "C", Rand(Hex, 32))
)

// A bundle shaped like real minified output: one real AWS pair, a live
// Stripe key, a revoked Slack token, a public Google Maps key, and the usual
// pile of things regex tools report.
func bundle() string {
	return strings.Join([]string{
		`!function(e){var t={};`,
		`const cfg={region:"us-east-1",accessKeyId:"` + awsID + `",secretAccessKey:"` + awsSecret + `",bucket:"assets"};`,
		`var s="` + stripeKey + `";`,
		`fetch("/api",{headers:{Authorization:"Bearer ` + slackTok + `"}});`,
		`maps.init({key:"` + googleKey + `"});`,
		`// docs: AKIAIOSFODNN7EXAMPLE / wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`,
		`var sid="` + twilioSID + `";`,
		`const passwordLabel="Enter your password",apiKey=process.env.API_KEY,token_url="https://x.io/oauth/token";`,
		`var integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC";`,
		`var stripe_secret="` + stripeKey + `";`, // generic duplicate of the same key
		`}();`,
	}, "\n")
}

// fakeProviders answers like the real APIs for the values above.
func fakeProviders(t *testing.T) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/account": // Stripe
			if strings.Contains(r.Header.Get("Authorization"), "Basic") {
				w.Write([]byte(`{"id":"acct_123","email":"billing@target.tld"}`))
				return
			}
			w.WriteHeader(401)
		case r.URL.Path == "/api/auth.test": // Slack
			w.Write([]byte(`{"ok":false,"error":"token_revoked"}`))
		case strings.HasPrefix(r.URL.Path, "/v1beta/models"): // Google
			w.WriteHeader(403)
			w.Write([]byte(`{"error":{"code":403,"status":"PERMISSION_DENIED","details":[{"reason":"API_KEY_HTTP_REFERRER_BLOCKED"}]}}`))
		case r.URL.Path == "/" && r.Method == "POST": // AWS STS
			if strings.Contains(r.Header.Get("Authorization"), awsID) {
				w.Write([]byte(`<GetCallerIdentityResponse><GetCallerIdentityResult><Arn>arn:aws:iam::123456789012:user/deploy</Arn></GetCallerIdentityResult></GetCallerIdentityResponse>`))
				return
			}
			w.WriteHeader(403)
		default:
			t.Logf("unexpected request %s %s", r.Method, r.URL)
			w.WriteHeader(500)
		}
	}))
}

func run(t *testing.T, verifyOn bool) (live, rest []*finding.Finding, st Stats) {
	srv := fakeProviders(t)
	defer srv.Close()
	v := verify.New(5 * time.Second)
	v.SetRewrite(func(u string) string {
		i := strings.Index(u[8:], "/")
		return srv.URL + u[8+i:]
	})
	liveCh := make(chan *finding.Finding, 16)
	e := New(Options{Verify: verifyOn, Verifier: v, MinScore: 50, OnLive: func(f *finding.Finding) { liveCh <- f }})
	chunks := make(chan Chunk, 1)
	chunks <- Chunk{Loc: finding.Location{Source: "https://target.tld/static/main.js"}, Data: []byte(bundle())}
	close(chunks)
	rest, st = e.Run(context.Background(), chunks)
	close(liveCh)
	for f := range liveCh {
		live = append(live, f)
	}
	return
}

func byRule(fs []*finding.Finding, rule string) *finding.Finding {
	for _, f := range fs {
		if f.RuleID == rule {
			return f
		}
	}
	return nil
}

func TestEndToEndVerified(t *testing.T) {
	live, rest, st := run(t, true)

	aws := byRule(live, "aws-access-key")
	if aws == nil || aws.Parts["secret_key"] != awsSecret || !strings.Contains(aws.Identity, "user/deploy") {
		t.Fatalf("AWS pair not verified correctly: %+v", aws)
	}
	if s := byRule(live, "stripe-key"); s == nil || !strings.Contains(s.Identity, "acct_123") {
		t.Fatalf("Stripe not verified: %+v", s)
	}
	for _, f := range rest {
		if f.Status == finding.Likely {
			t.Errorf("nothing should be left as likely, got %s %q (%v)", f.RuleID, f.Secret, f.Reasons)
		}
	}
	if s := byRule(rest, "slack-token"); s == nil || !strings.Contains(s.Drop, "token_revoked") {
		t.Errorf("revoked Slack token should be dropped as dead: %+v", s)
	}
	if g := byRule(rest, "google-api-key"); g == nil || !strings.Contains(g.Drop, "harmless") {
		t.Errorf("referrer-locked Google key should be dropped as harmless: %+v", g)
	}
	if tw := byRule(rest, "twilio-credentials"); tw == nil || tw.Status != finding.Dropped {
		t.Errorf("Twilio SID alone should be dropped: %+v", tw)
	}
	for _, f := range append(live, rest...) {
		if f.RuleID == "generic-secret" && (f.Secret == stripeKey || f.Secret == awsSecret) {
			t.Errorf("generic match duplicated a vendor-specific finding: %q", f.Secret)
		}
	}
	if st.Verified != 2 {
		t.Errorf("verified = %d, want 2", st.Verified)
	}
	t.Logf("stats: %+v", st)
}

func TestOfflineScoring(t *testing.T) {
	live, rest, _ := run(t, false)
	if len(live) != 0 {
		t.Fatal("nothing can be verified with verification off")
	}
	likely := map[string]bool{}
	for _, f := range rest {
		if f.Status == finding.Likely {
			likely[f.RuleID] = true
		}
	}
	for _, want := range []string{"aws-access-key", "stripe-key", "slack-token"} {
		if !likely[want] {
			t.Errorf("%s should be reported as likely offline", want)
		}
	}
	if likely["google-api-key"] {
		t.Error("unverified Google API key should not clear the threshold")
	}
}

func TestGitLineMapping(t *testing.T) {
	ch := Chunk{
		Loc:   finding.Location{Source: "repo", Commit: "abc", File: "config.py"},
		Data:  []byte("x = 1\nSTRIPE = \"" + stripeKey + "\"\n"),
		Lines: []int{40, 41},
		Local: true,
	}
	cs := Detect(ch)
	if len(cs) == 0 || cs[0].Loc.Line != 41 {
		t.Fatalf("want line 41, got %+v", cs)
	}
}

func TestTestPathPenalty(t *testing.T) {
	data := []byte(`key = "` + stripeKey + `"`)
	prod := Detect(Chunk{Loc: finding.Location{Source: "src/billing.js"}, Data: data, Local: true})
	test := Detect(Chunk{Loc: finding.Location{Source: "src/__tests__/billing.test.js"}, Data: data, Local: true})
	if len(prod) == 0 || len(test) == 0 || test[0].Score >= prod[0].Score {
		t.Fatalf("test path should score lower: prod=%v test=%v", prod, test)
	}
}
