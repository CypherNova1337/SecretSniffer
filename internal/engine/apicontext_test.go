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

func TestAPIContextGateway(t *testing.T) {
	key := Rand(Alnum, 40)
	src := `const api="https://ksb1pq7l53.execute-api.us-east-1.amazonaws.com/prod";` +
		`fetch(api+"/v1/accounts/export",{headers:{"x-api-key":"` + key + `"}});fetch(api+"/v1/accounts");` +
		`var img="/static/logo.png";`
	var c *finding.Candidate
	for _, x := range Detect(Chunk{Loc: finding.Location{Source: "https://app.target.tld/static/js/1ab.js"}, Data: []byte(src)}) {
		if x.Secret == key {
			c = x
		}
	}
	if c == nil {
		t.Fatal("key not found")
	}
	if c.Info["api_host"] != "https://ksb1pq7l53.execute-api.us-east-1.amazonaws.com/prod" || c.Info["api_header"] != "x-api-key" {
		t.Fatalf("info %v", c.Info)
	}
	if !strings.Contains(c.Info["api_paths"], "/v1/accounts") || strings.Contains(c.Info["api_paths"], "logo.png") {
		t.Fatalf("paths %q", c.Info["api_paths"])
	}
}

func TestAPIContextFallsBackToOrigin(t *testing.T) {
	key := Rand(Alnum, 40)
	src := `var cfg={baseUrl:location.origin,prodIrelandApiKey:"` + key + `"};get(cfg.baseUrl+"/api/v2/regions");`
	for _, x := range Detect(Chunk{Loc: finding.Location{Source: "https://eu.target.tld/assets/3a8e.js"}, Data: []byte(src)}) {
		if x.Secret == key {
			if x.Info["api_host"] != "https://eu.target.tld" || !strings.Contains(x.Info["api_paths"], "/api/v2/regions") {
				t.Fatalf("info %v", x.Info)
			}
			return
		}
	}
	t.Fatal("key not found")
}

func TestNoAPIContextForLocalFilesWithoutHost(t *testing.T) {
	key := Rand(Alnum, 40)
	for _, x := range Detect(Chunk{Loc: finding.Location{Source: "config.py"}, Data: []byte(`api_key = "` + key + `"`), Local: true}) {
		if x.Info["api_host"] != "" {
			t.Fatalf("unexpected context %v", x.Info)
		}
	}
}

func TestEndToEndAPIKeyProbe(t *testing.T) {
	key := Rand(Alnum, 40)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-api-key") == key && r.URL.Path == "/prod/v1/accounts" {
			w.Write([]byte(`[{"id":1,"name":"Acme"}]`))
			return
		}
		w.WriteHeader(403)
		w.Write([]byte(`{"message":"Forbidden"}`))
	}))
	defer srv.Close()
	v := verify.New(5 * time.Second)
	v.SetRewrite(func(u string) string { i := strings.Index(u[8:], "/"); return srv.URL + u[8+i:] })

	src := `const api="https://ksb1pq7l53.execute-api.us-east-1.amazonaws.com/prod";` +
		`fetch(api+"/v1/accounts",{headers:{"x-api-key":"` + key + `"}});`
	var live []*finding.Finding
	e := New(Options{Verify: true, Verifier: v, MinScore: 50, OnLive: func(f *finding.Finding) { live = append(live, f) }})
	ch := make(chan Chunk, 1)
	ch <- Chunk{Loc: finding.Location{Source: "https://app.target.tld/static/js/1ab.js"}, Data: []byte(src)}
	close(ch)
	e.Run(context.Background(), ch)
	if len(live) != 1 || live[0].Secret != key || live[0].Evidence == nil || !strings.Contains(live[0].Identity, "execute-api") {
		t.Fatalf("expected the gateway key to verify, got %+v", live)
	}
}
