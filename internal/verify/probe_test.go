package verify

import (
	"net/http"
	"strings"
	"sync"
	"testing"
)

const realKey = "Rk3yRealValue0123456789abcdefGHIJ"

// apiGateway behaves like AWS API Gateway with a usage-plan key: anything
// without the right key is 403 Forbidden; the right key gets past the key
// check (403 Missing Authentication Token on unknown routes, 200 on real ones).
func apiGateway(seen *[]string, mu *sync.Mutex) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		*seen = append(*seen, r.URL.Path)
		mu.Unlock()
		if r.Method != "GET" {
			w.WriteHeader(405)
			return
		}
		if r.Header.Get("x-api-key") != realKey {
			w.WriteHeader(403)
			w.Write([]byte(`{"message":"Forbidden"}`))
			return
		}
		if r.URL.Path == "/prod/v1/accounts" {
			w.Write([]byte(`{"accounts":[{"id":1}]}`))
			return
		}
		w.WriteHeader(403)
		w.Write([]byte(`{"message":"Missing Authentication Token"}`))
	}
}

func TestProbeAcceptsRealKey(t *testing.T) {
	var seen []string
	var mu sync.Mutex
	v := serve(t, apiGateway(&seen, &mu))
	res := check(t, v, Target{RuleID: "generic-secret", Secret: realKey, Hints: map[string]string{
		"api_host":   "https://abc123.execute-api.us-east-1.amazonaws.com/prod",
		"api_header": "x-api-key",
		"api_paths":  "/v1/accounts/export /v1/accounts",
	}})
	if res.State != Live || res.Evidence == nil || !strings.Contains(res.Evidence.Command, "x-api-key: "+realKey) {
		t.Fatalf("%+v", res)
	}
	for _, p := range seen {
		if strings.Contains(p, "export") {
			t.Fatal("an export endpoint must never be probed")
		}
	}
}

func TestProbeRejectsFakeLikeKey(t *testing.T) {
	var seen []string
	var mu sync.Mutex
	v := serve(t, apiGateway(&seen, &mu))
	res := check(t, v, Target{RuleID: "generic-secret", Secret: "Wr0ngValue0123456789abcdefGHIJKLM", Hints: map[string]string{
		"api_host": "https://abc123.execute-api.us-east-1.amazonaws.com/prod", "api_header": "x-api-key",
	}})
	// No key and fake key are both 403 Forbidden, so a wrong key can't be
	// told apart from no key: inconclusive, never "live".
	if res.State == Live {
		t.Fatalf("a wrong key must not be reported live: %+v", res)
	}
}

func TestProbeDeadWhenAPIDistinguishesBadKeys(t *testing.T) {
	v := serve(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.Header.Get("x-api-key") {
		case "":
			w.WriteHeader(401)
			w.Write([]byte(`{"error":"missing api key"}`))
		default:
			w.WriteHeader(403)
			w.Write([]byte(`{"error":"invalid api key"}`))
		}
	})
	res := check(t, v, Target{RuleID: "generic-secret", Secret: "Some0ldKey123456789", Hints: map[string]string{"api_host": "https://api.target.tld", "api_header": "x-api-key"}})
	if res.State != Dead {
		t.Fatalf("got %v %s", res.State, res.Note)
	}
}

func TestProbeIgnoresAPIsThatDontCheck(t *testing.T) {
	var calls int
	v := serve(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Write([]byte(`{"status":"ok","time":` + strings.Repeat("1", calls) + `}`))
	})
	res := check(t, v, Target{RuleID: "generic-secret", Secret: "AnyKey123456789012", Hints: map[string]string{"api_host": "https://api.target.tld", "api_header": "x-api-key"}})
	if res.State != Unknown || calls != 3 {
		t.Fatalf("state %v after %d calls (volatile numbers must not look like a difference; no retry)", res.State, calls)
	}
}

func TestProbeSkipsWithoutHost(t *testing.T) {
	v := serve(t, func(w http.ResponseWriter, r *http.Request) { t.Error("no request expected") })
	if res := check(t, v, Target{RuleID: "generic-secret", Secret: "k"}); res.State != Skip {
		t.Fatalf("got %v", res.State)
	}
}

func TestFakeLikeKeepsShape(t *testing.T) {
	s := "AbC-123_xyz.9"
	f := fakeLike(s)
	if f == s || len(f) != len(s) || f[3] != '-' || f[7] != '_' || f[11] != '.' {
		t.Fatalf("fake %q does not keep the shape of %q", f, s)
	}
}
