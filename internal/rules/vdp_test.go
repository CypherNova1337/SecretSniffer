package rules

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/CypherNova1337/SecretSniffer/internal/finding"
	. "github.com/CypherNova1337/SecretSniffer/internal/testutil"
)

// Noise classes seen on a real VDP run.
func TestVDPNoiseIsDropped(t *testing.T) {
	r := ByID("generic-secret")
	noise := map[string]string{ // line -> the drop reason it must hit
		`password: "forgot-password-module__forgotPasswordForm"`: "plain words",
		`password: "reset-password-module__form___3xYz9"`:        "CSS-module",
		`password:"Unrequired!"`:                                 "plain words",
		`accessToken: "+encodeURIComponent(ae)),Y"`:              "fragment of code",
		`apiToken: "Ab3.getItem(k);x9"`:                          "fragment of code",
		`accessTokenValidation: "无法验证访问令牌"`:                      "non-ASCII",
		`client_secret: "` + Rand(Alnum, 20) + `%^!@%^!@#^"`:     "characters that generated keys",
		`publicLicenseToken: "` + Rand(Alnum, 40) + `"`:          "public-by-design",
	}
	for line, want := range noise {
		m := r.Re.FindStringSubmatch(line)
		if m == nil {
			t.Errorf("pattern no longer matches %s - test is not exercising the filter", line)
			continue
		}
		c := &finding.Candidate{RuleID: r.ID, Secret: m[r.Group], Groups: m, Score: r.Base}
		if why := PlaceholderReason(c.Secret); why != "" {
			t.Errorf("%s: caught by placeholder filter (%s) instead of %q", line, why, want)
			continue
		}
		checkGeneric(c)
		if !strings.Contains(c.Drop, want) {
			t.Errorf("%s: drop = %q, want reason containing %q", line, c.Drop, want)
		}
	}
	for _, rfc := range []string{"2YotnFZFEjr1zCsicMWpAA", "tGzv3JOkF0XG5Qx2TlKWIA"} {
		if PlaceholderReason(rfc) == "" {
			t.Errorf("RFC 6749 example %s not recognised", rfc)
		}
	}
}

func TestRealKeysStillPass(t *testing.T) {
	r := ByID("generic-secret")
	// Real-looking values, including base64 ending in "+=" and a key whose
	// alphabet includes '-' and '_'.
	keep := []string{
		`"x-api-key": "` + Rand(Alnum, 40) + `"`,
		`prodFrankfurtApiKey: "` + Rand(Alnum, 38) + `"`,
		`client_secret = "` + Rand(Alnum, 41) + `+="`,
		`apiKey: "` + Rand(Alnum, 12) + "-" + Rand(Alnum, 12) + "_" + Rand(Alnum, 12) + `"`,
	}
	for _, line := range keep {
		m := r.Re.FindStringSubmatch(line)
		if m == nil {
			t.Errorf("no match: %s", line)
			continue
		}
		c := &finding.Candidate{RuleID: r.ID, Secret: m[r.Group], Groups: m, Score: r.Base}
		checkGeneric(c)
		if c.Drop != "" || c.Score < 50 {
			t.Errorf("real key lost: %s (drop=%q score=%d)", line, c.Drop, c.Score)
		}
	}
}

func TestProdNamedKeyOutranksTestNamed(t *testing.T) {
	r := ByID("generic-secret")
	v := Rand(Alnum, 40)
	score := func(line string) int {
		m := r.Re.FindStringSubmatch(line)
		c := &finding.Candidate{RuleID: r.ID, Secret: m[r.Group], Groups: m, Score: r.Base}
		checkGeneric(c)
		return c.Score
	}
	if score(`prodIrelandApiKey: "`+v+`"`) <= score(`uatIrelandApiKey: "`+v+`"`) {
		t.Error("prod-named key should score above uat-named key")
	}
}

func TestTelerikLicenseJWTDropped(t *testing.T) {
	enc := base64.RawURLEncoding
	h, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "Telerik License Evidence"})
	p, _ := json.Marshal(map[string]any{"type": "kendo-ui", "id": "x"})
	tok := enc.EncodeToString(h) + "." + enc.EncodeToString(p) + "." + Rand(Alnum, 43)
	c := cand("jwt", tok)
	checkJWT(c)
	if c.Drop == "" {
		t.Fatal("Telerik license token should be dropped as public by design")
	}
}
