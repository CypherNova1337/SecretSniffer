package rules

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/CypherNova1337/SecretSniffer/internal/finding"
	. "github.com/CypherNova1337/SecretSniffer/internal/testutil"
)

func TestPlaceholderReason(t *testing.T) {
	noise := []string{
		"AKIAIOSFODNN7EXAMPLE",
		"sk_live_xxxxxxxxxxxxxxxxxxxxxxxx",
		"YOUR_API_KEY_HERE",
		"<your-token>",
		"${STRIPE_SECRET}",
		"{{ api_key }}",
		"abcdefghijklmnopqrstuvwxyz",
		"1234567890123456",
		"aaaaaaaaaaaaaaaaaaaa",
		"my_secret_token_value",
		"replace_with_real_key",
	}
	for _, s := range noise {
		if PlaceholderReason(s) == "" {
			t.Errorf("expected %q to be flagged as a placeholder", s)
		}
	}
	real := []string{
		J("sk_live_", Rand(Alnum, 24)),
		Rand(B64, 40),
		Rand(Hex, 32),
	}
	for _, s := range real {
		if why := PlaceholderReason(s); why != "" {
			t.Errorf("random value %q flagged: %s", s, why)
		}
	}
}

func TestEntropy(t *testing.T) {
	if e := Entropy("aaaaaaaa"); e != 0 {
		t.Errorf("entropy of a constant string = %v", e)
	}
	if e := Entropy(Rand(Alnum, 64)); e < 5 {
		t.Errorf("entropy of random base62 = %v, want >= 5", e)
	}
}

func TestAWSAccountID(t *testing.T) {
	// Published example from the research that documented the encoding.
	id, ok := awsAccountID("ASIAY34FZKBOKMUTVV7A")
	if !ok || id != "609629065308" {
		t.Fatalf("got %q %v, want 609629065308", id, ok)
	}
}

func cand(rule, secret string, groups ...string) *finding.Candidate {
	if len(groups) == 0 {
		groups = []string{secret}
	}
	return &finding.Candidate{RuleID: rule, Secret: secret, Groups: groups, Score: ByID(rule).Base}
}

func TestPrivateKeyParses(t *testing.T) {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}))
	// As it would appear inside a JS or JSON string.
	escaped := strings.ReplaceAll(strings.TrimSpace(p), "\n", `\n`)
	c := cand("private-key", escaped, escaped, "RSA PRIVATE KEY")
	checkPrivateKey(c)
	if c.Drop != "" || c.Info["key_type"] != "RSA 2048-bit private key" {
		t.Fatalf("drop=%q info=%v", c.Drop, c.Info)
	}

	ek, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(ek)
	p8 := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	c = cand("private-key", p8, p8, "PRIVATE KEY")
	checkPrivateKey(c)
	if c.Drop != "" || !strings.Contains(c.Info["key_type"], "P-256") {
		t.Fatalf("pkcs8 ec: drop=%q info=%v", c.Drop, c.Info)
	}
}

func TestPrivateKeyTruncatedIsDropped(t *testing.T) {
	fake := "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----"
	c := cand("private-key", fake, fake, "RSA PRIVATE KEY")
	checkPrivateKey(c)
	if c.Drop == "" {
		t.Fatal("truncated documentation key should be dropped")
	}
}

func jwt(payload map[string]any) string {
	enc := base64.RawURLEncoding
	h, _ := json.Marshal(map[string]string{"alg": "HS256", "typ": "JWT"})
	p, _ := json.Marshal(payload)
	return enc.EncodeToString(h) + "." + enc.EncodeToString(p) + "." + Rand(Alnum, 43)
}

func TestJWT(t *testing.T) {
	Now = func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }
	defer func() { Now = time.Now }()

	expired := cand("jwt", jwt(map[string]any{"sub": "1", "exp": 1600000000}))
	checkJWT(expired)
	if !strings.HasPrefix(expired.Drop, "expired") {
		t.Errorf("expired token: drop=%q", expired.Drop)
	}

	anon := cand("jwt", jwt(map[string]any{"iss": "supabase", "role": "anon", "ref": "abcd"}))
	checkJWT(anon)
	if anon.Drop == "" {
		t.Error("supabase anon key should be dropped as public")
	}

	svc := cand("jwt", jwt(map[string]any{"iss": "supabase", "role": "service_role", "ref": "abcdefgh"}))
	checkJWT(svc)
	if svc.Drop != "" || svc.Severity != Critical || svc.Parts["supabase_ref"] != "abcdefgh" {
		t.Errorf("service_role: drop=%q sev=%q parts=%v", svc.Drop, svc.Severity, svc.Parts)
	}
}

func TestURIChecks(t *testing.T) {
	r := ByID("database-uri")
	cases := map[string]bool{ // uri -> should survive
		"postgres://app:" + Rand(Alnum, 20) + "@db.prod.internal.corp.net:5432/app": true,
		"postgres://postgres:postgres@localhost:5432/db":                            false,
		"mysql://user:password@example.com/db":                                      false,
		"mongodb+srv://admin:${MONGO_PASS}@cluster0.mongodb.net":                    false,
		"redis://default:" + Rand(Alnum, 16) + "@redis:6379":                        true, // survives, but scored down
	}
	for uri, keep := range cases {
		m := r.Re.FindStringSubmatch(uri)
		if m == nil {
			if keep {
				t.Errorf("no match for %q", uri)
			}
			continue
		}
		c := &finding.Candidate{RuleID: r.ID, Secret: m[r.Group], Groups: m, Score: r.Base}
		checkURI(c)
		if (c.Drop == "") != keep {
			t.Errorf("%q: drop=%q, want keep=%v", uri, c.Drop, keep)
		}
	}
}

func TestGenericFilters(t *testing.T) {
	r := ByID("generic-secret")
	noise := []string{
		`const passwordLabel = "Enter your password"`,
		`apiKey: process.env.API_KEY`,
		`"api_key": "API_KEY"`,
		`token_url: "https://auth.example.org/token"`,
		`secret = "integrity-check"`,
		`password: "required"`,
		`csrf_token = "` + Rand(Alnum, 32) + `"`,
		`apiKey = "` + "12345678-1234-1234-1234-123456789abc" + `"`,
		`client_secret: "short"`,
		`tokenExpiry = "1700000000000"`,
	}
	for _, line := range noise {
		m := r.Re.FindStringSubmatch(line)
		if m == nil {
			continue // not matching at all is also fine
		}
		c := &finding.Candidate{RuleID: r.ID, Secret: m[r.Group], Groups: m, Score: r.Base}
		if why := PlaceholderReason(c.Secret); why != "" {
			continue
		}
		checkGeneric(c)
		if c.Drop == "" {
			t.Errorf("noise survived: %s (score %d)", line, c.Score)
		}
	}
	good := `client_secret = "` + Rand(Alnum, 40) + `"`
	m := r.Re.FindStringSubmatch(good)
	if m == nil {
		t.Fatal("no match for real-looking secret")
	}
	c := &finding.Candidate{RuleID: r.ID, Secret: m[r.Group], Groups: m, Score: r.Base}
	checkGeneric(c)
	if c.Drop != "" || c.Score < 50 {
		t.Errorf("real secret: drop=%q score=%d", c.Drop, c.Score)
	}
}

func TestDiscordBotStructure(t *testing.T) {
	id := base64.RawStdEncoding.EncodeToString([]byte("123456789012345678"))
	good := cand("discord-bot-token", id+"."+Rand(Alnum, 6)+"."+Rand(Alnum, 30))
	checkDiscordBot(good)
	if good.Drop != "" {
		t.Errorf("valid structure dropped: %s", good.Drop)
	}
	bad := cand("discord-bot-token", "MaterialDesignIconsPackage.module.someVeryLongFunctionNameHere")
	checkDiscordBot(bad)
	if bad.Drop == "" {
		t.Error("minified identifier chain should not pass as a Discord token")
	}
}

func TestRulesCompileAndHaveIDs(t *testing.T) {
	for _, r := range All() {
		if r.ID == "" || r.Name == "" || r.Re == nil || r.Severity == "" {
			t.Errorf("incomplete rule: %+v", r)
		}
		if r.Group >= r.Re.NumSubexp()+1 {
			t.Errorf("%s: group %d out of range", r.ID, r.Group)
		}
	}
}
