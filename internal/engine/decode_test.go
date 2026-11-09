package engine

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/CypherNova1337/SecretSniffer/internal/finding"
	. "github.com/CypherNova1337/SecretSniffer/internal/testutil"
)

func findSecret(t *testing.T, src, secret string) *finding.Candidate {
	t.Helper()
	for _, c := range Detect(Chunk{Loc: finding.Location{Source: "app.js"}, Data: []byte(src)}) {
		if c.Secret == secret && c.Drop == "" {
			return c
		}
	}
	return nil
}

func TestDecodesHiddenSecrets(t *testing.T) {
	key := J("sk_", "live_", Rand(Alnum, 24))
	codes := make([]string, len(key))
	for i := range key {
		codes[i] = fmt.Sprint(int(key[i]))
	}
	var esc strings.Builder
	for i := range key {
		fmt.Fprintf(&esc, `\x%02x`, key[i])
	}
	cases := map[string]string{
		"string concatenation": `var k="` + key[:6] + `"+"` + key[6:15] + `" + '` + key[15:] + `';`,
		"array join":           `const k=["` + key[:5] + `","` + key[5:] + `"].join("");`,
		"base64":               `const k=atob("` + base64.StdEncoding.EncodeToString([]byte(key)) + `");`,
		"hex encoding":         `k=Buffer.from("` + hex.EncodeToString([]byte(key)) + `","hex").toString()`,
		"escape sequences":     `var k="` + esc.String() + `";`,
		"char codes":           `var k=String.fromCharCode(` + strings.Join(codes, ",") + `);`,
	}
	for how, src := range cases {
		c := findSecret(t, "line one\n"+src, key)
		if c == nil {
			t.Errorf("%s: secret not found in %s", how, src)
			continue
		}
		if c.Info["hidden_by"] != how {
			t.Errorf("%s: hidden_by = %q", how, c.Info["hidden_by"])
		}
		if c.Loc.Line != 2 {
			t.Errorf("%s: line = %d, want 2", how, c.Loc.Line)
		}
	}
}

func TestDecodesKubernetesSecret(t *testing.T) {
	pass := "Pr0d-" + Rand(Alnum, 14) + "!"
	manifest := "apiVersion: v1\nkind: Secret\ndata:\n  db_password: " + base64.StdEncoding.EncodeToString([]byte(pass)) + "\n"
	if c := findSecret(t, manifest, pass); c == nil {
		t.Fatal("base64 value in a Kubernetes Secret not decoded")
	}
}

func TestDecodingDoesNotInventNoise(t *testing.T) {
	// Binary-looking base64 (images, random keys) and plain hex hashes must not
	// produce views.
	src := `var img="` + base64.StdEncoding.EncodeToString([]byte(Rand("\x00\x01\x02\xff", 64))) + `";` +
		`var h="` + Rand(Hex, 64) + `";var a="hello"+" world";`
	for _, v := range decodedViews([]byte(src)) {
		if v.how != "string concatenation" {
			t.Errorf("unexpected view %s: %q", v.how, v.text)
		}
	}
}

func TestDocCommentPenalty(t *testing.T) {
	v := Rand(Alnum, 40)
	code := Detect(Chunk{Loc: finding.Location{Source: "a.js"}, Data: []byte(`apiKey = "` + v + `"`)})
	doc := Detect(Chunk{Loc: finding.Location{Source: "a.js"}, Data: []byte(" * apiKey = \"" + v + "\"")})
	if len(code) == 0 || len(doc) == 0 || doc[0].Score >= code[0].Score {
		t.Fatalf("doc comment should score lower: code=%v doc=%v", code, doc)
	}
}
