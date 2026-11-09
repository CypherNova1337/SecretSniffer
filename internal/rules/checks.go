package rules

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/CypherNova1337/SecretSniffer/internal/finding"
)

// Now is overridable in tests.
var Now = time.Now

func group(c *finding.Candidate, i int) string {
	if i < len(c.Groups) {
		return c.Groups[i]
	}
	return ""
}

func setInfo(c *finding.Candidate, k, v string) {
	if c.Info == nil {
		c.Info = map[string]string{}
	}
	c.Info[k] = v
}

func setPart(c *finding.Candidate, k, v string) {
	if c.Parts == nil {
		c.Parts = map[string]string{}
	}
	c.Parts[k] = v
}

func because(c *finding.Candidate, delta int, why string) {
	c.Score += delta
	c.Reasons = append(c.Reasons, why)
}

// ------------------------------------------------------------------ AWS

func validAWSSecret(v string) bool {
	return Entropy(v) >= 4.0 && charClasses(v) >= 3 && PlaceholderReason(v) == ""
}

func validHexSecret(v string) bool {
	return Entropy(v) >= 3.3 && !LowDiversity(v)
}

// awsAccountID recovers the 12-digit account ID encoded in an access key ID.
func awsAccountID(keyID string) (string, bool) {
	if len(keyID) != 20 {
		return "", false
	}
	raw, err := base32.StdEncoding.DecodeString(keyID[4:])
	if err != nil || len(raw) < 6 {
		return "", false
	}
	var z uint64
	for _, b := range raw[:6] {
		z = z<<8 | uint64(b)
	}
	id := (z & 0x7fffffffff80) >> 7
	return fmt.Sprintf("%012d", id), true
}

func checkAWS(c *finding.Candidate) {
	if id, ok := awsAccountID(c.Secret); ok {
		setInfo(c, "account_id", id)
	}
	if strings.HasPrefix(c.Secret, "ASIA") {
		setInfo(c, "type", "temporary (STS) credentials")
	}
	if c.Parts["secret_key"] == "" {
		c.Reasons = append(c.Reasons, "no secret access key found next to the key ID")
		return
	}
	because(c, 45, "paired with a secret access key")
	if strings.HasPrefix(c.Secret, "ASIA") && c.Parts["session_token"] == "" {
		c.Reasons = append(c.Reasons, "temporary key without its session token")
	}
}

// ---------------------------------------------------------- Google / Azure

func checkGCPServiceAccount(c *finding.Candidate) {
	pk := c.Parts["private_key"]
	if pk == "" {
		return
	}
	key := strings.ReplaceAll(pk, `\n`, "\n")
	block, _ := pem.Decode([]byte(key))
	if block == nil {
		c.Drop = "service account private key does not decode"
		return
	}
	if _, err := x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
		c.Drop = "service account private key does not parse"
		return
	}
	// Report the client email as the visible secret identifier; the key itself
	// stays in Parts so verification and JSON output have it.
	c.Secret = c.Parts["client_email"]
	if c.Secret == "" {
		c.Secret = "service account (no client_email)"
	}
	because(c, 50, "contains a private key that parses")
}

func checkAzureStorage(c *finding.Candidate) {
	setPart(c, "account", strings.ToLower(group(c, 1)))
	if _, err := base64.StdEncoding.DecodeString(c.Secret); err != nil {
		c.Drop = "account key is not valid base64"
		return
	}
	if c.Parts["account"] == "devstoreaccount1" {
		c.Drop = "Azure storage emulator well-known key"
	}
}

// ------------------------------------------------------------- packages

var pypiScope = regexp.MustCompile(`"projects"\s*:\s*\[([^\]]*)\]`)

func checkPyPI(c *finding.Candidate) {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(c.Secret[5:], "="))
	if err != nil || len(raw) < 40 {
		c.Drop = "does not decode as a PyPI macaroon"
		return
	}
	because(c, 10, "decodes as a PyPI macaroon")
	if m := pypiScope.FindSubmatch(raw); m != nil {
		setInfo(c, "scope", "projects: "+strings.ReplaceAll(string(m[1]), `"`, ""))
	} else {
		setInfo(c, "scope", "entire account")
	}
}

// ------------------------------------------------------------ payments

func checkStripe(c *finding.Candidate) {
	if strings.Contains(c.Secret, "_test_") {
		c.Severity = Low
		setInfo(c, "mode", "test mode")
		because(c, -15, "test-mode key (no real money)")
	} else {
		setInfo(c, "mode", "live mode")
	}
	if strings.HasPrefix(c.Secret, "rk_") {
		setInfo(c, "type", "restricted key")
	}
}

// --------------------------------------------------------------- discord

func checkDiscordBot(c *finding.Candidate) {
	first := c.Secret[:strings.IndexByte(c.Secret, '.')]
	raw, err := base64.RawStdEncoding.DecodeString(strings.TrimRight(first, "="))
	if err != nil {
		raw, err = base64.RawURLEncoding.DecodeString(strings.TrimRight(first, "="))
	}
	id := string(raw)
	if err != nil || len(id) < 17 || len(id) > 20 || strings.Trim(id, "0123456789") != "" {
		c.Drop = "first segment does not decode to a Discord user ID"
		return
	}
	setInfo(c, "bot_user_id", id)
	because(c, 20, "first segment decodes to a Discord user ID")
}

func checkCloudinary(c *finding.Candidate) {
	setPart(c, "api_key", group(c, 1))
	setPart(c, "cloud", group(c, 3))
}

// ----------------------------------------------------------- private key

func checkPrivateKey(c *finding.Candidate) {
	if len(c.Secret) > 20000 {
		c.Drop = "BEGIN/END markers too far apart to be one key"
		return
	}
	text := c.Secret
	text = strings.NewReplacer(`\\n`, "\n", `\n`, "\n", `\r`, "", "\r", "").Replace(text)
	// Strip string-concatenation residue and indentation from code.
	var lines []string
	for _, ln := range strings.Split(text, "\n") {
		ln = stripCodeQuoting(ln)
		if ln != "" {
			lines = append(lines, ln)
		}
	}
	text = strings.Join(lines, "\n") + "\n"
	label := group(c, 1)

	if strings.Contains(label, "PGP") {
		body := pgpBody(lines)
		if raw, err := base64.StdEncoding.DecodeString(body); err != nil || len(raw) < 100 {
			c.Drop = "PGP block does not decode (truncated or placeholder)"
			return
		}
		setInfo(c, "key_type", "PGP private key")
		because(c, 30, "PGP private key block decodes")
		return
	}

	block, _ := pem.Decode([]byte(text))
	if block == nil {
		c.Drop = "PEM body does not decode (truncated or placeholder)"
		return
	}
	encrypted := block.Headers["Proc-Type"] != "" && strings.Contains(block.Headers["Proc-Type"], "ENCRYPTED")
	var desc string
	switch block.Type {
	case "RSA PRIVATE KEY":
		if encrypted {
			desc = "RSA private key"
			break
		}
		k, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			c.Drop = "does not parse as an RSA key"
			return
		}
		desc = fmt.Sprintf("RSA %d-bit private key", k.N.BitLen())
	case "EC PRIVATE KEY":
		if encrypted {
			desc = "EC private key"
			break
		}
		k, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			c.Drop = "does not parse as an EC key"
			return
		}
		desc = "EC " + k.Curve.Params().Name + " private key"
	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			c.Drop = "does not parse as a PKCS#8 key"
			return
		}
		switch kk := k.(type) {
		case *rsa.PrivateKey:
			desc = fmt.Sprintf("RSA %d-bit private key", kk.N.BitLen())
		case *ecdsa.PrivateKey:
			desc = "EC " + kk.Curve.Params().Name + " private key"
		case ed25519.PrivateKey:
			desc = "Ed25519 private key"
		default:
			desc = "PKCS#8 private key"
		}
	case "ENCRYPTED PRIVATE KEY":
		encrypted = true
		desc = "PKCS#8 private key"
	case "OPENSSH PRIVATE KEY":
		kt, cipher, ok := parseOpenSSH(block.Bytes)
		if !ok {
			c.Drop = "does not parse as an OpenSSH key"
			return
		}
		desc = "OpenSSH " + kt + " private key"
		encrypted = cipher != "none"
	case "DSA PRIVATE KEY":
		if len(block.Bytes) < 300 {
			c.Drop = "DSA key body too short to be real"
			return
		}
		desc = "DSA private key"
	default:
		c.Drop = "unrecognised PEM block " + block.Type
		return
	}
	setInfo(c, "key_type", desc)
	if encrypted {
		setInfo(c, "encrypted", "yes - needs a passphrase")
		c.Severity = Medium
		because(c, 10, "real "+desc+", but passphrase-encrypted")
		return
	}
	because(c, 35, "parses as a real, unencrypted "+desc)
}

// stripCodeQuoting removes string quoting and concatenation around one line
// of a key embedded in source ("...\n" +), without touching base64 '+'.
func stripCodeQuoting(ln string) string {
	ln = strings.TrimSpace(ln)
	for i := 0; i < 3; i++ {
		ln = strings.TrimSpace(strings.TrimRight(ln, ";,"))
		if strings.HasSuffix(ln, "+") {
			if t := strings.TrimSpace(ln[:len(ln)-1]); strings.HasSuffix(t, `"`) || strings.HasSuffix(t, "'") {
				ln = t
			}
		}
		if strings.HasPrefix(ln, "+") {
			if t := strings.TrimSpace(ln[1:]); strings.HasPrefix(t, `"`) || strings.HasPrefix(t, "'") {
				ln = t
			}
		}
		ln = strings.Trim(ln, "\"'`")
	}
	return strings.TrimSpace(ln)
}

func pgpBody(lines []string) string {
	var b strings.Builder
	inBody := false
	for _, ln := range lines {
		switch {
		case strings.HasPrefix(ln, "-----"):
			inBody = false
			if strings.HasPrefix(ln, "-----BEGIN") {
				inBody = true
			}
		case !inBody:
		case strings.Contains(ln, ": "): // armor header
		case strings.HasPrefix(ln, "="): // CRC line
		default:
			b.WriteString(ln)
		}
	}
	return b.String()
}

func parseOpenSSH(b []byte) (keyType, cipher string, ok bool) {
	const magic = "openssh-key-v1\x00"
	if !bytes.HasPrefix(b, []byte(magic)) {
		return "", "", false
	}
	b = b[len(magic):]
	next := func() ([]byte, bool) {
		if len(b) < 4 {
			return nil, false
		}
		n := binary.BigEndian.Uint32(b)
		if uint32(len(b)-4) < n {
			return nil, false
		}
		v := b[4 : 4+n]
		b = b[4+n:]
		return v, true
	}
	ci, ok1 := next()
	_, ok2 := next() // kdf name
	_, ok3 := next() // kdf options
	if !ok1 || !ok2 || !ok3 || len(b) < 4 {
		return "", "", false
	}
	b = b[4:] // number of keys
	pub, ok4 := next()
	if !ok4 || len(pub) < 4 {
		return "", "", false
	}
	n := binary.BigEndian.Uint32(pub)
	if int(n)+4 > len(pub) {
		return "", "", false
	}
	return string(pub[4 : 4+n]), string(ci), true
}

// ------------------------------------------------------------------- JWT

func decodeSegment(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
}

func checkJWT(c *finding.Candidate) {
	parts := strings.Split(c.Secret, ".")
	hdrRaw, err1 := decodeSegment(parts[0])
	payRaw, err2 := decodeSegment(parts[1])
	var hdr, pay map[string]any
	if err1 != nil || err2 != nil || json.Unmarshal(hdrRaw, &hdr) != nil || json.Unmarshal(payRaw, &pay) != nil {
		c.Drop = "does not decode as a JWT"
		return
	}
	if alg, _ := hdr["alg"].(string); alg != "" {
		setInfo(c, "alg", alg)
	}
	iss, _ := pay["iss"].(string)
	role, _ := pay["role"].(string)
	if iss != "" {
		setInfo(c, "iss", iss)
	}
	if role != "" {
		setInfo(c, "role", role)
	}
	if exp, ok := pay["exp"].(float64); ok {
		t := time.Unix(int64(exp), 0).UTC()
		if t.Before(Now()) {
			c.Drop = "expired " + t.Format("2006-01-02")
			return
		}
		setInfo(c, "expires", t.Format("2006-01-02"))
		because(c, 10, "not expired")
	} else {
		because(c, 15, "has no expiry")
	}

	switch {
	case iss == "supabase-demo":
		c.Drop = "Supabase local-development demo key"
	case role == "anon" || role == "anonymous" || role == "public":
		c.Drop = "anonymous/public role key - meant to be shipped to clients"
	case strings.Contains(iss, "supabase") && role == "service_role":
		c.Severity = Critical
		if ref, _ := pay["ref"].(string); ref != "" {
			setPart(c, "supabase_ref", ref)
		}
		because(c, 30, "Supabase service_role key - bypasses row level security")
	case strings.HasPrefix(iss, "https://securetoken.google.com/"):
		because(c, -10, "Firebase user ID token (short-lived session)")
	}
}

// ------------------------------------------------------------------- URIs

var defaultPasswords = map[string]bool{
	"password": true, "pass": true, "passwd": true, "pwd": true, "secret": true,
	"root": true, "admin": true, "postgres": true, "mysql": true, "guest": true,
	"user": true, "test": true, "changeme": true, "123456": true, "1234": true,
	"12345": true, "toor": true, "default": true, "redis": true, "mongo": true,
	"example": true, "demo": true, "dev": true, "local": true, "pw": true,
}

var localHost = regexp.MustCompile(`(?i)^(localhost|127\.\d+\.\d+\.\d+|0\.0\.0\.0|::1|host\.docker\.internal|[a-z0-9_-]+)$`)
var exampleHost = regexp.MustCompile(`(?i)(^|\.)(example\.(com|org|net)|domain\.com|host\.com|yourdomain\.[a-z]+|mydomain\.[a-z]+|server\.com|hostname|test\.com|foo\.com|bar\.com)$`)
var templatePart = regexp.MustCompile(`^[:$%{<\[]|[}>\]]$`)

func checkURI(c *finding.Candidate) {
	user, pass, host := group(c, 2), group(c, 3), group(c, 4)
	if c.RuleID == "url-credentials" {
		c.Secret = group(c, 0)
	}
	setPart(c, "user", user)
	setPart(c, "host", host)
	low := strings.ToLower(pass)
	switch {
	case templatePart.MatchString(pass) || templatePart.MatchString(user):
		c.Drop = "templated credentials, not literal values"
	case defaultPasswords[low] || strings.EqualFold(pass, user):
		c.Drop = "default or placeholder password \"" + pass + "\""
	case PlaceholderReason(pass) != "":
		c.Drop = "password " + PlaceholderReason(pass)
	case exampleHost.MatchString(host):
		c.Drop = "points at an example/documentation host"
	case len(pass) < 4:
		c.Drop = "password too short to be real"
	}
	if c.Drop != "" {
		return
	}
	if localHost.MatchString(host) {
		because(c, -30, "points at a local or container-internal host ("+host+")")
	}
	if Entropy(pass) >= 3.0 && len(pass) >= 10 {
		because(c, 15, "strong password")
	}
}

func checkBasicAuth(c *finding.Candidate) {
	raw, err := base64.StdEncoding.DecodeString(c.Secret)
	if err != nil {
		c.Drop = "Basic auth value is not valid base64"
		return
	}
	s := string(raw)
	i := strings.IndexByte(s, ':')
	if i <= 0 || strconv.QuoteToASCII(s) != `"`+s+`"` {
		c.Drop = "does not decode to user:password"
		return
	}
	user, pass := s[:i], s[i+1:]
	setInfo(c, "decoded_user", user)
	switch {
	case defaultPasswords[strings.ToLower(pass)] || strings.EqualFold(pass, user):
		c.Drop = "default or placeholder password"
	case PlaceholderReason(s) != "":
		c.Drop = "decoded credentials " + PlaceholderReason(s)
	case len(pass) < 4:
		c.Drop = "password too short to be real"
	default:
		because(c, 15, "decodes to user:password")
	}
}

// ---------------------------------------------------------------- generic

var metaSuffix = regexp.MustCompile(`(?i)(url|uri|endpoint|path|file|filename|name|label|field|type|length|len|policy|placeholder|hint|regex|pattern|min|max|count|header|param|id|prefix|format|input|error|message|msg|text|title|mode|expiry|expires|ttl|timeout|enabled|required|visible|reset|confirm|strength|storage|cookie|ref|key_id)$`)
var publicName = regexp.MustCompile(`(?i)(public|publishable|pub_?key|site_?key|recaptcha|captcha|csrf|xsrf|nonce|tokenizer|token_?type|sentry|dsn|analytics|tracking|measurement|gtm|pixel)`)
var strongName = regexp.MustCompile(`(?i)(client_?secret|secret_?key|api_?key|apikey|private_?key|access_?key|auth_?key|signing|master|admin)`)
var passName = regexp.MustCompile(`(?i)(passw|pwd)`)

func checkGeneric(c *finding.Candidate) {
	name, val := group(c, 1), c.Secret
	setInfo(c, "variable", name)
	isPass := passName.MatchString(name)
	switch {
	case metaSuffix.MatchString(name):
		c.Drop = "variable holds metadata about a secret, not the secret (" + name + ")"
	case publicName.MatchString(name):
		c.Drop = "public-by-design or per-session value (" + name + ")"
	case IsCodeReference(val):
		c.Drop = "value is a reference to another variable or config, not a literal"
	case propPathRe.MatchString(val):
		c.Drop = "value is a property path, not a secret"
	case strings.Contains(val, "://") || pathLikeRe.MatchString(val):
		c.Drop = "value is a URL or file path"
	case uuidRe.MatchString(val):
		c.Drop = "value is a UUID - usually an identifier"
	case hashPrefixRe.MatchString(val):
		c.Drop = "value is a subresource-integrity hash"
	case strings.Trim(val, "0123456789") == "":
		c.Drop = "value is all digits (ID, timestamp or length)"
	case wordsOnlyRe.MatchString(val) || camelIdentRe.MatchString(val):
		c.Drop = "value is plain words or an identifier, not a secret"
	case strings.EqualFold(val, name):
		c.Drop = "value equals its own variable name"
	}
	if c.Drop != "" {
		return
	}
	e := Entropy(val)
	if isPass {
		if charClasses(val) < 2 {
			c.Drop = "password uses a single character class - likely a label"
			return
		}
		c.Score = 45
		if charClasses(val) >= 3 {
			because(c, 10, "password mixes 3+ character classes")
		}
		return
	}
	if len(val) < 16 {
		c.Drop = "too short for a generated key"
		return
	}
	if e < 3.5 {
		c.Drop = fmt.Sprintf("entropy %.1f is too low for a generated key", e)
		return
	}
	switch {
	case e >= 4.5:
		because(c, 15, fmt.Sprintf("high entropy (%.1f bits/char)", e))
	case e >= 4.0:
		because(c, 10, fmt.Sprintf("good entropy (%.1f bits/char)", e))
	}
	if strongName.MatchString(name) {
		because(c, 5, "assigned to a strongly named variable ("+name+")")
	}
}
