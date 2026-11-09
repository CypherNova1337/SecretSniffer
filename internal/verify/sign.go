package verify

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"sort"
	"strings"
	"time"
)

func hmacSHA256(key []byte, data string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(data))
	return m.Sum(nil)
}

func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// sigV4 returns the Authorization header value for an AWS Signature V4
// request. headers must include host and x-amz-date, lower-cased.
func sigV4(method, path, query string, headers map[string]string, body, accessKey, secretKey, region, service string, t time.Time) string {
	amzDate := t.UTC().Format("20060102T150405Z")
	date := amzDate[:8]

	names := make([]string, 0, len(headers))
	for k := range headers {
		names = append(names, k)
	}
	sort.Strings(names)
	var canonHeaders strings.Builder
	for _, k := range names {
		canonHeaders.WriteString(k + ":" + strings.TrimSpace(headers[k]) + "\n")
	}
	signed := strings.Join(names, ";")

	canonical := strings.Join([]string{
		method, path, query, canonHeaders.String(), signed, sha256Hex(body),
	}, "\n")
	scope := date + "/" + region + "/" + service + "/aws4_request"
	toSign := "AWS4-HMAC-SHA256\n" + amzDate + "\n" + scope + "\n" + sha256Hex(canonical)

	k := hmacSHA256([]byte("AWS4"+secretKey), date)
	k = hmacSHA256(k, region)
	k = hmacSHA256(k, service)
	k = hmacSHA256(k, "aws4_request")
	sig := hex.EncodeToString(hmacSHA256(k, toSign))

	return "AWS4-HMAC-SHA256 Credential=" + accessKey + "/" + scope +
		", SignedHeaders=" + signed + ", Signature=" + sig
}

// azureSharedKey signs a GET with no body for the Azure Storage Shared Key
// scheme. canonResource is e.g. "/account/\ncomp:list".
func azureSharedKey(account, key, msDate, msVersion, canonResource string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return "", err
	}
	toSign := "GET\n" + strings.Repeat("\n", 11) +
		"x-ms-date:" + msDate + "\nx-ms-version:" + msVersion + "\n" + canonResource
	return "SharedKey " + account + ":" + base64.StdEncoding.EncodeToString(hmacSHA256(raw, toSign)), nil
}

// googleAssertion builds the signed JWT a service account exchanges for an
// access token.
func googleAssertion(email, pemKey, aud string, now time.Time) (string, error) {
	block, _ := pem.Decode([]byte(pemKey))
	if block == nil {
		return "", errors.New("bad PEM")
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return "", err
	}
	rk, ok := k.(*rsa.PrivateKey)
	if !ok {
		return "", errors.New("not an RSA key")
	}
	enc := base64.RawURLEncoding
	hdr, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT"})
	claims, _ := json.Marshal(map[string]any{
		"iss":   email,
		"scope": "https://www.googleapis.com/auth/cloud-platform.read-only",
		"aud":   aud,
		"iat":   now.Unix(),
		"exp":   now.Add(10 * time.Minute).Unix(),
	})
	unsigned := enc.EncodeToString(hdr) + "." + enc.EncodeToString(claims)
	sum := sha256.Sum256([]byte(unsigned))
	sig, err := rsa.SignPKCS1v15(rand.Reader, rk, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	return unsigned + "." + enc.EncodeToString(sig), nil
}
