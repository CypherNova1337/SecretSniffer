package verify

import (
	"context"
	"fmt"
	"math/rand"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/CypherNova1337/SecretSniffer/internal/finding"
)

// The probe tests keys for the site's own APIs, which have no known check.
// It asks the API the same question three ways - with no key, with a
// made-up key of the same shape, and with the real key - and only calls the
// key accepted when the real one gets a different answer from both. That
// works on any API without knowing its error format.
//
// It only ever sends GET, only to the API host and endpoint paths found next
// to the key, and skips paths whose names suggest they do something.

const (
	probeMaxPaths = 3
	probeSpacing  = 350 * time.Millisecond
)

var unsafePath = regexp.MustCompile(`(?i)(export|download|delete|remove|destroy|purge|send|create|new|add|upload|import|reset|pay|charge|refund|transfer|withdraw|invite|logout|signout|cancel|update|edit|save|submit|approve|reject|revoke|disable|enable|activate|deactivate|purchase|order|checkout|subscribe|publish|sync|trigger|run|exec|write|notify|email|mail|sms|otp|verify|confirm|register|signup|login|signin|password|token|webhook|callback|batch|bulk|job|task|report)`)

var volatileRe = regexp.MustCompile(`[0-9a-fA-F]{8,}|\d+`)

func init() {
	funcs["generic-secret"] = probeAPI
	funcs["basic-auth-header"] = probeAPI
}

type answer struct {
	status int
	sig    string
	snip   string
}

func signature(r *Response) answer {
	body := string(r.Body)
	if len(body) > 600 {
		body = body[:600]
	}
	return answer{
		status: r.Status,
		sig:    fmt.Sprintf("%d|%s", r.Status, volatileRe.ReplaceAllString(body, "#")),
		snip:   snippetOf(r.Body, 120),
	}
}

// fakeLike returns a random value with the same character classes and
// length as s, so it passes any format check the API does.
func fakeLike(s string) string {
	const (
		lo = "abcdefghijklmnopqrstuvwxyz"
		up = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		dg = "0123456789"
	)
	b := []byte(s)
	for i, c := range b {
		switch {
		case c >= 'a' && c <= 'z':
			b[i] = lo[rand.Intn(len(lo))]
		case c >= 'A' && c <= 'Z':
			b[i] = up[rand.Intn(len(up))]
		case c >= '0' && c <= '9':
			b[i] = dg[rand.Intn(len(dg))]
		}
	}
	if string(b) == s && len(b) > 0 { // all symbols: flip one character
		b[0] ^= 1
	}
	return string(b)
}

// probeURLs builds the URLs to ask: the API root, then up to a few safe
// endpoint paths seen next to the key.
func probeURLs(host, paths string) []string {
	base, err := url.Parse(host)
	if err != nil {
		return nil
	}
	urls := []string{strings.TrimRight(host, "/") + "/"}
	n := 0
	for _, p := range strings.Fields(paths) {
		if n == probeMaxPaths {
			break
		}
		if unsafePath.MatchString(p) {
			continue
		}
		var u string
		if base.Path != "" && base.Path != "/" && strings.HasPrefix(p, base.Path) {
			u = base.Scheme + "://" + base.Host + p
		} else {
			u = strings.TrimRight(host, "/") + p
		}
		urls = append(urls, u)
		n++
	}
	return urls
}

func probeAPI(ctx context.Context, h *HTTP, t Target) Result {
	host := t.Hints["api_host"]
	if host == "" {
		return Result{State: Skip, Note: "no API host found nearby to test it against"}
	}
	header := t.Hints["api_header"]
	value, fake := t.Secret, fakeLike(t.Secret)
	switch {
	case t.RuleID == "basic-auth-header":
		header, value, fake = "Authorization", "Basic "+value, "Basic "+fake
	case strings.EqualFold(header, "authorization"):
		value, fake = "Bearer "+value, "Bearer "+fake
	}

	ask := func(u string, hdr map[string]string) (answer, error) {
		select {
		case <-time.After(probeSpacing):
		case <-ctx.Done():
			return answer{}, ctx.Err()
		}
		r, err := h.Do(ctx, "GET", u, hdr, "")
		if err != nil {
			return answer{}, err
		}
		return signature(r), nil
	}

	var lastErr error
	for _, u := range probeURLs(host, t.Hints["api_paths"]) {
		none, err := ask(u, nil)
		if err != nil {
			lastErr = err
			continue
		}
		bogus, err := ask(u, map[string]string{header: fake})
		if err != nil {
			lastErr = err
			continue
		}
		real, err := ask(u, map[string]string{header: value})
		if err != nil {
			lastErr = err
			continue
		}
		summary := fmt.Sprintf("GET %s - no key: %d, fake key: %d, this key: %d", u, none.status, bogus.status, real.status)
		ev := &finding.Evidence{
			Command:  curlFor(exchange{method: "GET", url: u, headers: map[string]string{header: value}}),
			Request:  "GET " + u,
			Status:   real.status,
			Response: real.snip,
			Time:     time.Now().UTC().Format(time.RFC3339),
		}
		switch {
		case real.status >= 500:
			continue
		case real.sig != bogus.sig && real.sig != none.sig:
			return Result{State: Live, Severity: "high",
				Identity: "accepted by " + host + " (" + header + " header)",
				Access:   []string{summary},
				Evidence: ev}
		case real.sig == bogus.sig && bogus.sig != none.sig:
			return Result{State: Dead, Note: "the API rejects it exactly like a made-up key (" + summary + ")"}
		}
	}
	if lastErr != nil {
		return unknownErr(lastErr)
	}
	return Result{State: Unknown, Note: "the API at " + host + " answered the same with or without the key"}
}
