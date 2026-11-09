package engine

import (
	"net/url"
	"regexp"
	"strings"

	"github.com/CypherNova1337/SecretSniffer/internal/finding"
)

// Keys found in web bundles are mostly for the site's own APIs, not for a
// vendor with a known check. What makes them testable is context: the API
// host the bundle talks to, the endpoint paths it calls, and the header the
// key travels in. apiContext recovers those from the content around a key.

const apiWindow = 6000

var (
	// Hosts that are unambiguously API front doors, most specific first.
	apiHostRes = []struct {
		re     *regexp.Regexp
		header string // default key header for this gateway type
	}{
		{regexp.MustCompile(`https://[a-z0-9]+\.execute-api\.[a-z0-9-]+\.amazonaws\.com(?:/[A-Za-z0-9_\-]+)?`), "x-api-key"},
		{regexp.MustCompile(`https://[a-z0-9]+\.appsync-api\.[a-z0-9-]+\.amazonaws\.com/graphql`), "x-api-key"},
		{regexp.MustCompile(`https://[a-z0-9]+\.lambda-url\.[a-z0-9-]+\.on\.aws`), "x-api-key"},
		{regexp.MustCompile(`https://[a-z0-9-]+\.azure-api\.net(?:/[A-Za-z0-9_\-]+)?`), "Ocp-Apim-Subscription-Key"},
		{regexp.MustCompile(`https://[a-z0-9-]+\.azurewebsites\.net/api`), "x-functions-key"},
		{regexp.MustCompile(`https://[a-z0-9-]+\.(?:apigee\.net|apigee\.io)(?:/[A-Za-z0-9_\-]+)?`), "x-api-key"},
		{regexp.MustCompile(`https://[a-z0-9-]+-[a-z0-9]+\.[a-z]+\.run\.app`), "x-api-key"},
		{regexp.MustCompile(`https://[a-z0-9-]+\.cloudfunctions\.net`), "x-api-key"},
		{regexp.MustCompile(`https://(?:api|gateway|apigw|services?)[a-z0-9-]*\.[a-z0-9.-]+\.[a-z]{2,}(?:/(?:api|v\d+))?`), ""},
		{regexp.MustCompile(`https://[a-z0-9.-]+\.[a-z]{2,}/(?:api|v\d+)(?:/v\d+)?`), ""},
	}
	// Endpoint paths as they appear in client code: "/v1/accounts", "/api/users".
	apiPathRe = regexp.MustCompile(`["'\x60](/(?:api|v\d+|rest|graphql|services?|internal|public|prod|dev)?/?[A-Za-z0-9_\-./]{2,120})["'\x60?]`)
	// Header names a key can be assigned to directly.
	headerNameRe = regexp.MustCompile(`(?i)^(x-api-key|api-key|apikey|x-apikey|ocp-apim-subscription-key|x-functions-key|x-auth-token|x-access-token|authorization)$`)
	paramRe      = regexp.MustCompile(`[:{}$<>\[\]]|\$\{`)
)

type apiCtx struct {
	host   string
	paths  []string
	header string
}

// apiContext looks around [s,e) for the API a key belongs to. origin is the
// scheme://host the chunk was fetched from (empty for local files); when the
// bundle only uses relative paths, the API is the origin itself.
func apiContext(data []byte, s, e int, varName, origin string) *apiCtx {
	lo, hi := s-apiWindow, e+apiWindow
	if lo < 0 {
		lo = 0
	}
	if hi > len(data) {
		hi = len(data)
	}
	win := data[lo:hi]
	ctx := &apiCtx{}

	best := -1
	for _, h := range apiHostRes {
		for _, m := range h.re.FindAllIndex(win, -1) {
			d := abs(lo + m[0] - s)
			if best < 0 || d < best {
				best = d
				ctx.host = strings.TrimRight(string(win[m[0]:m[1]]), "/")
				ctx.header = h.header
			}
		}
		if ctx.host != "" {
			break // most specific gateway type wins
		}
	}

	seen := map[string]bool{}
	for _, m := range apiPathRe.FindAllSubmatch(win, -1) {
		p := string(m[1])
		if seen[p] || len(ctx.paths) >= 8 || paramRe.MatchString(p) || isAssetPath(p) {
			continue
		}
		seen[p] = true
		ctx.paths = append(ctx.paths, p)
	}
	if ctx.host == "" {
		if origin == "" || len(ctx.paths) == 0 {
			return nil // nothing to test against
		}
		ctx.host = origin
	}
	if headerNameRe.MatchString(varName) {
		ctx.header = varName
	}
	if ctx.header == "" {
		ctx.header = "x-api-key"
	}
	return ctx
}

func isAssetPath(p string) bool {
	low := strings.ToLower(p)
	for _, ext := range []string{".js", ".css", ".png", ".jpg", ".jpeg", ".svg", ".gif", ".ico", ".woff", ".woff2", ".ttf", ".map", ".html", ".json", ".txt", ".webp"} {
		if strings.HasSuffix(low, ext) {
			return true
		}
	}
	return strings.HasPrefix(low, "/static/") || strings.HasPrefix(low, "/assets/") || strings.HasPrefix(low, "/_next/") || p == "/"
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

// originOf returns scheme://host for web sources.
func originOf(loc finding.Location) string {
	if loc.Archived != "" {
		return "" // archived copies may point at hosts that moved
	}
	u, err := url.Parse(strings.SplitN(loc.Source, " ", 2)[0])
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

// attachAPI records the API context on a candidate as Info entries the
// probe and the report both use.
func attachAPI(c *finding.Candidate, ctx *apiCtx) {
	if ctx == nil {
		return
	}
	if c.Info == nil {
		c.Info = map[string]string{}
	}
	c.Info["api_host"] = ctx.host
	c.Info["api_header"] = ctx.header
	if len(ctx.paths) > 0 {
		c.Info["api_paths"] = strings.Join(ctx.paths, " ")
	}
}
