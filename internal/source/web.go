// Package source turns targets (URLs, files, git repositories) into chunks of
// content for the engine.
package source

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/CypherNova1337/SecretSniffer/internal/engine"
	"github.com/CypherNova1337/SecretSniffer/internal/finding"
)

// WebOptions controls fetching.
type WebOptions struct {
	Client      *http.Client
	Headers     map[string]string
	Concurrency int
	RatePerSec  int   // 0 = unlimited
	MaxBytes    int64 // per response
	ThirdParty  bool  // also fetch scripts from public CDNs and analytics vendors
	NoMaps      bool  // don't fetch or probe source maps
	MaxDepth    int   // how far to follow script references from a page
	Logf        func(format string, a ...any)
}

// Library and analytics hosts. Their scripts are the same for every site and
// only produce noise (and the occasional public demo key).
var thirdParty = []string{
	"googletagmanager.com", "google-analytics.com", "gstatic.com", "googleapis.com",
	"google.com", "googlesyndication.com", "doubleclick.net", "cdnjs.cloudflare.com",
	"cdn.jsdelivr.net", "unpkg.com", "code.jquery.com", "ajax.aspnetcdn.com",
	"connect.facebook.net", "static.cloudflareinsights.com", "js.stripe.com",
	"cdn.segment.com", "static.hotjar.com", "widget.intercom.io", "js.intercomcdn.com",
	"browser.sentry-cdn.com", "js-agent.newrelic.com", "bam.nr-data.net",
	"maxcdn.bootstrapcdn.com", "stackpath.bootstrapcdn.com", "polyfill.io",
	"cdn.optimizely.com", "snap.licdn.com", "platform.twitter.com", "static.ads-twitter.com",
	"cdn.cookielaw.org", "consent.cookiebot.com", "js.hs-scripts.com", "js.hsforms.net",
	"cdn.amplitude.com", "cdn.mxpnl.com", "cdn.heapanalytics.com", "script.crazyegg.com",
	"www.youtube.com", "player.vimeo.com", "challenges.cloudflare.com", "hcaptcha.com",
	"recaptcha.net", "cdn.shopify.com", "assets.adobedtm.com", "cdn.datatables.net",
}

func isThirdParty(host string) bool {
	host = strings.ToLower(host)
	for _, h := range thirdParty {
		if host == h || strings.HasSuffix(host, "."+h) {
			return true
		}
	}
	return false
}

var (
	scriptSrc  = regexp.MustCompile(`(?i)<script[^>]+src\s*=\s*["']?([^"'\s>]+)`)
	mapComment = regexp.MustCompile(`(?m)[#@]\s*sourceMappingURL=([^\s'"*]+)`)
	jsRef      = regexp.MustCompile(`["'\x60]((?:https?:)?/[^"'\x60\s<>()]{1,300}?\.js)(?:\?[^"'\x60\s]*)?["'\x60]`)
)

type webTask struct {
	url   string
	depth int
	kind  string // "page", "js", "map", "probe-map"
}

type web struct {
	opt  WebOptions
	out  chan<- engine.Chunk
	seen sync.Map
	sem  chan struct{}
	wg   sync.WaitGroup
	tick <-chan time.Time
}

// Web fetches each URL, scans it, and follows the scripts and source maps it
// references. It returns when everything reachable has been processed.
func Web(ctx context.Context, urls []string, opt WebOptions, out chan<- engine.Chunk) {
	if opt.Concurrency <= 0 {
		opt.Concurrency = 20
	}
	if opt.MaxBytes <= 0 {
		opt.MaxBytes = 15 << 20
	}
	if opt.MaxDepth <= 0 {
		opt.MaxDepth = 2
	}
	w := &web{opt: opt, out: out, sem: make(chan struct{}, opt.Concurrency)}
	if opt.RatePerSec > 0 {
		t := time.NewTicker(time.Second / time.Duration(opt.RatePerSec))
		defer t.Stop()
		w.tick = t.C
	}
	for _, u := range urls {
		w.enqueue(ctx, webTask{url: u, kind: "page"})
	}
	w.wg.Wait()
}

func (w *web) enqueue(ctx context.Context, t webTask) {
	key := strings.SplitN(t.url, "#", 2)[0]
	if _, dup := w.seen.LoadOrStore(key, true); dup {
		return
	}
	w.wg.Add(1)
	go func() {
		defer w.wg.Done()
		select {
		case w.sem <- struct{}{}:
		case <-ctx.Done():
			return
		}
		defer func() { <-w.sem }()
		if w.tick != nil {
			select {
			case <-w.tick:
			case <-ctx.Done():
				return
			}
		}
		w.process(ctx, t)
	}()
}

func (w *web) fetch(ctx context.Context, u string) (body []byte, ctype string, hdr http.Header, ok bool) {
	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return nil, "", nil, false
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36")
	for k, v := range w.opt.Headers {
		req.Header.Set(k, v)
	}
	resp, err := w.opt.Client.Do(req)
	if err != nil {
		w.log("fetch %s: %v", u, err)
		return nil, "", nil, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, "", nil, false
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, w.opt.MaxBytes))
	if err != nil {
		return nil, "", nil, false
	}
	return b, strings.ToLower(resp.Header.Get("Content-Type")), resp.Header, true
}

func (w *web) process(ctx context.Context, t webTask) {
	body, ctype, hdr, ok := w.fetch(ctx, t.url)
	if !ok || len(body) == 0 {
		return
	}
	if t.kind == "map" || t.kind == "probe-map" {
		w.emitSourceMap(t.url, body)
		return
	}
	isHTML := strings.Contains(ctype, "html") || (t.kind == "page" && looksHTML(body))
	if isHTML && strings.Contains(ctype, "javascript") {
		isHTML = false
	}
	// A soft-404 HTML page served for a .js URL is not worth scanning twice.
	if t.kind == "js" && isHTML {
		return
	}
	w.emit(t.url, body)

	base, err := url.Parse(t.url)
	if err != nil {
		return
	}
	if isHTML {
		for _, m := range scriptSrc.FindAllSubmatch(body, -1) {
			w.follow(ctx, base, string(m[1]), t.depth+1, "js")
		}
		return
	}
	if t.depth < w.opt.MaxDepth {
		for _, m := range jsRef.FindAllSubmatch(body, 200) {
			ref, err := base.Parse(string(m[1]))
			if err != nil || !sameSite(ref.Host, base.Host) {
				continue
			}
			w.follow(ctx, base, string(m[1]), t.depth+1, "js")
		}
	}
	if w.opt.NoMaps {
		return
	}
	declared := hdr.Get("SourceMap")
	if declared == "" {
		declared = hdr.Get("X-SourceMap")
	}
	if declared == "" {
		if ms := mapComment.FindAllSubmatch(body, -1); len(ms) > 0 {
			declared = string(ms[len(ms)-1][1])
		}
	}
	switch {
	case strings.HasPrefix(declared, "data:"):
		if i := strings.Index(declared, "base64,"); i >= 0 {
			if raw, err := base64.StdEncoding.DecodeString(declared[i+7:]); err == nil {
				w.emitSourceMap(t.url+"#inline-map", raw)
			}
		}
	case declared != "":
		w.follow(ctx, base, declared, t.depth, "map")
	case strings.HasSuffix(base.Path, ".js"):
		// Maps are often deployed without being referenced.
		w.follow(ctx, base, base.Path+".map", t.depth, "probe-map")
	}
}

func (w *web) follow(ctx context.Context, base *url.URL, ref string, depth int, kind string) {
	u, err := base.Parse(ref)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return
	}
	if !w.opt.ThirdParty && isThirdParty(u.Hostname()) {
		return
	}
	if depth > w.opt.MaxDepth+1 {
		return
	}
	w.enqueue(ctx, webTask{url: u.String(), depth: depth, kind: kind})
}

func (w *web) emit(src string, data []byte) {
	w.out <- engine.Chunk{Loc: finding.Location{Source: src}, Data: data}
}

type sourceMap struct {
	Sources        []string  `json:"sources"`
	SourcesContent []*string `json:"sourcesContent"`
}

func (w *web) emitSourceMap(src string, body []byte) {
	for _, c := range sourceMapChunks(src, body) {
		w.out <- c
	}
}

// sourceMapChunks returns each original source file embedded in a map as its
// own chunk, so findings point at the real file and line rather than column
// 90,000 of a minified bundle.
func sourceMapChunks(src string, body []byte) []engine.Chunk {
	var sm sourceMap
	if json.Unmarshal(body, &sm) != nil {
		return nil
	}
	var out []engine.Chunk
	for i, content := range sm.SourcesContent {
		if content == nil || *content == "" {
			continue
		}
		name := "source-" + strconv.Itoa(i)
		if i < len(sm.Sources) {
			name = sm.Sources[i]
		}
		// Third-party packages bundled into the app are not the app's secrets.
		if strings.Contains(name, "node_modules/") || strings.Contains(name, "webpack/bootstrap") {
			continue
		}
		out = append(out, engine.Chunk{Loc: finding.Location{Source: src + " -> " + name}, Data: []byte(*content)})
	}
	return out
}

func looksHTML(b []byte) bool {
	s := strings.TrimSpace(string(b[:min(len(b), 512)]))
	s = strings.ToLower(s)
	return strings.HasPrefix(s, "<!doctype html") || strings.HasPrefix(s, "<html") || strings.Contains(s, "<head")
}

// sameSite compares the last two labels of each host - close enough to keep
// script discovery on the target without pulling in the whole internet.
func sameSite(a, b string) bool {
	return registrable(a) == registrable(b)
}

func registrable(h string) string {
	if i := strings.IndexByte(h, ':'); i >= 0 {
		h = h[:i]
	}
	parts := strings.Split(strings.ToLower(h), ".")
	if len(parts) <= 2 {
		return strings.Join(parts, ".")
	}
	return strings.Join(parts[len(parts)-2:], ".")
}

func (w *web) log(format string, a ...any) {
	if w.opt.Logf != nil {
		w.opt.Logf(format, a...)
	}
}
