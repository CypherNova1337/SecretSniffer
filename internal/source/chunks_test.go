package source

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/CypherNova1337/SecretSniffer/internal/engine"
	. "github.com/CypherNova1337/SecretSniffer/internal/testutil"
)

func refsFor(t *testing.T, base, body string) map[string]bool {
	t.Helper()
	u, _ := url.Parse(base)
	got := map[string]bool{}
	for _, r := range chunkRefs([]byte(body), u) {
		got[r] = true
	}
	return got
}

func want(t *testing.T, got map[string]bool, urls ...string) {
	t.Helper()
	for _, u := range urls {
		if !got[u] {
			t.Errorf("missing %s; got %v", u, got)
		}
	}
}

func TestCRARuntime(t *testing.T) {
	body := `!function(e){...;o.p="/",o.u=function(e){return"static/js/"+e+"."+{12:"a1b2c3d4",345:"e5f6a7b8"}[e]+".chunk.js"}}([]);`
	got := refsFor(t, "https://app.target.tld/static/js/runtime-main.js", body)
	want(t, got,
		"https://app.target.tld/static/js/12.a1b2c3d4.chunk.js",
		"https://app.target.tld/static/js/345.e5f6a7b8.chunk.js")
}

func TestWebpackNamedChunks(t *testing.T) {
	body := `r.p="/assets/";r.u=e=>"js/"+({101:"admin",202:"billing"}[e]||e)+"."+{101:"aaaa1111",202:"bbbb2222",303:"cccc3333"}[e]+".js";`
	got := refsFor(t, "https://target.tld/assets/runtime.js", body)
	want(t, got,
		"https://target.tld/assets/js/admin.aaaa1111.js",
		"https://target.tld/assets/js/billing.bbbb2222.js",
		"https://target.tld/assets/js/303.cccc3333.js")
}

func TestAngularAutoPublicPath(t *testing.T) {
	body := `__webpack_require__.u=e=>e+"."+{"src_app_admin_module_ts":"9f8e7d6c"}[e]+".js";`
	got := refsFor(t, "https://target.tld/app/runtime.abc.js", body)
	want(t, got, "https://target.tld/app/src_app_admin_module_ts.9f8e7d6c.js")
}

func TestNextBuildManifest(t *testing.T) {
	body := `self.__BUILD_MANIFEST={__rewrites:{},"/":["static/chunks/pages/index-1a2b.js"],"/admin/users":["static/chunks/pages/admin/users-3c4d.js"],"/post/[id]":["static/chunks/pages/post/[id]-5e6f.js"]};`
	got := refsFor(t, "https://target.tld/_next/static/BUILDID/_buildManifest.js", body)
	want(t, got,
		"https://target.tld/_next/static/chunks/pages/index-1a2b.js",
		"https://target.tld/_next/static/chunks/pages/admin/users-3c4d.js")
}

func TestNextAppRouterHTML(t *testing.T) {
	html := `<script src="/shop/_next/static/chunks/main-app.js"></script><script>self.__next_f.push([1,"2:I[\"static/chunks/app/dashboard/page-77aa.js\"]"])</script>`
	got := refsFor(t, "https://target.tld/shop", html)
	want(t, got, "https://target.tld/shop/_next/static/chunks/app/dashboard/page-77aa.js")
}

func TestViteImports(t *testing.T) {
	body := `const __vite__mapDeps=(i,m=__vite__mapDeps,d=(m.f||(m.f=["assets/Settings-Dk2s.js","assets/vendor-x9.js"])))=>i.map(i=>d[i]);const A=()=>import("./Admin-B7c1.js");`
	got := refsFor(t, "https://target.tld/assets/index-Ab12.js", body)
	want(t, got,
		"https://target.tld/assets/Settings-Dk2s.js",
		"https://target.tld/assets/Admin-B7c1.js")
}

func TestCrawlReachesLazyChunk(t *testing.T) {
	key := J("sk_", "live_", Rand(Alnum, 24))
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" { // SPA fallback: unknown paths get index.html
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte("<html>app</html>"))
			return
		}
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><script src="/static/js/runtime.js"></script></html>`))
	})
	mux.HandleFunc("/static/js/runtime.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.Write([]byte(`o.p="/";o.u=function(e){return"static/js/"+e+"."+{7:"deadbeef"}[e]+".chunk.js"};`))
	})
	mux.HandleFunc("/static/js/7.deadbeef.chunk.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.Write([]byte(`(self.webpackChunk=self.webpackChunk||[]).push([[7],{9:function(){var s="` + key + `"}}]);`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	chunks := collect(func(out chan<- engine.Chunk) {
		Web(context.Background(), []string{srv.URL + "/"}, WebOptions{Client: &http.Client{Timeout: 5 * time.Second}, NoMaps: true}, out)
	})
	for _, c := range chunks {
		if strings.Contains(c.Loc.Source, "7.deadbeef.chunk.js") {
			for _, cand := range engine.Detect(c) {
				if cand.Secret == key {
					return
				}
			}
		}
	}
	t.Fatal("secret in a lazily loaded chunk was not found")
}
