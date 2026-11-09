package source

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/CypherNova1337/SecretSniffer/internal/engine"
	. "github.com/CypherNova1337/SecretSniffer/internal/testutil"
)

func TestWaybackFindsRemovedKey(t *testing.T) {
	key := J("sk_", "live_", Rand(Alnum, 24))
	var fetched []string
	index := func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("url") != "target.tld/*" || r.URL.Query().Get("collapse") != "digest" {
			t.Errorf("bad index query %s", r.URL.RawQuery)
		}
		w.Write([]byte(`[["timestamp","original","mimetype"],
["20210304050607","https://target.tld/static/app.js","application/javascript"],
["20220101000000","https://target.tld/logo.png","image/png"],
["20230505000000","https://target.tld/config.json","application/json"]]`))
	}
	// A plain handler: ServeMux would "clean" the embedded https:// away.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/cdx/search/cdx" {
			index(w, r)
			return
		}
		fetched = append(fetched, r.URL.Path)
		if strings.Contains(r.URL.Path, "20210304050607id_/https://target.tld/static/app.js") {
			w.Write([]byte(`var stripe="` + key + `";`))
			return
		}
		w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()
	old := WaybackBase
	WaybackBase = srv.URL
	defer func() { WaybackBase = old }()

	chunks := collect(func(out chan<- engine.Chunk) {
		Wayback(context.Background(), []string{"target.tld"}, WaybackOptions{Client: &http.Client{Timeout: 5 * time.Second}}, out)
	})
	for _, p := range fetched {
		if strings.Contains(p, "logo.png") {
			t.Error("images should not be fetched from the archive")
		}
	}
	for _, c := range chunks {
		for _, cand := range engine.Detect(c) {
			if cand.Secret == key {
				if cand.Loc.Archived != "2021-03-04" {
					t.Errorf("archived date = %q", cand.Loc.Archived)
				}
				return
			}
		}
	}
	t.Fatal("key from archived JS not found")
}
