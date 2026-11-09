package source

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CypherNova1337/SecretSniffer/internal/engine"
	. "github.com/CypherNova1337/SecretSniffer/internal/testutil"
)

func collect(f func(out chan<- engine.Chunk)) []engine.Chunk {
	ch := make(chan engine.Chunk, 64)
	go func() { f(ch); close(ch) }()
	var out []engine.Chunk
	for c := range ch {
		out = append(out, c)
	}
	return out
}

func TestGitFindsDeletedSecret(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dir := t.TempDir()
	key := J("sk_", "live_", Rand(Alnum, 24))
	gitc := func(args ...string) {
		cmd := exec.Command("git", append([]string{"-C", dir, "-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false"}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
	}
	gitc("init", "-q")
	os.WriteFile(filepath.Join(dir, "app.py"), []byte("import os\n\nSTRIPE = \""+key+"\"\n"), 0o644)
	gitc("add", ".")
	gitc("commit", "-qm", "add billing")
	os.WriteFile(filepath.Join(dir, "app.py"), []byte("import os\n\nSTRIPE = os.environ['STRIPE']\n"), 0o644)
	gitc("commit", "-qam", "move key to env")

	chunks := collect(func(out chan<- engine.Chunk) {
		if err := Git(context.Background(), dir, 1<<20, out, nil); err != nil {
			t.Error(err)
		}
	})
	var found bool
	for _, c := range chunks {
		for _, cand := range engine.Detect(c) {
			if cand.Secret == key {
				found = true
				if cand.Loc.File != "app.py" || cand.Loc.Line != 3 || cand.Loc.Commit == "" {
					t.Errorf("bad location %+v", cand.Loc)
				}
			}
		}
	}
	if !found {
		t.Fatal("secret removed in a later commit was not found")
	}
}

func TestWebFollowsScriptsAndProbesMaps(t *testing.T) {
	key := J("sk_", "live_", Rand(Alnum, 24))
	original := "// src/billing.ts\nexport const STRIPE = \"" + key + "\";\n"
	sm, _ := json.Marshal(map[string]any{
		"version":        3,
		"sources":        []string{"webpack://app/src/billing.ts", "webpack://app/node_modules/lib/index.js"},
		"sourcesContent": []string{original, "var x = 1;"},
	})
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><head><script src="/static/main.js"></script><script src="https://www.googletagmanager.com/gtm.js"></script></head></html>`))
	})
	mux.HandleFunc("/static/main.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.Write([]byte(`!function(){var a=1}();`)) // minified, no map comment
	})
	mux.HandleFunc("/static/main.js.map", func(w http.ResponseWriter, r *http.Request) {
		w.Write(sm)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	chunks := collect(func(out chan<- engine.Chunk) {
		Web(context.Background(), []string{srv.URL + "/"}, WebOptions{Client: &http.Client{Timeout: 5 * time.Second}}, out)
	})
	var sources []string
	var found bool
	for _, c := range chunks {
		sources = append(sources, c.Loc.Source)
		if strings.Contains(c.Loc.Source, "node_modules") {
			t.Errorf("bundled third-party source should be skipped: %s", c.Loc.Source)
		}
		if strings.Contains(c.Loc.Source, "googletagmanager") {
			t.Errorf("analytics script should not be fetched")
		}
		for _, cand := range engine.Detect(c) {
			if cand.Secret == key && strings.HasSuffix(c.Loc.Source, "src/billing.ts") && cand.Loc.Line == 2 {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("secret in unreferenced source map not found; scanned %v", sources)
	}
}
