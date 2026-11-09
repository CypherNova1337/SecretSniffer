package source

import (
	"net/url"
	"regexp"
	"strings"
)

// Modern front ends ship a small entry script and load the rest of the app
// on demand. The chunk names live in build manifests and runtime maps rather
// than in <script> tags, so a crawler that only follows tags sees a fraction
// of the code - usually not the admin and internal routes. chunkRefs reads
// those manifests and maps.

const maxChunkRefs = 3000

var (
	// Next.js: "/_next/" root (with optional basePath) and static/... chunk names.
	nextRoot   = regexp.MustCompile(`(?:https?://[^"'\s/]+)?(/(?:[A-Za-z0-9_\-./]*/)?_next/)static/`)
	nextStatic = regexp.MustCompile(`["'\x60(,\s](static/[A-Za-z0-9_\-./\[\]%@~]+?\.js)["'\x60),\\]`)

	// webpack (CRA, Angular, Vue CLI, custom): prefix + id/name + sep + {id:hash}[id] + suffix
	webpackMap = regexp.MustCompile(`(?:"([^"\n]{0,200})"\s*\+\s*)?(\(\s*\{[^{}]*\}\s*\[\s*[\w$]+\s*\]\s*\|\|\s*[\w$]+\s*\)|[\w$]+)\s*\+\s*"([^"\n]{0,20})"\s*\+\s*\{([^{}]+)\}\s*\[\s*[\w$]+\s*\]\s*\+\s*"([^"\n]{0,40}\.js)"`)
	mapEntry   = regexp.MustCompile(`(?:"([^"]+)"|'([^']+)'|([\w$]+))\s*:\s*"([^"]+)"`)
	publicPath = regexp.MustCompile(`[\w$]\.p\s*=\s*"([^"]*)"`)

	// Vite / Rollup / esbuild: relative dynamic imports and preload dep lists.
	relImport = regexp.MustCompile(`["'\x60]((?:\./|\.\./)[A-Za-z0-9_\-./@~]+\.m?js)["'\x60]`)
	assetsRef = regexp.MustCompile(`["'\x60]((?:assets|_nuxt|build|dist|js|static/js)/[A-Za-z0-9_\-./@~]+\.m?js)["'\x60]`)
)

// chunkRefs returns absolute URLs of lazily loaded scripts referenced by body,
// which was fetched from base.
func chunkRefs(body []byte, base *url.URL) []string {
	seen := map[string]bool{}
	var out []string
	add := func(ref string, against *url.URL) {
		if len(out) >= maxChunkRefs {
			return
		}
		u, err := against.Parse(ref)
		if err != nil || u.Host == "" {
			return
		}
		u.Fragment = ""
		s := u.String()
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	origin := &url.URL{Scheme: base.Scheme, Host: base.Host, Path: "/"}

	// Next.js
	root := ""
	if i := strings.Index(base.Path, "/_next/"); i >= 0 {
		root = base.Path[:i+len("/_next/")]
	} else if m := nextRoot.FindSubmatch(body); m != nil {
		root = string(m[1])
	}
	if root != "" {
		nr := &url.URL{Scheme: base.Scheme, Host: base.Host, Path: root}
		for _, m := range nextStatic.FindAllSubmatch(body, -1) {
			add(string(m[1]), nr)
		}
	}

	// webpack runtime chunk maps
	pp := ""
	if m := publicPath.FindSubmatch(body); m != nil {
		pp = string(m[1])
	}
	ppBase := base // "auto"/relative public path: relative to the runtime script
	if strings.HasPrefix(pp, "/") || strings.HasPrefix(pp, "http") {
		if u, err := base.Parse(pp); err == nil {
			ppBase = u
		}
	} else if pp != "" && pp != "auto" {
		if u, err := base.Parse(pp); err == nil {
			ppBase = u
		}
	}
	for _, m := range webpackMap.FindAllSubmatch(body, -1) {
		prefix, idExpr, sep, hashes, suffix := string(m[1]), string(m[2]), string(m[3]), string(m[4]), string(m[5])
		names := map[string]string{}
		if strings.HasPrefix(idExpr, "(") {
			if i, j := strings.IndexByte(idExpr, '{'), strings.IndexByte(idExpr, '}'); i >= 0 && j > i {
				names = parseMap(idExpr[i+1 : j])
			}
		}
		for id, hash := range parseMap(hashes) {
			name := id
			if n, ok := names[id]; ok {
				name = n
			}
			add(prefix+name+sep+hash+suffix, ppBase)
		}
	}

	// Vite and friends
	for _, m := range relImport.FindAllSubmatch(body, -1) {
		add(string(m[1]), base)
	}
	for _, m := range assetsRef.FindAllSubmatch(body, -1) {
		add(string(m[1]), origin)
	}
	return out
}

func parseMap(body string) map[string]string {
	out := map[string]string{}
	for _, m := range mapEntry.FindAllStringSubmatch(body, -1) {
		k := m[1] + m[2] + m[3]
		out[k] = m[4]
	}
	return out
}
