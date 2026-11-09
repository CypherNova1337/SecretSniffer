// SecretSniffer finds secrets in web assets, files and git history, then
// proves which ones are real before showing them to you.
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"time"

	"github.com/CypherNova1337/SecretSniffer/internal/engine"
	"github.com/CypherNova1337/SecretSniffer/internal/finding"
	"github.com/CypherNova1337/SecretSniffer/internal/report"
	"github.com/CypherNova1337/SecretSniffer/internal/source"
	"github.com/CypherNova1337/SecretSniffer/internal/verify"
)

const version = "1.0.0"

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ", ") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

func main() {
	var (
		list        = flag.String("l", "", "File of targets (URLs, domains, paths), one per line")
		gitRepos    multi
		headers     multi
		noVerify    = flag.Bool("no-verify", false, "Don't contact providers; score findings offline only")
		noEnrich    = flag.Bool("no-enrich", false, "Only confirm keys are live; skip the read-only calls that map what they can access")
		showDropped = flag.Bool("show-dropped", false, "Also print what was discarded and why")
		minScore    = flag.Int("min-score", 50, "Lowest score an unverified finding needs to be shown")
		jsonOut     = flag.Bool("json", false, "Print findings as JSON lines")
		outFile     = flag.String("o", "", "Also write findings to this file as JSON lines")
		mdFile      = flag.String("md", "", "Write a Markdown report of verified and likely findings, with evidence")
		threads     = flag.Int("t", 20, "Concurrent fetches")
		vthreads    = flag.Int("vt", 10, "Concurrent verifications")
		rate        = flag.Int("rl", 0, "Max fetches per second (0 = unlimited)")
		timeout     = flag.Int("timeout", 15, "Request timeout in seconds")
		proxy       = flag.String("proxy", "", "Proxy for fetching targets, e.g. http://127.0.0.1:8080 (not used for verification)")
		insecure    = flag.Bool("k", false, "Skip TLS verification when fetching targets")
		thirdParty  = flag.Bool("third-party", false, "Also scan scripts from public CDNs and analytics vendors")
		noMaps      = flag.Bool("no-maps", false, "Don't fetch or probe JavaScript source maps")
		wayback     = flag.Bool("wayback", false, "Also scan archived JS, source maps and JSON from the Wayback Machine")
		wbLimit     = flag.Int("wayback-limit", 500, "Most archived file versions to fetch per host")
		depth       = flag.Int("depth", 2, "How many levels of script references to follow from a page")
		maxSize     = flag.Int("max-size", 15, "Skip files and responses larger than this many MB")
		redact      = flag.Bool("redact", false, "Mask secrets in output")
		quiet       = flag.Bool("q", false, "Print findings only - no progress or summary")
		verbose     = flag.Bool("v", false, "Verbose: log fetch errors and skipped files")
		noColor     = flag.Bool("no-color", false, "Disable coloured output")
		showVersion = flag.Bool("version", false, "Print version and exit")
	)
	flag.Var(&gitRepos, "git", "Scan the full history of a git repository (path or clone URL); repeatable")
	flag.Var(&headers, "H", "Header to send when fetching targets, e.g. \"Cookie: a=b\"; repeatable")
	flag.Usage = usage
	flag.Parse()

	if *showVersion {
		fmt.Println("secretsniffer", version)
		return
	}

	targets := flag.Args()
	if *list != "" {
		lines, err := readLines(*list)
		if err != nil {
			fatal("reading %s: %v", *list, err)
		}
		targets = append(targets, lines...)
	}
	if len(targets) == 0 && len(gitRepos) == 0 && stdinIsPiped() {
		sc := bufio.NewScanner(os.Stdin)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		for sc.Scan() {
			if t := strings.TrimSpace(sc.Text()); t != "" && !strings.HasPrefix(t, "#") {
				targets = append(targets, t)
			}
		}
	}
	urls, paths, bad := classify(targets)
	for _, b := range bad {
		warn("skipping %q: not a URL, domain or existing path", b)
	}
	if len(urls) == 0 && len(paths) == 0 && len(gitRepos) == 0 {
		usage()
		os.Exit(2)
	}

	color := !*noColor && !*jsonOut && isTerminal(os.Stdout)
	errColor := !*noColor && isTerminal(os.Stderr)
	logf := func(format string, a ...any) {
		if *verbose {
			fmt.Fprintf(os.Stderr, "[-] "+format+"\n", a...)
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	var file *os.File
	if *outFile != "" {
		var err error
		file, err = os.Create(*outFile)
		if err != nil {
			fatal("creating %s: %v", *outFile, err)
		}
		defer file.Close()
	}
	pr := &report.Printer{W: os.Stdout, JSON: *jsonOut, Color: color, Redact: *redact}
	if file != nil {
		pr.File = file
	}

	if !*quiet {
		mode := "verification on"
		if *noVerify {
			mode = "verification off (offline scoring only)"
		}
		fmt.Fprintf(os.Stderr, "secretsniffer %s - %d url(s), %d path(s), %d repo(s) - %s\n\n",
			version, len(urls), len(paths), len(gitRepos), mode)
	}

	verifier := verify.New(time.Duration(*timeout) * time.Second)
	verifier.Enrich = !*noEnrich
	eng := engine.New(engine.Options{
		Verify:        !*noVerify,
		Verifier:      verifier,
		MinScore:      *minScore,
		VerifyWorkers: *vthreads,
		OnLive:        pr.Print,
	})

	chunks := make(chan engine.Chunk, 256)
	maxBytes := int64(*maxSize) << 20
	var wg sync.WaitGroup
	if len(urls) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			source.Web(ctx, urls, source.WebOptions{
				Client:      fetchClient(*timeout, *proxy, *insecure),
				Headers:     parseHeaders(headers),
				Concurrency: *threads,
				RatePerSec:  *rate,
				MaxBytes:    maxBytes,
				ThirdParty:  *thirdParty,
				NoMaps:      *noMaps,
				MaxDepth:    *depth,
				Logf:        logf,
			}, chunks)
		}()
	}
	if *wayback && len(urls) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			source.Wayback(ctx, source.HostsOf(urls), source.WaybackOptions{
				Client:   fetchClient(*timeout*2, *proxy, *insecure),
				Limit:    *wbLimit,
				MaxBytes: maxBytes,
				Logf: func(f string, a ...any) {
					if !*quiet {
						fmt.Fprintf(os.Stderr, "[*] "+f+"\n", a...)
					}
				},
			}, chunks)
		}()
	}
	if len(paths) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			source.Files(ctx, paths, maxBytes, chunks, logf)
		}()
	}
	for _, repo := range gitRepos {
		wg.Add(1)
		go func(repo string) {
			defer wg.Done()
			if err := source.Git(ctx, repo, maxBytes, chunks, func(f string, a ...any) {
				if !*quiet {
					fmt.Fprintf(os.Stderr, "[*] "+f+"\n", a...)
				}
			}); err != nil {
				warn("%v", err)
			}
		}(repo)
	}
	go func() { wg.Wait(); close(chunks) }()

	rest, stats := eng.Run(ctx, chunks)
	for _, f := range rest {
		if f.Status == finding.Dropped && !*showDropped {
			continue
		}
		pr.Print(f)
	}
	if *mdFile != "" {
		mf, err := os.Create(*mdFile)
		if err != nil {
			warn("creating %s: %v", *mdFile, err)
		} else {
			all := append(append([]*finding.Finding(nil), pr.Printed...), rest...)
			report.Markdown(mf, dedupe(all), stats, *redact)
			mf.Close()
		}
	}
	if !*quiet {
		report.Summary(os.Stderr, stats, errColor)
	}
}

// dedupe removes findings that appear twice (printed and in the remainder).
func dedupe(fs []*finding.Finding) []*finding.Finding {
	seen := map[*finding.Finding]bool{}
	var out []*finding.Finding
	for _, f := range fs {
		if !seen[f] {
			seen[f] = true
			out = append(out, f)
		}
	}
	return out
}

// classify sorts raw targets into URLs and local paths. Bare domains become
// https URLs.
func classify(targets []string) (urls, paths, bad []string) {
	for _, t := range targets {
		switch {
		case strings.HasPrefix(t, "http://") || strings.HasPrefix(t, "https://"):
			if _, err := url.Parse(t); err == nil {
				urls = append(urls, t)
			} else {
				bad = append(bad, t)
			}
		case exists(t):
			paths = append(paths, t)
		case looksLikeHost(t):
			urls = append(urls, "https://"+t)
		default:
			bad = append(bad, t)
		}
	}
	return
}

func looksLikeHost(s string) bool {
	if strings.ContainsAny(s, " /\\") || !strings.Contains(s, ".") {
		return false
	}
	host := s
	if i := strings.IndexByte(host, ':'); i >= 0 {
		host = host[:i]
	}
	for _, c := range host {
		if !(c == '.' || c == '-' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') {
			return false
		}
	}
	return true
}

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func fetchClient(timeout int, proxy string, insecure bool) *http.Client {
	tr := &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		MaxIdleConnsPerHost: 10,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: insecure}, //nolint:gosec // user opt-in via -k
	}
	if proxy != "" {
		u, err := url.Parse(proxy)
		if err != nil {
			fatal("bad proxy URL: %v", err)
		}
		tr.Proxy = http.ProxyURL(u)
	}
	return &http.Client{
		Timeout:   time.Duration(timeout) * time.Second,
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}

func parseHeaders(hs []string) map[string]string {
	m := map[string]string{}
	for _, h := range hs {
		k, v, ok := strings.Cut(h, ":")
		if !ok {
			fatal("bad header %q, want \"Name: value\"", h)
		}
		m[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	return m
}

func readLines(p string) ([]string, error) {
	data, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, l := range strings.Split(string(data), "\n") {
		l = strings.TrimSpace(l)
		if l != "" && !strings.HasPrefix(l, "#") {
			out = append(out, l)
		}
	}
	return out, nil
}

func stdinIsPiped() bool {
	st, err := os.Stdin.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice == 0
}

func isTerminal(f *os.File) bool {
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

func warn(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "[!] "+format+"\n", a...)
}

func fatal(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", a...)
	os.Exit(1)
}

func usage() {
	fmt.Fprintf(os.Stderr, `SecretSniffer %s - finds secrets and proves which ones are real

Usage:
  secretsniffer [flags] [target ...]
  cat urls.txt | secretsniffer [flags]
  secretsniffer -git <repo path or URL> [flags]

Targets can be URLs, bare domains, files or directories.

Flags:
`, version)
	flag.PrintDefaults()
}
