package source

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/CypherNova1337/SecretSniffer/internal/engine"
	"github.com/CypherNova1337/SecretSniffer/internal/finding"
)

// WaybackBase is the archive endpoint (overridable in tests).
var WaybackBase = "https://web.archive.org"

// WaybackOptions controls archive scanning.
type WaybackOptions struct {
	Client   *http.Client
	Limit    int   // most distinct file versions to fetch per host
	MaxBytes int64 // per file
	Logf     func(string, ...any)
}

// archiveExt is what's worth pulling from the archive: scripts, source maps
// and JSON config. HTML pages are mostly noise at archive scale.
var archiveExt = []string{".js", ".mjs", ".map", ".json"}

type snapshot struct {
	ts, original string
}

// Wayback scans archived copies of each host's JavaScript, source maps and
// JSON. Keys removed from a site are often still in the archive, and often
// still work; verification decides which.
func Wayback(ctx context.Context, hosts []string, opt WaybackOptions, out chan<- engine.Chunk) {
	if opt.Limit <= 0 {
		opt.Limit = 500
	}
	if opt.MaxBytes <= 0 {
		opt.MaxBytes = 15 << 20
	}
	for _, host := range hosts {
		snaps, err := listSnapshots(ctx, opt, host)
		if err != nil {
			logf(opt.Logf, "wayback index for %s: %v", host, err)
			continue
		}
		logf(opt.Logf, "wayback: %d archived file versions for %s", len(snaps), host)

		// The archive throttles hard; a few workers with backoff gets through
		// a list faster than many workers getting 429s.
		var wg sync.WaitGroup
		jobs := make(chan snapshot)
		for i := 0; i < 4; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for s := range jobs {
					body, ok := archiveGet(ctx, opt, WaybackBase+"/web/"+s.ts+"id_/"+s.original)
					if !ok || isBinary(body) {
						continue
					}
					date := s.ts
					if len(date) >= 8 {
						date = date[:4] + "-" + date[4:6] + "-" + date[6:8]
					}
					loc := finding.Location{Source: s.original, Archived: date}
					if strings.HasSuffix(strings.SplitN(s.original, "?", 2)[0], ".map") {
						for _, c := range sourceMapChunks(s.original, body) {
							c.Loc.Archived = date
							out <- c
						}
						continue
					}
					out <- engine.Chunk{Loc: loc, Data: body}
				}
			}()
		}
	feed:
		for _, s := range snaps {
			select {
			case jobs <- s:
			case <-ctx.Done():
				break feed
			}
		}
		close(jobs)
		wg.Wait()
	}
}

func listSnapshots(ctx context.Context, opt WaybackOptions, host string) ([]snapshot, error) {
	q := url.Values{
		"url":      {host + "/*"},
		"output":   {"json"},
		"fl":       {"timestamp,original,mimetype"},
		"filter":   {"statuscode:200"},
		"collapse": {"digest"}, // one row per distinct file content
	}
	body, ok := archiveGet(ctx, opt, WaybackBase+"/cdx/search/cdx?"+q.Encode())
	if !ok {
		return nil, fmt.Errorf("index request failed")
	}
	var rows [][]string
	if err := json.Unmarshal(body, &rows); err != nil {
		return nil, fmt.Errorf("unexpected index response")
	}
	// Newest first: recent versions are the likeliest to hold a key that
	// still works.
	var snaps []snapshot
	for i := len(rows) - 1; i >= 1 && len(snaps) < opt.Limit; i-- {
		r := rows[i]
		if len(r) < 3 || !wantedArchive(r[1], r[2]) {
			continue
		}
		snaps = append(snaps, snapshot{ts: r[0], original: r[1]})
	}
	return snaps, nil
}

func wantedArchive(original, mime string) bool {
	p := strings.ToLower(strings.SplitN(original, "?", 2)[0])
	for _, e := range archiveExt {
		if strings.HasSuffix(p, e) {
			return true
		}
	}
	return strings.Contains(mime, "javascript")
}

// archiveGet fetches with retries, backing off on throttling.
func archiveGet(ctx context.Context, opt WaybackOptions, u string) ([]byte, bool) {
	wait := 2 * time.Second
	for attempt := 0; attempt < 4; attempt++ {
		req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
		if err != nil {
			return nil, false
		}
		req.Header.Set("User-Agent", "SecretSniffer")
		resp, err := opt.Client.Do(req)
		if err == nil {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, opt.MaxBytes))
			resp.Body.Close()
			switch {
			case resp.StatusCode == 200:
				return body, true
			case resp.StatusCode == 404 || resp.StatusCode == 403:
				return nil, false
			}
		}
		select {
		case <-time.After(wait):
		case <-ctx.Done():
			return nil, false
		}
		wait *= 2
	}
	return nil, false
}

func logf(f func(string, ...any), format string, a ...any) {
	if f != nil {
		f(format, a...)
	}
}

// HostsOf extracts the distinct hosts from a list of URLs.
func HostsOf(urls []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range urls {
		u, err := url.Parse(s)
		if err != nil || u.Host == "" || seen[u.Host] {
			continue
		}
		seen[u.Host] = true
		out = append(out, u.Host)
	}
	return out
}
