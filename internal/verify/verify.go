// Package verify confirms whether a credential is live by making a single
// read-only call to the provider that issued it. Nothing here creates,
// modifies, sends or deletes anything on the provider's side.
package verify

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// State is the outcome of a verification attempt.
type State int

const (
	// Skip means no check applies to this particular credential (missing
	// companion, unsupported variant, check would have side effects).
	Skip State = iota
	// Live means the provider accepted the credential.
	Live
	// Dead means the provider rejected it: revoked, rotated, never valid.
	Dead
	// Harmless means it is real but cannot do anything worth reporting, such
	// as a search-only Algolia key or a referrer-locked Google key.
	Harmless
	// Unknown means the check could not reach a verdict (timeouts, rate
	// limits, 5xx, unexpected responses).
	Unknown
)

func (s State) String() string {
	return [...]string{"skip", "live", "dead", "harmless", "unknown"}[s]
}

// Target is what gets verified.
type Target struct {
	RuleID string
	Secret string
	Parts  map[string]string
	// Hints carries context found next to the credential (API host, paths,
	// header) for checks that need it.
	Hints map[string]string
}

// Result is a verification verdict.
type Result struct {
	State    State
	Identity string // who or what the credential belongs to
	Note     string // why, in a few words
	Severity string // optional override
	Boost    int    // score adjustment for Unknown results that still taught us something
	// Access lists what a live credential can reach, from enrichment calls.
	Access []string
	// Evidence lets someone else reproduce the verification.
	Evidence *Evidence

	raw *Response // the successful verification response, for enrichers
}

// Func verifies one kind of credential.
type Func func(ctx context.Context, h *HTTP, t Target) Result

// Verifier dispatches targets to provider checks, caching verdicts and
// limiting concurrent calls per provider so a big scan doesn't trip rate
// limits and come back "unknown".
type Verifier struct {
	h           *HTTP
	mu          sync.Mutex
	cache       map[string]*cacheEntry
	sems        map[string]chan struct{}
	perProvider int

	// Enrich runs extra read-only calls on live credentials to work out
	// what they can reach.
	Enrich bool
}

type cacheEntry struct {
	done chan struct{}
	res  Result
}

// New builds a verifier with the given per-request timeout.
func New(timeout time.Duration) *Verifier {
	return &Verifier{
		h: &HTTP{Client: &http.Client{
			Timeout: timeout,
			// Never follow redirects: a redirect is a verdict, not something
			// to chase with a credential attached.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
			Transport: &http.Transport{
				Proxy:               http.ProxyFromEnvironment,
				MaxIdleConnsPerHost: 4,
				TLSHandshakeTimeout: timeout,
			},
		}},
		cache:       map[string]*cacheEntry{},
		sems:        map[string]chan struct{}{},
		perProvider: 3,
	}
}

// SetRewrite redirects every outgoing verification URL through f. Used by
// tests to point provider checks at a local server.
func (v *Verifier) SetRewrite(f func(string) string) { v.h.Rewrite = f }

// Supports reports whether a check exists for a rule.
func Supports(ruleID string) bool { _, ok := funcs[ruleID]; return ok }

// Verify runs the check for t, at most once per distinct credential.
func (v *Verifier) Verify(ctx context.Context, key string, t Target) Result {
	fn, ok := funcs[t.RuleID]
	if !ok {
		return Result{State: Skip, Note: "no provider check"}
	}
	v.mu.Lock()
	if e, ok := v.cache[key]; ok {
		v.mu.Unlock()
		<-e.done
		return e.res
	}
	e := &cacheEntry{done: make(chan struct{})}
	v.cache[key] = e
	sem, ok := v.sems[t.RuleID]
	if !ok {
		sem = make(chan struct{}, v.perProvider)
		v.sems[t.RuleID] = sem
	}
	v.mu.Unlock()

	sem <- struct{}{}
	hc := *v.h
	var rec []exchange
	hc.rec = &rec
	res := fn(ctx, &hc, t)
	// One retry for transient failures before settling on unknown.
	if res.State == Unknown && transient(res.Note) && ctx.Err() == nil {
		time.Sleep(1500 * time.Millisecond)
		rec = rec[:0]
		res = fn(ctx, &hc, t)
	}
	if res.State == Live {
		if res.Evidence == nil {
			res.Evidence = buildEvidence(t, rec)
		}
		if v.Enrich {
			if en, ok := enrichers[t.RuleID]; ok {
				en(ctx, &hc, t, &res)
			}
		}
	}
	res.raw = nil
	<-sem
	e.res = res
	close(e.done)
	return res
}

// HTTP is a thin client wrapper used by provider checks.
type HTTP struct {
	Client *http.Client
	// Rewrite, if set, maps every outgoing URL (used by tests).
	Rewrite func(string) string

	rec *[]exchange // per-verification log of requests, for evidence
}

// exchange is one request/response pair, kept to build evidence.
type exchange struct {
	method, url string
	headers     map[string]string
	body        string
	status      int
	resp        []byte
	at          time.Time
}

// Response is a small, fully read HTTP response.
type Response struct {
	Status int
	Header http.Header
	Body   []byte
}

// Do sends one request and reads up to 1 MiB of the response.
func (h *HTTP) Do(ctx context.Context, method, url string, hdr map[string]string, body string) (*Response, error) {
	orig := url
	if h.Rewrite != nil {
		url = h.Rewrite(url)
	}
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, rd)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "SecretSniffer")
	req.Header.Set("Accept", "application/json")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := h.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if h.rec != nil {
		*h.rec = append(*h.rec, exchange{method: method, url: orig, headers: hdr, body: body,
			status: resp.StatusCode, resp: b, at: time.Now().UTC()})
	}
	return &Response{Status: resp.StatusCode, Header: resp.Header, Body: b}, nil
}

// noSuchHost reports whether err is a DNS NXDOMAIN, which for per-tenant
// hostnames (shop, storage account, project ref) means the tenant is gone.
func noSuchHost(err error) bool {
	var de *net.DNSError
	return errors.As(err, &de) && de.IsNotFound
}

func unknownErr(err error) Result {
	return Result{State: Unknown, Note: "request failed: " + shortErr(err)}
}

func shortErr(err error) string {
	s := err.Error()
	if i := strings.LastIndex(s, ": "); i >= 0 && len(s)-i < 80 {
		s = s[i+2:]
	}
	return s
}

// byStatus maps the common 200/401/403/429/5xx pattern to a verdict.
// ok is called for 200 to extract identity.
func byStatus(r *Response, ok func(*Response) Result) Result {
	switch {
	case r.Status >= 200 && r.Status < 300:
		res := Result{State: Live}
		if ok != nil {
			res = ok(r)
		}
		if res.raw == nil {
			res.raw = r
		}
		return res
	case r.Status == 401:
		return Result{State: Dead, Note: "provider rejected it (401)"}
	case r.Status == 429:
		return Result{State: Unknown, Note: "rate limited (429)"}
	case r.Status >= 500:
		return Result{State: Unknown, Note: "provider error (" + strconv.Itoa(r.Status) + ")"}
	default:
		return Result{State: Unknown, Note: "unexpected status " + strconv.Itoa(r.Status)}
	}
}

// transient reports whether an inconclusive result is worth retrying.
func transient(note string) bool {
	for _, p := range []string{"request failed", "rate limit", "provider error"} {
		if strings.Contains(note, p) {
			return true
		}
	}
	return false
}
