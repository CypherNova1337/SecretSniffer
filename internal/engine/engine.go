package engine

import (
	"context"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/CypherNova1337/SecretSniffer/internal/finding"
	"github.com/CypherNova1337/SecretSniffer/internal/rules"
	"github.com/CypherNova1337/SecretSniffer/internal/verify"
)

// Options controls a scan.
type Options struct {
	Verify        bool
	Verifier      *verify.Verifier
	MinScore      int
	Workers       int // detection workers
	VerifyWorkers int
	// OnLive is called as soon as a credential is confirmed live, so results
	// show up during long scans. Remaining findings come back from Run.
	OnLive func(*finding.Finding)
}

// Stats summarises what a scan saw and threw away.
type Stats struct {
	Chunks      int64
	Candidates  int64
	Unique      int
	Verified    int
	Likely      int
	Dropped     int
	DropReasons map[string]int
}

type entry struct {
	best    *finding.Candidate
	locs    []finding.Location
	locSeen map[string]bool
	queued  bool
	result  *verify.Result
}

// Engine runs a scan.
type Engine struct {
	opt   Options
	mu    sync.Mutex
	items map[string]*entry
	order []string
	vq    chan string
	vwg   sync.WaitGroup
	stats Stats
}

// New creates an engine.
func New(opt Options) *Engine {
	if opt.Workers <= 0 {
		opt.Workers = 8
	}
	if opt.VerifyWorkers <= 0 {
		opt.VerifyWorkers = 10
	}
	return &Engine{opt: opt, items: map[string]*entry{}, vq: make(chan string, 4096)}
}

const maxLocations = 50

// Run consumes chunks until the channel closes, then finishes verification
// and returns every finding that was not already delivered through OnLive,
// plus all dropped findings.
func (e *Engine) Run(ctx context.Context, chunks <-chan Chunk) ([]*finding.Finding, Stats) {
	if e.opt.Verify {
		for i := 0; i < e.opt.VerifyWorkers; i++ {
			e.vwg.Add(1)
			go e.verifyWorker(ctx)
		}
	}
	var dwg sync.WaitGroup
	for i := 0; i < e.opt.Workers; i++ {
		dwg.Add(1)
		go func() {
			defer dwg.Done()
			for ch := range chunks {
				atomic.AddInt64(&e.stats.Chunks, 1)
				for _, c := range Detect(ch) {
					atomic.AddInt64(&e.stats.Candidates, 1)
					e.add(c)
				}
			}
		}()
	}
	dwg.Wait()
	close(e.vq)
	e.vwg.Wait()
	return e.finish()
}

func (e *Engine) add(c *finding.Candidate) {
	k := c.Key()
	e.mu.Lock()
	en, ok := e.items[k]
	if !ok {
		en = &entry{best: c, locSeen: map[string]bool{}}
		e.items[k] = en
		e.order = append(e.order, k)
	} else if better(c, en.best) {
		en.best = c
	}
	ls := c.Loc.String()
	if !en.locSeen[ls] && len(en.locs) < maxLocations {
		en.locSeen[ls] = true
		en.locs = append(en.locs, c.Loc)
	}
	enqueue := e.opt.Verify && !en.queued && en.best.Drop == "" && verify.Supports(c.RuleID)
	if enqueue {
		en.queued = true
	}
	e.mu.Unlock()
	if enqueue {
		e.vq <- k // outside the lock: verify workers need it to make progress
	}
}

// better prefers a candidate that survived filtering, then the higher score.
func better(a, b *finding.Candidate) bool {
	if (a.Drop == "") != (b.Drop == "") {
		return a.Drop == ""
	}
	return a.Score > b.Score
}

func (e *Engine) verifyWorker(ctx context.Context) {
	defer e.vwg.Done()
	for k := range e.vq {
		e.mu.Lock()
		c := e.items[k].best
		e.mu.Unlock()
		res := e.opt.Verifier.Verify(ctx, k, verify.Target{RuleID: c.RuleID, Secret: c.Secret, Parts: c.Parts})
		e.mu.Lock()
		en := e.items[k]
		en.result = &res
		var live *finding.Finding
		if res.State == verify.Live {
			live = e.build(en)
		}
		e.mu.Unlock()
		if live != nil && e.opt.OnLive != nil {
			e.opt.OnLive(live)
		}
	}
}

// build turns an entry into a Finding with its final verdict. Caller holds mu.
func (e *Engine) build(en *entry) *finding.Finding {
	c := en.best
	r := rules.ByID(c.RuleID)
	f := &finding.Finding{
		RuleID:    c.RuleID,
		Name:      r.Name,
		Severity:  r.Severity,
		Score:     c.Score,
		Secret:    c.Secret,
		Parts:     c.Parts,
		Reasons:   c.Reasons,
		Info:      c.Info,
		Context:   c.Context,
		Locations: append([]finding.Location(nil), en.locs...),
	}
	if c.Severity != "" {
		f.Severity = c.Severity
	}
	if f.Score > 100 {
		f.Score = 100
	}
	if f.Score < 0 {
		f.Score = 0
	}

	switch {
	case c.Drop != "":
		f.Status, f.Drop = finding.Dropped, c.Drop
	case en.result != nil && en.result.State == verify.Live:
		f.Status, f.Score = finding.Verified, 100
		f.Identity = en.result.Identity
		f.Access = en.result.Access
		if en.result.Note != "" {
			f.Reasons = append(f.Reasons, en.result.Note)
		}
		if en.result.Severity != "" {
			f.Severity = en.result.Severity
		}
	case en.result != nil && en.result.State == verify.Dead:
		f.Status, f.Drop = finding.Dropped, "provider says it's dead: "+en.result.Note
	case en.result != nil && en.result.State == verify.Harmless:
		f.Status, f.Drop = finding.Dropped, "real but harmless: "+en.result.Note
	default:
		if en.result != nil && en.result.Boost != 0 {
			f.Score += en.result.Boost
			f.Reasons = append(f.Reasons, en.result.Note)
		} else if en.result != nil && en.result.Note != "" {
			f.Reasons = append(f.Reasons, "not verified: "+en.result.Note)
		} else if !e.opt.Verify && verify.Supports(c.RuleID) {
			f.Reasons = append(f.Reasons, "not verified: verification disabled")
		} else if !verify.Supports(c.RuleID) {
			f.Reasons = append(f.Reasons, "no provider check exists for this type")
		}
		if f.Score >= e.opt.MinScore {
			f.Status = finding.Likely
		} else {
			f.Status, f.Drop = finding.Dropped, "score "+strconv.Itoa(f.Score)+" is below the threshold"
		}
	}
	return f
}

func (e *Engine) finish() ([]*finding.Finding, Stats) {
	e.mu.Lock()
	defer e.mu.Unlock()

	// If one pairing of a credential verified (e.g. AWS key ID + the right
	// secret), the other pairings of the same primary value are noise.
	liveSecret := map[string]bool{}
	for _, k := range e.order {
		en := e.items[k]
		if en.result != nil && en.result.State == verify.Live {
			liveSecret[en.best.RuleID+"\x00"+en.best.Secret] = true
		}
	}

	var out []*finding.Finding
	e.stats.DropReasons = map[string]int{}
	droppedSeen := map[string]bool{}
	for _, k := range e.order {
		en := e.items[k]
		f := e.build(en)
		primary := f.RuleID + "\x00" + en.best.Secret
		if f.Status != finding.Verified && liveSecret[primary] {
			f.Status, f.Drop = finding.Dropped, "another pairing of this key verified"
		}
		// Several failed pairings of one key are one dropped finding.
		if f.Status == finding.Dropped {
			if droppedSeen[primary] {
				continue
			}
			droppedSeen[primary] = true
		}
		e.stats.Unique++
		switch f.Status {
		case finding.Verified:
			e.stats.Verified++
			continue // already delivered via OnLive
		case finding.Likely:
			e.stats.Likely++
		case finding.Dropped:
			e.stats.Dropped++
			e.stats.DropReasons[category(f.Drop)]++
		}
		out = append(out, f)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Status != out[j].Status {
			return out[i].Status == finding.Likely
		}
		return out[i].Score > out[j].Score
	})
	return out, e.stats
}

// category groups drop reasons for the summary line.
func category(reason string) string {
	switch {
	case strings.HasPrefix(reason, "provider says"):
		return "dead (rejected by provider)"
	case strings.HasPrefix(reason, "real but harmless"):
		return "real but harmless"
	case strings.HasPrefix(reason, "score "):
		return "low confidence"
	case strings.HasPrefix(reason, "another pairing"):
		return "duplicate pairing"
	case strings.Contains(reason, "placeholder") || strings.Contains(reason, "example") || strings.Contains(reason, "sequential") ||
		strings.Contains(reason, "repeated") || strings.Contains(reason, "distinct characters") || strings.Contains(reason, "demo"):
		return "placeholder/example"
	case strings.Contains(reason, "expired"):
		return "expired"
	case strings.Contains(reason, "public") || strings.Contains(reason, "anonymous"):
		return "public by design"
	case strings.Contains(reason, "parse") || strings.Contains(reason, "decode"):
		return "malformed"
	default:
		return "not a secret"
	}
}
