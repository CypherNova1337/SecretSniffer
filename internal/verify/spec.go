package verify

import (
	"context"
	"strings"
)

// spec describes a single-request check declaratively. Templates may use
// {secret} and {part_name} for companion values (e.g. {host}).
type spec struct {
	Method  string
	URL     string
	Headers map[string]string // value "basic:USER:PASS" becomes a Basic header
	Body    string
	ID      string   // JSON path for the identity on success
	Need    []string // companion parts required; Skip without them
	// Status handling beyond the default (2xx live, 401 dead, 429/5xx unknown).
	Dead403   bool                 // 403 means invalid for this provider
	Live403   bool                 // 403 means valid but under-privileged
	Dead404   bool                 // 404 means the tenant/object is gone
	DeadBody  []string             // substrings in a non-2xx body that mean invalid
	LiveCheck func(*Response) bool // optional: 2xx is only live if this agrees
}

func fill(s string, t Target) string {
	s = strings.ReplaceAll(s, "{secret}", t.Secret)
	for k, v := range t.Parts {
		s = strings.ReplaceAll(s, "{"+k+"}", v)
	}
	return s
}

func (sp spec) Func() Func {
	return func(ctx context.Context, h *HTTP, t Target) Result {
		for _, n := range sp.Need {
			if t.Parts[n] == "" {
				return Result{State: Skip, Note: "no " + strings.ReplaceAll(n, "_", " ") + " found nearby to check against"}
			}
		}
		hdr := map[string]string{}
		for k, v := range sp.Headers {
			v = fill(v, t)
			if strings.HasPrefix(v, "basic:") {
				up := strings.SplitN(strings.TrimPrefix(v, "basic:"), ":", 2)
				if len(up) == 2 {
					v = basic(up[0], up[1])
				}
			}
			hdr[k] = v
		}
		method := sp.Method
		if method == "" {
			method = "GET"
		}
		r, err := h.Do(ctx, method, fill(sp.URL, t), hdr, fill(sp.Body, t))
		if err != nil {
			if noSuchHost(err) {
				return Result{State: Dead, Note: "host no longer exists"}
			}
			return unknownErr(err)
		}
		body := string(r.Body)
		if r.Status < 200 || r.Status >= 300 {
			for _, d := range sp.DeadBody {
				if strings.Contains(body, d) {
					return Result{State: Dead, Note: "provider rejected it (" + d + ")"}
				}
			}
		}
		switch {
		case r.Status == 403 && sp.Dead403:
			return Result{State: Dead, Note: "provider rejected it (403)"}
		case r.Status == 403 && sp.Live403:
			return Result{State: Live, Note: "accepted, but lacks permission for the identity call"}
		case r.Status == 404 && sp.Dead404:
			return Result{State: Dead, Note: "not found (404)"}
		}
		return byStatus(r, func(r *Response) Result {
			if sp.LiveCheck != nil && !sp.LiveCheck(r) {
				return Result{State: Dead, Note: "provider rejected it"}
			}
			res := Result{State: Live}
			if sp.ID != "" {
				res.Identity = jsonPath(r.Body, sp.ID)
			}
			return res
		})
	}
}
