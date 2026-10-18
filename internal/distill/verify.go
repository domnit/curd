package distill

import (
	"context"
	"encoding/json"
	"fmt"
	"mime"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/domnit/curd/internal/api"
	"github.com/domnit/curd/internal/apierr"
	"github.com/domnit/curd/internal/capture"
	"github.com/domnit/curd/internal/policy"
)

// Replayer re-runs a request through the fetch broker under a policy. The
// error carries an apierr code (denied_*, auth_expired, ...).
type Replayer interface {
	Replay(ctx context.Context, p *policy.Policy, req ReplayRequest) (*ReplayResponse, error)
}

// ReplayRequest is one request to replay.
type ReplayRequest struct {
	Method, URL string
	Headers     []api.Header
	Body        []byte
}

// ReplayResponse is the broker's answer.
type ReplayResponse struct {
	Status  int
	Headers []api.Header
	Body    []byte
}

type compiledRule struct {
	idx int
	res []*regexp.Regexp
}

// ruleFor finds the draft rule that corresponds to e (enabled or not).
func ruleFor(p *policy.Policy, rules []compiledRule, e *capture.Entry, u *url.URL) int {
	cls := classify(e, u)
	wantGQLQuery := cls.isGQL && !cls.mutation
	method := strings.ToUpper(e.Method)
	path := u.Path
	if path == "" {
		path = "/"
	}
	first := -1
	for _, cr := range rules {
		r := p.Allow[cr.idx]
		okM := false
		for _, m := range r.Methods {
			if m == method {
				okM = true
			}
		}
		okP := false
		for _, re := range cr.res {
			if re.MatchString(path) {
				okP = true
			}
		}
		if !okM || !okP {
			continue
		}
		if (r.Inspect == policy.InspectGraphQLQueryOnly) == wantGQLQuery {
			return cr.idx
		}
		if first < 0 {
			first = cr.idx
		}
	}
	return first
}

// Verify replays each entry through rep under the draft and compares status
// and response shape with the capture. With minimize it also finds the
// smallest header allowlist that still passes and returns the narrowed
// policy.
func Verify(ctx context.Context, draft *policy.Policy, entries []*capture.Entry, rep Replayer, minimize bool) (*api.DistillVerifyResult, *policy.Policy, error) {
	data, err := policy.Marshal(draft)
	if err != nil {
		return nil, nil, err
	}
	work, err := policy.Parse(data, "")
	if err != nil {
		return nil, nil, fmt.Errorf("draft policy is invalid: %w", err)
	}
	var rules []compiledRule
	for i, r := range work.Allow {
		cr := compiledRule{idx: i}
		for _, p := range r.Paths {
			if re, err := regexp.Compile(p); err == nil {
				cr.res = append(cr.res, re)
			}
		}
		rules = append(rules, cr)
	}

	type verified struct {
		item   int
		e      *capture.Entry
		sent   []api.Header
		needed map[string]bool
	}
	res := &api.DistillVerifyResult{}
	var oks []*verified
	failures, tested := 0, 0

	for _, e := range entries {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		item := api.VerifyItem{ID: e.ID, Method: e.Method, URL: e.URL, CapturedStatus: e.Status}
		skip := func(why string) {
			item.Skipped = why
			res.Items = append(res.Items, item)
		}
		u, err := url.Parse(e.URL)
		switch {
		case err != nil || u.Host == "":
			skip("request URL is not valid")
			continue
		case !work.MatchesHost(u.Host):
			skip("host is not covered by the draft")
			continue
		}
		ri := ruleFor(work, rules, e, u)
		switch {
		case ri < 0:
			skip("no rule in the draft matches this request")
			continue
		case work.Allow[ri].Disabled:
			skip("write rule is disabled; enable it in the draft to verify it")
			continue
		case e.Status == 0:
			skip("no captured response (blocked or failed)")
			continue
		case e.Status >= 300 && e.Status < 400:
			skip("redirect hop; verified through the final request")
			continue
		case hasPlaceholder(e.URL) || hasPlaceholder(string(e.RequestBody)):
			skip("request carries a credential placeholder and cannot be replayed")
			continue
		}
		sent := sentHeaders(work.Request.HeaderAllowlist, e.RequestHeaders)
		tested++
		r, code, diffs, rerr := replayOnce(ctx, rep, work, e, sent)
		if rerr != nil {
			return nil, nil, rerr
		}
		item.Error = code
		if r != nil {
			item.ReplayStatus = r.Status
		}
		item.ShapeDiff = diffs
		item.OK = code == "" && statusOK(e.Status, item.ReplayStatus) && len(diffs) == 0
		res.Items = append(res.Items, item)
		if item.OK {
			oks = append(oks, &verified{item: len(res.Items) - 1, e: e, sent: sent, needed: map[string]bool{}})
		} else {
			failures++
		}
	}

	if minimize && len(oks) > 0 {
		testedHdr := map[string]bool{}
		for _, v := range oks {
			for _, h := range v.sent {
				testedHdr[strings.ToLower(h.Name)] = true
			}
		}
		// Greedy elimination: drop one header at a time from what is still
		// kept and keep it dropped if the replay still matches. Each step is
		// confirmed against the narrowed set, so headers that are redundant
		// only jointly (either one suffices) still narrow to one of them.
		for _, v := range oks {
			cur := append([]api.Header(nil), v.sent...)
			for _, h := range v.sent {
				var without []api.Header
				for _, k := range cur {
					if !strings.EqualFold(k.Name, h.Name) {
						without = append(without, k)
					}
				}
				if len(without) == len(cur) {
					continue
				}
				ok, err := passes(ctx, rep, work, v.e, without)
				if err != nil {
					return nil, nil, err
				}
				if ok {
					cur = without
				}
			}
			for _, k := range cur {
				v.needed[strings.ToLower(k.Name)] = true
			}
		}
		final := map[string]bool{}
		for _, a := range work.Request.HeaderAllowlist {
			if !testedHdr[strings.ToLower(a)] {
				final[strings.ToLower(a)] = true // never exercised by a verified request; keep
			}
		}
		for _, v := range oks {
			for n := range v.needed {
				final[n] = true
			}
		}
		var allow []string
		for n := range final {
			allow = append(allow, n)
		}
		sort.Strings(allow)
		work.Request.HeaderAllowlist = allow
		for _, v := range oks {
			var names []string
			for n := range v.needed {
				names = append(names, n)
			}
			sort.Strings(names)
			res.Items[v.item].NeededHeaders = names
		}
	}

	res.OK = tested > 0 && failures == 0
	out, err := policy.Marshal(work)
	if err != nil {
		return nil, nil, err
	}
	res.YAML = string(out)
	if res.Items == nil {
		res.Items = []api.VerifyItem{}
	}
	return res, work, nil
}

// passes reports whether replaying e with headers still matches the capture.
func passes(ctx context.Context, rep Replayer, p *policy.Policy, e *capture.Entry, headers []api.Header) (bool, error) {
	r, code, diffs, err := replayOnce(ctx, rep, p, e, headers)
	if err != nil {
		return false, err
	}
	return code == "" && r != nil && statusOK(e.Status, r.Status) && len(diffs) == 0, nil
}

// replayOnce runs one replay. The returned error is only a cancellation;
// replay failures come back as an error code.
func replayOnce(ctx context.Context, rep Replayer, p *policy.Policy, e *capture.Entry, headers []api.Header) (*ReplayResponse, string, []string, error) {
	r, err := rep.Replay(ctx, p, ReplayRequest{Method: e.Method, URL: e.URL, Headers: headers, Body: e.RequestBody})
	if err != nil {
		if cerr := ctx.Err(); cerr != nil {
			return nil, "", nil, cerr
		}
		return nil, apierr.CodeOf(err), nil, nil
	}
	if r == nil {
		return nil, apierr.Internal, nil, nil
	}
	if !statusOK(e.Status, r.Status) {
		return r, "", nil, nil
	}
	return r, "", compareResponse(e, r), nil
}

func statusOK(captured, replay int) bool {
	return captured == replay || (captured >= 200 && captured < 300 && replay >= 200 && replay < 300)
}

func headerValue(hs []api.Header, name string) string {
	for _, h := range hs {
		if strings.EqualFold(h.Name, name) {
			return h.Value
		}
	}
	return ""
}

// family reduces a content type to a comparable family.
func family(ct string) string {
	if ct == "" {
		return ""
	}
	mt, _, err := mime.ParseMediaType(ct)
	if err != nil {
		mt = strings.ToLower(strings.TrimSpace(strings.Split(ct, ";")[0]))
	}
	switch {
	case mt == "application/json" || strings.HasSuffix(mt, "+json") || mt == "text/json":
		return "json"
	case mt == "text/html" || mt == "application/xhtml+xml":
		return "html"
	case mt == "application/xml" || mt == "text/xml" || strings.HasSuffix(mt, "+xml"):
		return "xml"
	case strings.HasPrefix(mt, "text/"):
		return "text"
	}
	return mt
}

func compareResponse(e *capture.Entry, r *ReplayResponse) []string {
	capCT := headerValue(e.ResponseHeaders, "content-type")
	if capCT == "" {
		capCT = e.MimeType
	}
	capFam, repFam := family(capCT), family(headerValue(r.Headers, "content-type"))
	var diffs []string
	if capFam != "" && repFam != "" && capFam != repFam {
		diffs = append(diffs, fmt.Sprintf("content type changed: %s -> %s", capFam, repFam))
		return diffs
	}
	if capFam != "json" || e.BodyBase64 || e.BodyTruncated || len(e.ResponseBody) == 0 {
		return diffs
	}
	var a, b any
	if json.Unmarshal(e.ResponseBody, &a) != nil {
		return diffs
	}
	if json.Unmarshal(r.Body, &b) != nil {
		return append(diffs, "response body is not valid JSON")
	}
	shapeDiff("$", a, b, &diffs)
	return diffs
}

func kind(v any) string {
	switch v.(type) {
	case nil:
		return "null"
	case bool:
		return "boolean"
	case float64:
		return "number"
	case string:
		return "string"
	case []any:
		return "array"
	case map[string]any:
		return "object"
	}
	return "unknown"
}

// shapeDiff compares key sets and value types. null is compatible with any
// type (nullable fields); arrays compare their first element.
func shapeDiff(path string, a, b any, out *[]string) {
	ka, kb := kind(a), kind(b)
	if ka == "null" || kb == "null" {
		return
	}
	if ka != kb {
		*out = append(*out, fmt.Sprintf("type changed %s: %s -> %s", path, ka, kb))
		return
	}
	switch av := a.(type) {
	case map[string]any:
		bv := b.(map[string]any)
		keys := make([]string, 0, len(av))
		for k := range av {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if _, ok := bv[k]; !ok {
				*out = append(*out, fmt.Sprintf("missing key %s.%s", path, k))
				continue
			}
			shapeDiff(path+"."+k, av[k], bv[k], out)
		}
		extra := make([]string, 0)
		for k := range bv {
			if _, ok := av[k]; !ok {
				extra = append(extra, k)
			}
		}
		sort.Strings(extra)
		for _, k := range extra {
			*out = append(*out, fmt.Sprintf("extra key %s.%s", path, k))
		}
	case []any:
		bv := b.([]any)
		if len(av) > 0 && len(bv) > 0 {
			shapeDiff(path+"[0]", av[0], bv[0], out)
		}
	}
}
