package capture

import (
	"net/url"
	"strings"
	"time"

	"github.com/domnit/curd/internal/api"
)

const harTime = "2006-01-02T15:04:05.000Z07:00"

func harHeaders(h []api.Header) []map[string]any {
	out := make([]map[string]any, 0, len(h))
	for _, x := range h {
		out = append(out, map[string]any{"name": x.Name, "value": x.Value})
	}
	return out
}

func harCookies(h []api.Header, set bool) []map[string]any {
	out := []map[string]any{}
	for _, x := range h {
		switch {
		case !set && strings.EqualFold(x.Name, "cookie"):
			for _, part := range strings.Split(x.Value, ";") {
				n, v, _ := strings.Cut(strings.TrimSpace(part), "=")
				if n != "" {
					out = append(out, map[string]any{"name": n, "value": v})
				}
			}
		case set && strings.EqualFold(x.Name, "set-cookie"):
			first, _, _ := strings.Cut(x.Value, ";")
			n, v, _ := strings.Cut(strings.TrimSpace(first), "=")
			if n != "" {
				out = append(out, map[string]any{"name": n, "value": v})
			}
		}
	}
	return out
}

// ExportHAR returns a redacted HAR 1.2 document for the given captures (all
// of the session's if ids is empty).
func (s *Store) ExportHAR(sessionID string, ids []string) (map[string]any, error) {
	es, err := s.Entries(sessionID, ids)
	if err != nil {
		return nil, err
	}
	entries := make([]any, 0, len(es))
	for _, e := range es {
		qs := []map[string]any{}
		if u, err := url.Parse(e.URL); err == nil {
			for k, vs := range u.Query() {
				for _, v := range vs {
					qs = append(qs, map[string]any{"name": k, "value": v})
				}
			}
		}
		req := map[string]any{
			"method": e.Method, "url": e.URL, "httpVersion": "HTTP/1.1",
			"headers": harHeaders(e.RequestHeaders), "queryString": qs,
			"cookies": harCookies(e.RequestHeaders, false), "headersSize": -1, "bodySize": len(e.RequestBody),
		}
		if len(e.RequestBody) > 0 {
			mt := ""
			for _, h := range e.RequestHeaders {
				if strings.EqualFold(h.Name, "content-type") {
					mt = h.Value
				}
			}
			req["postData"] = map[string]any{"mimeType": mt, "text": string(e.RequestBody)}
		}
		content := map[string]any{"size": e.Size, "mimeType": e.MimeType, "text": string(e.ResponseBody)}
		if e.BodyBase64 {
			content["encoding"] = "base64"
		}
		resp := map[string]any{
			"status": e.Status, "statusText": e.StatusText, "httpVersion": "HTTP/1.1",
			"headers": harHeaders(e.ResponseHeaders), "cookies": harCookies(e.ResponseHeaders, true),
			"content": content, "redirectURL": locationOf(e.ResponseHeaders), "headersSize": -1, "bodySize": e.Size,
		}
		var ms float64
		if !e.Finished.IsZero() && e.Finished.After(e.Started) {
			ms = float64(e.Finished.Sub(e.Started)) / float64(time.Millisecond)
		}
		entries = append(entries, map[string]any{
			"startedDateTime": e.Started.UTC().Format(harTime),
			"time":            ms,
			"request":         req,
			"response":        resp,
			"cache":           map[string]any{},
			"timings":         map[string]any{"send": 0, "wait": ms, "receive": 0},
			"_curd": map[string]any{
				"id": e.ID, "blocked": e.Blocked, "blocked_write": e.BlockedWrite,
				"resource_type": e.ResourceType, "initiator": e.Initiator,
			},
		})
	}
	return map[string]any{"log": map[string]any{
		"version": "1.2",
		"creator": map[string]any{"name": "curd", "version": "1"},
		"entries": entries,
	}}, nil
}

func locationOf(h []api.Header) string {
	for _, x := range h {
		if strings.EqualFold(x.Name, "location") {
			return x.Value
		}
	}
	return ""
}
