package capture

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/domnit/curd/internal/api"
	"github.com/domnit/curd/internal/apierr"
	"github.com/domnit/curd/internal/cdp"
	"github.com/domnit/curd/internal/redact"
)

const (
	sessVal = "s3cr3t-session-value-123"
	lsVal   = "tok-AbCdEf-0987654321"
	csrf    = "csrf-9f8e7d6c5b4a"
)

func newRed() *redact.Redactor {
	return redact.New(
		redact.Secret{Value: sessVal, Placeholder: redact.CookiePlaceholder("session")},
		redact.Secret{Value: lsVal, Placeholder: redact.LocalStoragePlaceholder("https://app.example.com", "authToken")},
	)
}

func ev(method string, params any) cdp.Event {
	b, _ := json.Marshal(params)
	return cdp.Event{Method: method, Params: b}
}

type m = map[string]any

func reqSent(id, method, url string, extra m) cdp.Event {
	req := m{"url": url, "method": method, "headers": m{"Accept": "application/json", "User-Agent": "x"}}
	for k, v := range extra {
		req[k] = v
	}
	return ev("Network.requestWillBeSent", m{"requestId": id, "type": "XHR", "wallTime": 1700000000.5, "request": req,
		"initiator": m{"type": "script", "stack": m{"callFrames": []m{{"url": "https://app.example.com/app.js", "lineNumber": 11}}}}})
}

func fetcher(bodies map[string]string, b64 bool) BodyFetcher {
	return func(_ context.Context, _ string, id string) ([]byte, bool, error) {
		b, ok := bodies[id]
		if !ok {
			return nil, false, errors.New("no body")
		}
		return []byte(b), b64, nil
	}
}

func TestOrdersAndRedaction(t *testing.T) {
	for _, extraFirst := range []bool{false, true} {
		st := NewStore(Options{})
		rec := st.NewRecorder("s1", newRed(), fetcher(map[string]string{"r1": `{"ok":true,"echo":"` + sessVal + `"}`}, false), nil)
		url := "https://app.example.com/api/me?t=" + lsVal
		reqExtra := ev("Network.requestWillBeSentExtraInfo", m{"requestId": "r1", "headers": m{
			"Cookie": "session=" + sessVal + "; theme=dark", "X-Auth": "Bearer " + lsVal, ":authority": "app.example.com"}})
		respExtra := ev("Network.responseReceivedExtraInfo", m{"requestId": "r1", "statusCode": 200, "headers": m{
			"Set-Cookie": "session=" + sessVal + "; Path=/\nother=zz1234567; HttpOnly", "Content-Type": "application/json"}})
		main := reqSent("r1", "GET", url, nil)
		resp := ev("Network.responseReceived", m{"requestId": "r1", "type": "XHR", "response": m{
			"url": url, "status": 200, "statusText": "OK", "mimeType": "application/json", "headers": m{"Content-Type": "application/json"}}})
		if extraFirst {
			rec.HandleEvent("cs", reqExtra)
			rec.HandleEvent("cs", respExtra)
			rec.HandleEvent("cs", main)
			rec.HandleEvent("cs", resp)
		} else {
			rec.HandleEvent("cs", main)
			rec.HandleEvent("cs", resp)
			rec.HandleEvent("cs", reqExtra)
			rec.HandleEvent("cs", respExtra)
		}
		rec.HandleEvent("cs", ev("Network.loadingFinished", m{"requestId": "r1", "encodedDataLength": 42}))
		rec.Wait()

		d, err := st.Get("c1", nil)
		if err != nil {
			t.Fatal(err)
		}
		if d.Status != 200 || d.Size != 42 || d.Initiator != "script https://app.example.com/app.js:12" {
			t.Fatalf("detail %+v", d)
		}
		hdr := map[string]string{}
		for _, h := range d.RequestHeaders {
			hdr[h.Name] = h.Value
		}
		if hdr["Cookie"] != "session={cookie:session}; theme={cookie:theme}" || hdr["X-Auth"] != "Bearer {ls:https://app.example.com:authToken}" {
			t.Fatalf("extraFirst=%v headers %+v", extraFirst, hdr)
		}
		if _, ok := hdr[":authority"]; ok {
			t.Fatal("pseudo header kept")
		}
		sc := 0
		for _, h := range d.ResponseHeaders {
			if h.Name == "Set-Cookie" {
				sc++
			}
		}
		if sc != 2 {
			t.Fatalf("set-cookie count %d: %+v", sc, d.ResponseHeaders)
		}
		assertNoSecret(t, st, "s1", "c1")
	}
}

func assertNoSecret(t *testing.T, st *Store, sid string, ids ...string) {
	t.Helper()
	var all []any
	all = append(all, st.List(sid, api.CaptureFilter{}))
	for _, id := range ids {
		d, err := st.Get(id, nil)
		if err != nil {
			t.Fatal(err)
		}
		all = append(all, d)
	}
	har, err := st.ExportHAR(sid, nil)
	if err != nil {
		t.Fatal(err)
	}
	all = append(all, har)
	for _, v := range []string{sessVal, lsVal} {
		src, _ := st.FindSource(sid, "nothing-here")
		all = append(all, src)
		b, _ := json.Marshal(all)
		if strings.Contains(string(b), v) {
			t.Fatalf("secret %q leaked: %s", v, b)
		}
	}
	es, _ := st.Entries(sid, nil)
	b, _ := json.Marshal(es)
	if strings.Contains(string(b), sessVal) || strings.Contains(string(b), lsVal) {
		t.Fatal("secret in Entries")
	}
}

func TestRedirectChain(t *testing.T) {
	st := NewStore(Options{})
	rec := st.NewRecorder("s1", newRed(), fetcher(map[string]string{"r1": "final"}, false), nil)
	rec.HandleEvent("cs", reqSent("r1", "GET", "https://app.example.com/a", nil))
	// raw response extra for the redirect arrives before the next hop
	rec.HandleEvent("cs", ev("Network.responseReceivedExtraInfo", m{"requestId": "r1", "statusCode": 302, "headers": m{"Location": "/b?x=" + sessVal}}))
	rec.HandleEvent("cs", ev("Network.requestWillBeSentExtraInfo", m{"requestId": "r1", "headers": m{"Cookie": "session=" + sessVal}}))
	rec.HandleEvent("cs", ev("Network.requestWillBeSentExtraInfo", m{"requestId": "r1", "headers": m{"Cookie": "session=" + sessVal, "X-Hop": "2"}}))
	rec.HandleEvent("cs", ev("Network.requestWillBeSent", m{"requestId": "r1", "type": "XHR",
		"request":          m{"url": "https://app.example.com/b?x=" + sessVal, "method": "GET", "headers": m{}},
		"redirectResponse": m{"url": "https://app.example.com/a", "status": 302, "statusText": "Found", "headers": m{"Location": "/b"}}}))
	rec.HandleEvent("cs", ev("Network.responseReceived", m{"requestId": "r1", "type": "XHR", "response": m{"status": 200, "statusText": "OK", "mimeType": "text/plain", "headers": m{}}}))
	rec.HandleEvent("cs", ev("Network.responseReceivedExtraInfo", m{"requestId": "r1", "statusCode": 200, "headers": m{"X-Final": "1"}}))
	rec.HandleEvent("cs", ev("Network.loadingFinished", m{"requestId": "r1"}))
	rec.Wait()
	es, _ := st.Entries("s1", nil)
	if len(es) != 2 {
		t.Fatalf("entries %d", len(es))
	}
	if es[0].Status != 302 || es[1].RedirectedFrom != es[0].ID || es[1].Status != 200 {
		t.Fatalf("%+v %+v", es[0], es[1])
	}
	if string(es[1].ResponseBody) != "final" || len(es[0].ResponseBody) != 0 {
		t.Fatal("bodies")
	}
	if len(es[0].ResponseHeaders) != 1 || es[0].ResponseHeaders[0].Value != "/b?x={cookie:session}" {
		t.Fatalf("redirect headers %+v", es[0].ResponseHeaders)
	}
	if len(es[1].RequestHeaders) != 2 { // second extra-info staged for hop 2
		t.Fatalf("hop2 request headers %+v", es[1].RequestHeaders)
	}
	if strings.Contains(es[1].URL, sessVal) {
		t.Fatal("url leak")
	}
}

func TestBlockedWrite(t *testing.T) {
	st := NewStore(Options{})
	rec := st.NewRecorder("s1", newRed(), nil, nil)
	// blocked before any network event
	rec.MarkBlocked("w1", "write", true, BlockedRequest{Method: "POST", URL: "https://app.example.com/api/upload", ResourceType: "XHR",
		Headers:  []api.Header{{Name: "Authorization", Value: "Bearer " + lsVal}, {Name: "Content-Type", Value: "application/json"}},
		PostData: []byte(`{"name":"x","tok":"` + lsVal + `"}`)})
	rec.HandleEvent("cs", reqSent("w1", "POST", "https://app.example.com/api/upload", nil))
	rec.HandleEvent("cs", ev("Network.loadingFailed", m{"requestId": "w1", "errorText": "net::ERR_FAILED"}))
	// network event first, then the mark
	rec.HandleEvent("cs", reqSent("w2", "DELETE", "https://app.example.com/api/x/1", nil))
	rec.MarkBlocked("w2", "write", true, BlockedRequest{Method: "DELETE", URL: "https://app.example.com/api/x/1"})

	l := st.List("s1", api.CaptureFilter{})
	if len(l) != 2 {
		t.Fatalf("%+v", l)
	}
	if !l[0].BlockedWrite || l[0].Blocked != "write" || l[0].Method != "POST" || !l[1].BlockedWrite {
		t.Fatalf("%+v", l)
	}
	d, _ := st.Get("c1", []string{"request_body", "request_headers"})
	if strings.Contains(d.RequestBody, lsVal) || !strings.Contains(d.RequestBody, "{ls:") || d.ResponseBody != "" {
		t.Fatalf("%+v", d)
	}
	assertNoSecret(t, st, "s1", "c1", "c2")
}

func TestPostDataFetchAndSizeCap(t *testing.T) {
	st := NewStore(Options{MaxBodyBytes: 16})
	post := fetcher(map[string]string{"p1": `{"q":"` + sessVal + `"}`}, false)
	rec := st.NewRecorder("s1", newRed(), fetcher(map[string]string{"p1": strings.Repeat("a", 100)}, false), post)
	rec.HandleEvent("cs", reqSent("p1", "POST", "https://app.example.com/api", m{"hasPostData": true}))
	rec.HandleEvent("cs", ev("Network.responseReceived", m{"requestId": "p1", "response": m{"status": 200, "headers": m{}}}))
	rec.HandleEvent("cs", ev("Network.loadingFinished", m{"requestId": "p1"}))
	rec.Wait()
	d, _ := st.Get("c1", nil)
	if len(d.ResponseBody) != 16 || !d.BodyTruncated {
		t.Fatalf("%d %v", len(d.ResponseBody), d.BodyTruncated)
	}
	if strings.Contains(d.RequestBody, sessVal) || !strings.HasPrefix(d.RequestBody, `{"q":"{cookie:`) {
		t.Fatalf("req body %q", d.RequestBody)
	}
}

func TestBase64Bodies(t *testing.T) {
	st := NewStore(Options{})
	text := base64.StdEncoding.EncodeToString([]byte("hello " + sessVal))
	bin := base64.StdEncoding.EncodeToString(append([]byte{0, 1, 2, 0xff}, sessVal...))
	clean := base64.StdEncoding.EncodeToString([]byte{0, 1, 2, 0xff, 9})
	bodies := map[string]string{"t": text, "b": bin, "c": clean}
	rec := st.NewRecorder("s1", newRed(), fetcher(bodies, true), nil)
	for _, id := range []string{"t", "b", "c"} {
		rec.HandleEvent("cs", reqSent(id, "GET", "https://app.example.com/"+id, nil))
		rec.HandleEvent("cs", ev("Network.loadingFinished", m{"requestId": id}))
	}
	rec.Wait()
	dt, _ := st.Get("c1", nil)
	db, _ := st.Get("c2", nil)
	dc, _ := st.Get("c3", nil)
	if dt.ResponseBody != "hello {cookie:session}" || dt.BodyBase64 {
		t.Fatalf("%+v", dt)
	}
	if !strings.Contains(db.ResponseBody, "dropped") || db.BodyBase64 {
		t.Fatalf("%+v", db)
	}
	if !dc.BodyBase64 || dc.ResponseBody != clean {
		t.Fatalf("%+v", dc)
	}
}

func TestListFilterGetErrors(t *testing.T) {
	st := NewStore(Options{MaxEntriesPerSession: 2})
	rec := st.NewRecorder("s1", newRed(), nil, nil)
	for i, u := range []string{"https://a.example.com/1", "https://app.example.com/2", "https://app.example.com/3"} {
		id := string(rune('a' + i))
		rec.HandleEvent("cs", reqSent(id, "GET", u, nil))
		rec.HandleEvent("cs", ev("Network.responseReceived", m{"requestId": id, "type": "Fetch", "response": m{"status": 200 + i, "headers": m{}}}))
	}
	if l := st.List("s1", api.CaptureFilter{}); len(l) != 2 || l[0].ID != "c2" {
		t.Fatalf("cap eviction %+v", l)
	}
	if l := st.List("s1", api.CaptureFilter{Status: 202, Host: "app.example.com", Type: "fetch", Method: "get", URLContains: "/3"}); len(l) != 1 {
		t.Fatalf("%+v", l)
	}
	if _, err := st.Get("c1", nil); apierr.CodeOf(err) != apierr.NotFound || !strings.Contains(apierr.As(err).Hint, "curd browse capture list") {
		t.Fatalf("%v", err)
	}
	if _, ok := st.SessionOf("c3"); !ok {
		t.Fatal("sessionOf")
	}
	if _, err := st.Entries("other", []string{"c3"}); err == nil {
		t.Fatal("cross-session")
	}
	st.Drop("s1")
	if _, ok := st.SessionOf("c3"); ok || len(st.List("s1", api.CaptureFilter{})) != 0 {
		t.Fatal("drop")
	}
}

func TestFindSourceCSRFAndHeldSecret(t *testing.T) {
	st := NewStore(Options{})
	html := `<html><head><meta name="csrf-token" content="` + csrf + `"></head><body>` + lsVal + `</body></html>`
	rec := st.NewRecorder("s1", newRed(), fetcher(map[string]string{"d": html}, false), nil)
	rec.HandleEvent("cs", reqSent("d", "GET", "https://app.example.com/", nil))
	rec.HandleEvent("cs", ev("Network.responseReceived", m{"requestId": "d", "type": "Document", "response": m{"status": 200, "mimeType": "text/html", "headers": m{"X-Request-Id": csrf}}}))
	rec.HandleEvent("cs", ev("Network.loadingFinished", m{"requestId": "d"}))
	rec.Wait()
	rec.HandleEvent("cs", reqSent("p", "POST", "https://app.example.com/api/save", m{
		"headers": m{"X-CSRF-Token": csrf, "Content-Type": "application/json"}, "postData": `{"csrf":"` + csrf + `"}`}))

	src, err := st.FindSource("s1", csrf)
	if err != nil {
		t.Fatal(err)
	}
	if len(src) < 3 || src[0].ID != "c1" {
		t.Fatalf("%+v", src)
	}
	locs := map[string]bool{}
	for _, s := range src {
		locs[s.ID+":"+s.Location] = true
	}
	if !locs["c1:response_body"] || !locs["c1:response_header:x-request-id"] || !locs["c2:request_body"] {
		t.Fatalf("%+v", src)
	}
	if !strings.Contains(src[len(src)-1].Context, csrf) && !strings.Contains(src[0].Context, "csrf-token") {
		t.Fatalf("context %+v", src)
	}
	for _, v := range []string{sessVal, lsVal} {
		if _, err := st.FindSource("s1", v); apierr.CodeOf(err) != apierr.InvalidRequest {
			t.Fatalf("held value search must be refused: %v", err)
		}
	}
	assertNoSecret(t, st, "s1", "c1", "c2")
}

func TestLateLearnedSecretRedactedOnOutput(t *testing.T) {
	st := NewStore(Options{})
	red := newRed()
	rec := st.NewRecorder("s1", red, fetcher(map[string]string{"a": "token=late-minted-secret-77"}, false), nil)
	rec.HandleEvent("cs", reqSent("a", "GET", "https://app.example.com/", nil))
	rec.HandleEvent("cs", ev("Network.loadingFinished", m{"requestId": "a"}))
	rec.Wait()
	red.Add(redact.Secret{Value: "late-minted-secret-77", Placeholder: "{cookie:late}"})
	d, _ := st.Get("c1", nil)
	if d.ResponseBody != "token={cookie:late}" {
		t.Fatal(d.ResponseBody)
	}
	har, _ := st.ExportHAR("s1", []string{"c1"})
	b, _ := json.Marshal(har)
	if strings.Contains(string(b), "late-minted") {
		t.Fatal("leak")
	}
}

func TestHARShape(t *testing.T) {
	st := NewStore(Options{Now: func() time.Time { return time.Unix(1700000001, 0) }})
	rec := st.NewRecorder("s1", newRed(), nil, nil)
	rec.HandleEvent("cs", reqSent("a", "POST", "https://app.example.com/api?x=1", m{"postData": "{}", "headers": m{"Content-Type": "application/json", "Cookie": "session=" + sessVal}}))
	rec.HandleEvent("cs", ev("Network.responseReceived", m{"requestId": "a", "type": "XHR", "response": m{"status": 201, "statusText": "Created", "mimeType": "application/json", "headers": m{}}}))
	rec.HandleEvent("cs", ev("Network.loadingFinished", m{"requestId": "a"}))
	har, err := st.ExportHAR("s1", nil)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(har)
	var back struct {
		Log struct {
			Version string
			Creator struct{ Name string }
			Entries []struct {
				StartedDateTime string
				Request         struct {
					Method      string
					QueryString []struct{ Name, Value string }
					PostData    struct{ MimeType, Text string }
					Cookies     []struct{ Name, Value string }
				}
				Response struct {
					Status  int
					Content struct{ MimeType string }
				}
				Curd struct{ ID, ResourceType string } `json:"_curd"`
			}
		}
	}
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	e := back.Log.Entries[0]
	if back.Log.Version != "1.2" || back.Log.Creator.Name != "curd" || e.Request.QueryString[0].Name != "x" ||
		e.Request.PostData.MimeType != "application/json" || e.Request.Cookies[0].Value != "{cookie:session}" ||
		e.Response.Status != 201 || e.Curd.ID != "c1" || e.StartedDateTime == "" {
		t.Fatalf("%s", b)
	}
	if _, err := st.ExportHAR("s1", []string{"zz"}); err == nil {
		t.Fatal("want not found")
	}
}
