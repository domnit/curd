package policy

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/vektah/gqlparser/v2/ast"
	"github.com/vektah/gqlparser/v2/parser"

	"github.com/domnit/curd/internal/api"
)

// execTimeout bounds an exec inspector run.
var execTimeout = 5 * time.Second

// InspectRequest is what an Inspector sees.
type InspectRequest struct {
	Method  string
	URL     *url.URL
	Headers []api.Header
	Body    []byte
	// Rule is the rule being applied (for its GraphQL options).
	Rule *Rule
}

// Inspector makes a body-aware allow/deny decision. reason is shown to the
// caller on denial and must not echo bodies or header values. A non-nil err
// means the inspector could not run; Check treats that as a denial.
type Inspector interface {
	Inspect(ctx context.Context, req InspectRequest) (allow bool, reason string, err error)
}

func inspectorFor(r *Rule) Inspector {
	if r.Inspect == InspectGraphQLQueryOnly {
		return GraphQLQueryOnly{}
	}
	return ExecInspector{Path: strings.TrimPrefix(r.Inspect, InspectExecPrefix)}
}

// GraphQLQueryOnly allows only GraphQL query operations.
type GraphQLQueryOnly struct{}

// gqlRequest is one GraphQL-over-HTTP request object.
type gqlRequest struct {
	Query         string          `json:"query"`
	OperationName *string         `json:"operationName"`
	Variables     json.RawMessage `json:"variables"`
	Extensions    json.RawMessage `json:"extensions"`
}

// Inspect implements Inspector.
func (GraphQLQueryOnly) Inspect(_ context.Context, req InspectRequest) (bool, string, error) {
	var items []gqlRequest

	// URL parameters (GET style). Inspected even on POST, because some
	// servers honor them there.
	q := req.URL.Query()
	for k, vs := range q {
		for _, want := range gqlKeys {
			if strings.EqualFold(k, want) && (k != want || len(vs) > 1) {
				return false, "URL has ambiguous GraphQL parameter " + strconv.Quote(k), nil
			}
		}
	}
	if q.Has("query") || q.Has("extensions") {
		g := gqlRequest{Query: q.Get("query")}
		if q.Has("operationName") {
			n := q.Get("operationName")
			g.OperationName = &n
		}
		if e := q.Get("extensions"); e != "" {
			if checkJSONKeys([]byte(e)) != nil {
				return false, "URL extensions parameter is not valid", nil
			}
			if _, err := exactObject([]byte(e), []string{"persistedQuery"}); err != nil {
				return false, "URL extensions parameter is not valid", nil
			}
			g.Extensions = json.RawMessage(e)
		}
		items = append(items, g)
	}

	if len(bytes.TrimSpace(req.Body)) > 0 {
		ct := ""
		for _, h := range req.Headers {
			if strings.EqualFold(h.Name, "content-type") {
				ct, _, _ = mime.ParseMediaType(h.Value)
			}
		}
		if ct == "application/graphql" {
			g := gqlRequest{Query: string(req.Body)}
			if n := q.Get("operationName"); n != "" {
				g.OperationName = &n
			}
			items = append(items, g)
		} else {
			bi, err := parseGQLBody(req.Body)
			if err != nil {
				return false, "body is not a valid GraphQL request", nil
			}
			items = append(items, bi...)
		}
	}
	if len(items) == 0 {
		return false, "no GraphQL query found in request", nil
	}
	for _, it := range items {
		if ok, reason := checkGQL(it, req.Rule); !ok {
			return false, reason, nil
		}
	}
	return true, "", nil
}

func parseGQLBody(body []byte) ([]gqlRequest, error) {
	b := bytes.TrimSpace(body)
	// encoding/json matches keys case-insensitively and keeps the last of
	// duplicates, while GraphQL servers read exact-case keys (and may keep
	// the first duplicate). Refuse anything where those readings could
	// differ, then read exact keys only.
	if err := checkJSONKeys(b); err != nil {
		return nil, err
	}
	if b[0] == '[' {
		var raws []json.RawMessage
		if err := strictJSON(b, &raws); err != nil {
			return nil, err
		}
		if len(raws) == 0 {
			return nil, errors.New("empty batch")
		}
		arr := make([]gqlRequest, 0, len(raws))
		for _, r := range raws {
			g, err := decodeGQLObject(r)
			if err != nil {
				return nil, err
			}
			arr = append(arr, g)
		}
		return arr, nil
	}
	g, err := decodeGQLObject(b)
	if err != nil {
		return nil, err
	}
	return []gqlRequest{g}, nil
}

// gqlKeys are the request-object keys a GraphQL server reads.
var gqlKeys = []string{"query", "operationName", "variables", "extensions"}

// ParseGraphQLRequests decodes a GraphQL-over-HTTP JSON body (one request
// object or a batch) the way graphql_query_only does: exact-case keys only,
// and an error for duplicate or case-variant keys that a server might read
// differently. It returns, per request, the query text, the operation name
// (nil when absent) and the raw extensions.
func ParseGraphQLRequests(body []byte) ([]GraphQLRequest, error) {
	if len(bytes.TrimSpace(body)) == 0 {
		return nil, errors.New("empty body")
	}
	items, err := parseGQLBody(body)
	if err != nil {
		return nil, err
	}
	out := make([]GraphQLRequest, len(items))
	for i, it := range items {
		out[i] = GraphQLRequest(it)
	}
	return out, nil
}

// GraphQLRequest is one decoded GraphQL-over-HTTP request object.
type GraphQLRequest struct {
	Query         string
	OperationName *string
	Variables     json.RawMessage
	Extensions    json.RawMessage
}

// PersistedQueryHash returns extensions.persistedQuery.sha256Hash read with
// exact-case keys, or "" when absent or ambiguous.
func PersistedQueryHash(ext json.RawMessage) string { return persistedHash(ext) }

func decodeGQLObject(b []byte) (gqlRequest, error) {
	var g gqlRequest
	m, err := exactObject(b, gqlKeys)
	if err != nil {
		return g, err
	}
	if raw, ok := m["query"]; ok && !isJSONNull(raw) {
		if err := json.Unmarshal(raw, &g.Query); err != nil {
			return g, errors.New("query is not a string")
		}
	}
	if raw, ok := m["operationName"]; ok && !isJSONNull(raw) {
		var n string
		if err := json.Unmarshal(raw, &n); err != nil {
			return g, errors.New("operationName is not a string")
		}
		g.OperationName = &n
	}
	if raw, ok := m["variables"]; ok {
		g.Variables = raw
	}
	if raw, ok := m["extensions"]; ok && !isJSONNull(raw) {
		if _, err := exactObject(raw, []string{"persistedQuery"}); err != nil {
			return g, err
		}
		g.Extensions = raw
	}
	return g, nil
}

func isJSONNull(raw json.RawMessage) bool { return string(bytes.TrimSpace(raw)) == "null" }

// exactObject decodes a JSON object into a map keyed by exact key text. It
// fails if a key is a case-variant (but not an exact match) of one of known.
// Duplicate keys are rejected by checkJSONKeys before this runs.
func exactObject(b []byte, known []string) (map[string]json.RawMessage, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	if m == nil {
		return nil, errors.New("not a JSON object")
	}
	for k := range m {
		for _, want := range known {
			if k != want && strings.EqualFold(k, want) {
				return nil, fmt.Errorf("ambiguous key %q", k)
			}
		}
	}
	return m, nil
}

// checkJSONKeys walks b and fails on any object with a duplicate key.
func checkJSONKeys(b []byte) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	type frame struct {
		obj    bool
		keys   map[string]bool
		expKey bool
	}
	var stack []*frame
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		var top *frame
		if len(stack) > 0 {
			top = stack[len(stack)-1]
		}
		if top != nil && top.obj && top.expKey {
			if d, ok := tok.(json.Delim); ok && d == '}' {
				stack = stack[:len(stack)-1]
				if len(stack) > 0 && stack[len(stack)-1].obj {
					stack[len(stack)-1].expKey = true
				}
				continue
			}
			k, ok := tok.(string)
			if !ok {
				return errors.New("bad object key")
			}
			if top.keys[k] {
				return fmt.Errorf("duplicate key %q", k)
			}
			top.keys[k] = true
			top.expKey = false
			continue
		}
		switch d := tok.(type) {
		case json.Delim:
			switch d {
			case '{':
				stack = append(stack, &frame{obj: true, keys: map[string]bool{}, expKey: true})
				continue
			case '[':
				stack = append(stack, &frame{})
				continue
			case ']':
				stack = stack[:len(stack)-1]
			}
		}
		// A value completed; if inside an object, expect the next key.
		if len(stack) > 0 && stack[len(stack)-1].obj {
			stack[len(stack)-1].expKey = true
		}
	}
}

func strictJSON(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing data")
	}
	return nil
}

func checkGQL(g gqlRequest, rule *Rule) (bool, string) {
	var gql GraphQLAllow
	if rule != nil && rule.GraphQL != nil {
		gql = *rule.GraphQL
	}
	if strings.TrimSpace(g.Query) == "" {
		hash := persistedHash(g.Extensions)
		if hash == "" {
			return false, "request has no query text"
		}
		for _, h := range gql.PersistedHashes {
			if strings.EqualFold(h, hash) {
				return true, ""
			}
		}
		return false, "persisted query is not in the policy's persisted_hashes"
	}
	doc, perr := parser.ParseQuery(&ast.Source{Name: "request", Input: g.Query})
	if perr != nil || doc == nil {
		return false, "query could not be parsed as GraphQL"
	}
	var ops []*ast.OperationDefinition
	if g.OperationName != nil && *g.OperationName != "" {
		op := doc.Operations.ForName(*g.OperationName)
		if op == nil {
			return false, fmt.Sprintf("operation %q not found in document", *g.OperationName)
		}
		ops = []*ast.OperationDefinition{op}
	} else {
		ops = doc.Operations
	}
	if len(ops) == 0 {
		return false, "document contains no operation"
	}
	for _, op := range ops {
		if op.Operation != ast.Query {
			return false, fmt.Sprintf("%s operations are not allowed%s", op.Operation, opLabel(op))
		}
		if len(gql.Operations) > 0 && !containsStr(gql.Operations, op.Name) {
			if op.Name == "" {
				return false, "anonymous operations are not allowed; policy lists allowed operation names"
			}
			return false, fmt.Sprintf("operation %q is not in the policy's allowed operations", op.Name)
		}
	}
	return true, ""
}

func opLabel(op *ast.OperationDefinition) string {
	if op.Name == "" {
		return ""
	}
	return fmt.Sprintf(" (%q)", op.Name)
}

func containsStr(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

func persistedHash(ext json.RawMessage) string {
	if len(ext) == 0 || checkJSONKeys(ext) != nil {
		return ""
	}
	e, err := exactObject(ext, []string{"persistedQuery"})
	if err != nil {
		return ""
	}
	pq, ok := e["persistedQuery"]
	if !ok {
		return ""
	}
	m, err := exactObject(pq, []string{"sha256Hash", "version"})
	if err != nil {
		return ""
	}
	var h string
	if raw, ok := m["sha256Hash"]; !ok || json.Unmarshal(raw, &h) != nil {
		return ""
	}
	return h
}

// ExecInspector runs an external program. It receives JSON
// {method, url, headers:[{name,value}], body_base64} on stdin and allows the
// request iff it exits 0 with "allow" as the first line of stdout.
type ExecInspector struct{ Path string }

// Inspect implements Inspector.
func (e ExecInspector) Inspect(ctx context.Context, req InspectRequest) (bool, string, error) {
	payload, err := json.Marshal(struct {
		Method     string       `json:"method"`
		URL        string       `json:"url"`
		Headers    []api.Header `json:"headers"`
		BodyBase64 string       `json:"body_base64"`
	}{req.Method, req.URL.String(), nonNilHeaders(req.Headers), base64.StdEncoding.EncodeToString(req.Body)})
	if err != nil {
		return false, "", err
	}
	ctx, cancel := context.WithTimeout(ctx, execTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, e.Path)
	cmd.Stdin = bytes.NewReader(payload)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
	cmd.WaitDelay = time.Second
	var out bytes.Buffer
	cmd.Stdout = &limitWriter{w: &out, n: 4096}
	runErr := cmd.Run()
	if ctx.Err() != nil {
		return false, "exec inspector timed out", nil
	}
	first, _, _ := strings.Cut(strings.TrimSpace(out.String()), "\n")
	first = strings.TrimSpace(first)
	var exitErr *exec.ExitError
	switch {
	case runErr == nil && first == "allow":
		return true, "", nil
	case runErr == nil, errors.As(runErr, &exitErr):
		if first == "" || first == "allow" {
			first = "denied by exec inspector"
		}
		if len(first) > 200 {
			first = first[:200]
		}
		return false, first, nil
	default:
		return false, "", fmt.Errorf("cannot run exec inspector: %w", runErr)
	}
}

func nonNilHeaders(h []api.Header) []api.Header {
	if h == nil {
		return []api.Header{}
	}
	return h
}

// limitWriter discards writes beyond n bytes (while reporting success so the
// child is not blocked).
type limitWriter struct {
	w io.Writer
	n int
}

func (l *limitWriter) Write(p []byte) (int, error) {
	if l.n > 0 {
		k := min(len(p), l.n)
		l.w.Write(p[:k])
		l.n -= k
	}
	return len(p), nil
}
