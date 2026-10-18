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
	if q := req.URL.Query(); q.Has("query") || q.Has("extensions") {
		g := gqlRequest{Query: q.Get("query")}
		if q.Has("operationName") {
			n := q.Get("operationName")
			g.OperationName = &n
		}
		if e := q.Get("extensions"); e != "" {
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
			if n := req.URL.Query().Get("operationName"); n != "" {
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
	if b[0] == '[' {
		var arr []gqlRequest
		if err := strictJSON(b, &arr); err != nil {
			return nil, err
		}
		if len(arr) == 0 {
			return nil, errors.New("empty batch")
		}
		return arr, nil
	}
	var one gqlRequest
	if err := strictJSON(b, &one); err != nil {
		return nil, err
	}
	return []gqlRequest{one}, nil
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
	if len(ext) == 0 {
		return ""
	}
	var e struct {
		PersistedQuery struct {
			Hash string `json:"sha256Hash"`
		} `json:"persistedQuery"`
	}
	if json.Unmarshal(ext, &e) != nil {
		return ""
	}
	return e.PersistedQuery.Hash
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
