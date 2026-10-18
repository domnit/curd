package mockup

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
)

var itemPath = regexp.MustCompile(`^/api/items/(\d+|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})$`)

func (s *Server) sessionOf(r *http.Request) (string, bool) {
	c, err := r.Cookie(SessionCookieName)
	if err != nil {
		return "", false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return c.Value, c.Value != "" && c.Value == s.st.validSession
}

func unauthorized(w http.ResponseWriter) {
	writeJSON(w, 401, map[string]any{"error": "unauthorized"})
}

func (s *Server) serveApp(w http.ResponseWriter, r *http.Request, body []byte) {
	sess, authed := s.sessionOf(r)
	p := r.URL.Path
	switch {
	case r.Method == "GET" && p == "/api/me":
		if !authed {
			unauthorized(w)
			return
		}
		writeJSON(w, 200, map[string]any{"user": "alice", "id": 42,
			"teams": []map[string]any{{"id": 1, "name": "core"}, {"id": 2, "name": "infra"}}})
	case r.Method == "GET" && itemPath.MatchString(p):
		id := itemPath.FindStringSubmatch(p)[1]
		writeJSON(w, 200, map[string]any{"id": id, "name": "Item " + id, "price": 9.99})
	case r.Method == "DELETE" && itemPath.MatchString(p):
		writeJSON(w, 200, map[string]any{"deleted": itemPath.FindStringSubmatch(p)[1]})
	case r.Method == "GET" && p == "/api/big":
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte(strings.Repeat("0123456789abcdef", 2<<16))) // 2 MiB
	case r.Method == "GET" && p == "/api/rotate":
		s.mu.Lock()
		s.st.validSession = RotatedCookie
		s.mu.Unlock()
		http.SetCookie(w, &http.Cookie{Name: SessionCookieName, Value: RotatedCookie, Path: "/", Secure: true, HttpOnly: true})
		writeJSON(w, 200, map[string]any{"rotated": true})
	case r.Method == "GET" && p == "/api/flaky-auth":
		s.mu.Lock()
		first := !s.st.flakySeen
		s.st.flakySeen = true
		mode := s.st.flakyMode
		s.mu.Unlock()
		if mode == "fail" || (first && mode != "ok") {
			unauthorized(w)
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true})
	case r.Method == "GET" && p == "/api/always-401":
		unauthorized(w)
	case p == "/api/upload" && r.Method == "POST":
		writeJSON(w, 200, map[string]any{"uploaded": true, "bytes": len(body)})
	case p == "/api/settings" && r.Method == "GET":
		if !authed {
			unauthorized(w)
			return
		}
		s.mu.Lock()
		theme := s.st.theme
		s.mu.Unlock()
		writeJSON(w, 200, map[string]any{"theme": theme})
	case p == "/api/settings" && r.Method == "POST":
		if !authed {
			unauthorized(w)
			return
		}
		s.mu.Lock()
		want := s.st.csrf[sess]
		s.mu.Unlock()
		if got := r.Header.Get("X-CSRF-Token"); want == "" || got != want {
			writeJSON(w, 403, map[string]any{"error": "bad csrf token"})
			return
		}
		var in struct {
			Theme string `json:"theme"`
		}
		json.Unmarshal(body, &in)
		s.mu.Lock()
		if in.Theme != "" {
			s.st.theme = in.Theme
		}
		theme := s.st.theme
		s.mu.Unlock()
		writeJSON(w, 200, map[string]any{"saved": true, "theme": theme})
	case r.Method == "GET" && p == "/redirect/same":
		http.Redirect(w, r, "/api/me", http.StatusFound)
	case r.Method == "GET" && p == "/redirect/other":
		http.Redirect(w, r, scheme(r)+"://"+HostOther+":"+s.hostPort(r)+"/collect", http.StatusFound)
	case r.Method == "GET" && p == "/redirect/api":
		http.Redirect(w, r, scheme(r)+"://"+HostAPI+":"+s.hostPort(r)+"/v1/ping", http.StatusFound)
	case r.Method == "GET" && p == "/":
		writeHTML(w, 200, dashboardPage(authed))
	case r.Method == "GET" && p == "/items":
		writeHTML(w, 200, itemsPage)
	case r.Method == "GET" && p == "/login":
		writeHTML(w, 200, loginPage)
	case r.Method == "POST" && p == "/login":
		s.mu.Lock()
		v := s.st.validSession
		s.mu.Unlock()
		http.SetCookie(w, &http.Cookie{Name: SessionCookieName, Value: v, Path: "/", HttpOnly: true, Secure: r.TLS != nil})
		http.Redirect(w, r, "/", http.StatusFound)
	case r.Method == "GET" && p == "/settings":
		tok := "csrf-" + randHex(8)
		s.mu.Lock()
		s.st.csrf[sess] = tok
		s.mu.Unlock()
		writeHTML(w, 200, strings.ReplaceAll(settingsPage, "{{TOKEN}}", tok))
	case r.Method == "GET" && p == "/ls":
		writeHTML(w, 200, strings.NewReplacer("{{PORT}}", s.hostPort(r), "{{SCHEME}}", scheme(r)).Replace(lsPage))
	default:
		writeJSON(w, 404, map[string]any{"error": "not found"})
	}
}

func (s *Server) serveAPI(w http.ResponseWriter, r *http.Request, body []byte) {
	if o := r.Header.Get("Origin"); o != "" {
		w.Header().Set("Access-Control-Allow-Origin", o)
		w.Header().Set("Vary", "Origin")
	}
	if r.Method == "OPTIONS" {
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		w.Header().Set("Access-Control-Max-Age", "600")
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(204)
		return
	}
	if r.Header.Get("Authorization") != "Bearer "+AuthToken {
		unauthorized(w)
		return
	}
	switch {
	case r.Method == "GET" && r.URL.Path == "/v1/me":
		writeJSON(w, 200, map[string]any{"user": "alice", "id": 42})
	case r.Method == "GET" && r.URL.Path == "/v1/ping":
		writeJSON(w, 200, map[string]any{"pong": true})
	case r.Method == "POST" && r.URL.Path == "/graphql":
		var in struct {
			Query         string          `json:"query"`
			OperationName string          `json:"operationName"`
			Variables     json.RawMessage `json:"variables"`
		}
		if err := json.Unmarshal(body, &in); err != nil {
			writeJSON(w, 400, map[string]any{"errors": []map[string]any{{"message": "invalid JSON body"}}})
			return
		}
		q := in.Query
		switch {
		case strings.Contains(q, "mutation") || in.OperationName == "DeleteBuild":
			writeJSON(w, 200, map[string]any{"data": map[string]any{"deleteBuild": map[string]any{"id": "b1", "deleted": true}}})
		case strings.Contains(q, "builds"):
			writeJSON(w, 200, map[string]any{"data": map[string]any{"builds": []map[string]any{
				{"id": "b1", "status": "passed"}, {"id": "b2", "status": "failed"}}}})
		case strings.Contains(q, "viewer"):
			writeJSON(w, 200, map[string]any{"data": map[string]any{"viewer": map[string]any{"login": "alice"}}})
		default:
			writeJSON(w, 200, map[string]any{"errors": []map[string]any{{"message": "unsupported query"}}})
		}
	default:
		writeJSON(w, 404, map[string]any{"error": "not found"})
	}
}
