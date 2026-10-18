package testenv

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Policies returns the test policies written into <dir>/policies, keyed by
// file name. They use realistic hostnames mapped to the mock upstream with
// test.host_map, honored only in test mode (spec 15.3). tlsPort is the mock's
// TLS port: localStorage origins carry it in test mode.
//
// They double as documentation of what a policy looks like.
func Policies(tlsPort int) map[string]string {
	p := map[string]string{}
	p["app.yaml"] = fmt.Sprintf(`# The mock "app" site: cookie-authenticated, read-only by default.
name: app
match:
  hosts: [app.example.com]
credentials:
  cookies: [session]            # only the session cookie is ever sent
  local_storage:                # no inject_as: only seeded into browser sessions, never sent by fetch
    - origin: https://app.example.com:%d
      keys: [authToken]
allow:
  - methods: [GET, HEAD]        # read scope
    paths:
      - '^/api/.*$'
      - '^/redirect/.*$'
      - '^/$'
      - '^/(items|settings|login|ls)$'
  - methods: [POST, DELETE]     # write scope: needs its own grant
    scope: write
    paths: ['^/api/(upload|settings|items/[0-9]+)$']
redirects: same-host-only       # never follow a redirect to another host
ttl_default: 8h
test:
  host_map: {app.example.com: 127.0.0.1}
`, tlsPort)
	p["api.yaml"] = fmt.Sprintf(`# The mock "api" site: authenticates with a bearer token that lives in the
# localStorage for the api origin (inject_as builds the Authorization header
# server-side; injection is scoped to that origin).
name: api
match:
  hosts: [api.example.com]
credentials:
  cookies: ['api-*']            # no cookies are needed here
  local_storage:
    - origin: https://api.example.com:%d
      keys: [authToken]
      inject_as: 'header:Authorization:Bearer {value}'
allow:
  - methods: [GET]
    paths: ['^/v1/.*$']
  - methods: [POST]
    paths: ['^/graphql$']
    inspect: graphql_query_only   # queries pass, mutations and subscriptions are rejected
    scope: read
ttl_default: 8h
test:
  host_map: {api.example.com: 127.0.0.1}
`, tlsPort)
	return p
}

// ExtraPolicies returns policies that are not installed by default because
// they overlap the default ones' hosts (naming a policy resolves that). Tests
// copy them into <dir>/policies when they need them; policies reload on file
// change, so no restart is needed.
func ExtraPolicies(tlsPort int) map[string]string {
	p := map[string]string{}
	p["app-follow.yaml"] = fmt.Sprintf(`# Like "app" but redirects may go to any host this policy covers
# (redirects: policy-hosts); anything else is still not followed. Credentials
# are recomputed for every hop: the host-only session cookie never goes to the
# api host, and the localStorage bearer token only to the api origin.
name: app-follow
match:
  hosts: [app.example.com, api.example.com]
credentials:
  cookies: [session]
  local_storage:
    - origin: https://api.example.com:%d
      keys: [authToken]
      inject_as: 'header:Authorization:Bearer {value}'
allow:
  - methods: [GET]
    paths: ['^/api/.*$', '^/redirect/.*$', '^/v1/.*$']
redirects: policy-hosts
test:
  host_map: {app.example.com: 127.0.0.1, api.example.com: 127.0.0.1}
`, tlsPort)
	p["app-all.yaml"] = `# Like "app" but with no cookie allowlist: every cookie that matches the
# request (domain, path, Secure) is sent. Shows cookie matching.
name: app-all
match:
  hosts: [app.example.com]
allow:
  - methods: [GET]
    paths: ['^/api/.*$', '^/admin/.*$']
test:
  host_map: {app.example.com: 127.0.0.1}
`
	p["wild.yaml"] = `# An explicit wildcard: matches subdomains of example.com, never example.com
# itself and never other.example.net.
name: wild
match:
  hosts: ['*.example.com']
credentials:
  cookies: [session]
allow:
  - methods: [GET]
    paths: ['^/.*$']
test:
  host_map: {app.example.com: 127.0.0.1, api.example.com: 127.0.0.1, example.com: 127.0.0.1, other.example.net: 127.0.0.1}
`
	return p
}

// WritePolicies writes Policies into dir.
func WritePolicies(dir string, tlsPort int) error { return WritePolicyFiles(dir, Policies(tlsPort)) }

// WritePolicyFiles writes the given policy files (name -> YAML) into dir.
func WritePolicyFiles(dir string, pol map[string]string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	names := make([]string, 0, len(pol))
	for n := range pol {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(strings.TrimLeft(pol[n], "\n")), 0o600); err != nil {
			return err
		}
	}
	return nil
}
