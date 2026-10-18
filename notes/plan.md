# curd implementation plan

Implements `notes/spec.md` v0.2, milestones M1–M4. M5 items (gated `js`
verb, standing grants, `grants.derive`, MCP wrapper, sessionStorage/IndexedDB
seeding, policy tamper detection) are stubbed to return `not_available` with
a hint, never silently missing.

Development happens on Linux with Playwright's Chromium; the target is macOS
with Google Chrome. Everything platform-specific sits behind build tags and
both `GOOS=linux` and `GOOS=darwin` (CGO off) must build in pre-commit.
Things that can only be checked on a Mac are collected in
`notes/manual-testing.md`.

## Layout

```
cmd/curd/                 main: calls cli.Execute()
internal/creds            Cookie, LocalStorageItem, Credentials, Source, MatchHost   [done]
internal/apierr           error codes + Error{Code,Message,Hint}                     [done]
internal/api              JSON-RPC method names and param/result types              [done]
internal/config           Paths, Mode, env var names                                [done]
internal/cdp              raw CDP client over --remote-debugging-pipe (fd 3/4)
internal/chrome           binary discovery, launch, profile discovery, version/UA,
                          cookie DB read+decrypt, key providers, localStorage LevelDB
internal/fixture          Chrome-made fixture profile builder (mock keychain), static fixture file
internal/policy           policy YAML, host/method/path rules, inspectors, drafts
internal/jar              cookie jar: RFC 6265 matching, Set-Cookie overlay
internal/grants           grant store, crd_ tokens, scoping key lookup, once/session
internal/consent          Prompter: osascript (darwin), scripted (test), deny (fallback)
internal/audit            JSONL audit log with size rotation, token hashing
internal/rpc              newline-delimited JSON-RPC 2.0 server/client on unix socket, peer creds
internal/source           chrome + static Source impls, TTL cache, reload-on-401
internal/broker           fetch broker (spec section 8)
internal/browser          browser session manager, seeding, Fetch interception, browse verbs
internal/capture          capture store, redaction, find_source, HAR export
internal/distill          draft policy generation and replay-verify
internal/mockup           mock upstream for test mode (scripted routes, request recording)
internal/testenv          test-env up/down/run
internal/daemon           wires everything; RPC method handlers
internal/cli              cobra commands, help text, `curd guide`
e2e/                      end-to-end tests driving the built binary through test-env
```

## Key decisions

- **Raw CDP over pipe, hand-rolled.** `internal/cdp` speaks CDP JSON over fds
  3/4 (`--remote-debugging-pipe`, NUL-delimited messages) with flat
  sessions (`Target.attachToTarget{flatten:true}`). This is the "sole
  connection with raw command/event access" that section 17 calls
  load-bearing, without depending on rod/chromedp internals.
- **SQLite:** `modernc.org/sqlite` (pure Go, keeps the binary static).
  **LevelDB:** `github.com/syndtr/goleveldb` on a copied directory (replays
  `.log`). **GraphQL:** `github.com/vektah/gqlparser/v2/parser`.
  **CLI:** cobra. **YAML:** yaml.v3.
- **Cookie decryption.** `v10` prefix, AES-128-CBC, IV = 16 spaces, PBKDF2-SHA1
  salt `saltysalt`, 1003 iterations on macOS, 1 iteration on Linux. When the
  DB `meta.version >= 24`, the plaintext starts with SHA256(host_key), which is
  stripped. Key providers: `keychain` (macOS: Security framework via cgo,
  fallback `/usr/bin/security` without cgo; Linux: `peanuts` basic store
  only), `mock` (mac: Chrome's mock-keychain password; linux:
  `--password-store=basic` → `peanuts`), `static` (raw password from test
  config). The mock provider tries candidate passwords and keeps the one that
  decrypts with valid padding.
- **Test mode transport.** Test policies keep realistic hosts
  (`app.example.com`). `test.host_map` maps host → `127.0.0.1`; the mock
  upstream listens on TLS (self-signed, cert passed to the daemon) and plain
  HTTP on random ports, and test URLs carry the port
  (`https://app.example.com:PORT/`). Hosts match ignoring port. The test
  browser gets `--host-resolver-rules=MAP app.example.com 127.0.0.1` and
  `--ignore-certificate-errors`. All of this is refused outside test mode.
- **Browser request policy.** In a browser session, navigations (Document
  requests) to hosts outside the session's policies are blocked.
  Subresources to other hosts are allowed (no credentials are seeded for
  them). Safe methods (GET/HEAD/OPTIONS) to policy hosts are allowed;
  anything else to a policy host must pass the policy's allow rules and
  inspectors *and* the session must have a write grant, otherwise it is
  failed with `Fetch.failRequest` and recorded `blocked_write` (section 16.5).
- **Consent for browser sessions** uses the same grants as fetch: opening a
  session needs a grant covering all its policies (write scope if
  `--write`).
- **Daemon autostart.** A CLI call that finds no socket starts
  `curd daemon` detached (prod only; disabled by `CURD_NO_AUTOSTART=1`),
  waits for the socket, and proceeds.
- **Scoping key** is computed client-side (spec 6.3): `$CURD_SESSION_KEY`,
  `--session-key`, git toplevel, controlling tty, else none (uid-global).
- **Drafts** live at `<policy dir>/<name>.draft.yaml` with `status: draft`,
  are never used by fetch, and are activated by `curd policies approve
  <name>` after a native confirmation dialog.

## Phases and tasks

Each phase ends with review, `go test ./...`, and a commit + push to main.

### Phase 0 — foundation (done by lead)
go.mod, shared packages above, pre-commit hook (`.githooks/pre-commit`:
gofmt, go vet, darwin cross-build, `go test -short ./...`), Makefile.

### Phase 1 — Chrome internals and core libraries (parallel)
- **1A Chrome internals** (front-loaded risk, section 17): `cdp`, `chrome`,
  `fixture`. Proven by a test that builds a fixture profile with the
  installed Chromium, then decrypts its cookies and reads its localStorage.
- **1B Policy and jar:** `policy` (YAML, matching, `graphql_query_only`,
  `exec:`, drafts, explain), `jar`.
- **1C Plumbing:** `rpc`, `audit`, `grants`, `consent`.

### Phase 2 — fetch path (M1 + M2)
- **2A** `source` (chrome + static, TTL cache, reload), `broker`, `mockup`.
- **2B** `daemon` (status, fetch, grants.*, policies.*, audit.tail),
  `cli` (daemon/status/fetch/grants/audit/policies/guide/run/setup,
  help text), `testenv`, e2e fetch tests from the 15.6 coverage table.

### Phase 3 — browser (M3) and capture core (M4) (parallel)
- **3A** `browser`: launch, OTR context, seeding (hoist + interactive
  login), Fetch interception, verbs, lifetime, test-mode profile assertion;
  daemon + CLI wiring for `session`/`browse`.
- **3B** `capture` (store fed by a `Recorder` interface, redaction,
  find_source, HAR) and `distill` (draft + verify via broker).

### Phase 4 — integration
Wire capture into browser sessions, `curd browse capture ...`/`curd
distill ...` CLI, CSRF-flow e2e (16.8), help/error text tests (7.5),
manual-testing notes for macOS.
