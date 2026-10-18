# Manual testing on macOS

curd was developed on Linux against Playwright's Chromium 141. Everything
below is either macOS-only code that has only been cross-compiled
(`GOOS=darwin CGO_ENABLED=0`), or real-world behavior that test mode
deliberately cannot cover (spec section 15.6, last two rows). Work through it
on a Mac with Google Chrome installed and logged into at least one site.

## 0. Build and automated tests

```sh
make hooks                      # installs the pre-commit hook
go build -o bin/curd ./cmd/curd # CGO on: uses the Security framework for the keychain
go vet ./...                    # first compile of internal/chrome/keychain_darwin_cgo.go
go test -count=1 ./...          # full suite incl. Chrome-backed tests (uses Google Chrome)
```

- [ ] `keychain_darwin_cgo.go` compiles and vets with cgo (never compiled before).
- [ ] `go test ./internal/fixture` passes with **Google Chrome**: it builds a
      profile with `--use-mock-keychain` and decrypts it. This pins the mock
      keychain password (spec 15.1 "to verify"). `chrome.MockProvider` tries
      `mock_password`, `peanuts`, `mock` with 1003 PBKDF2 iterations; if none
      works, the test fails with a decryption error — find the real password in
      Chromium's `MockAppleKeychain` and update `internal/chrome/keys.go`.
- [ ] The same test confirms the cookie DB location (`Default/Cookies` vs
      `Default/Network/Cookies`), meta version ≥ 24 and the SHA256(host_key)
      plaintext prefix on the installed Chrome version (spec 5.1).
- [ ] `go test ./internal/browser ./e2e` pass with Google Chrome: headless
      `--headless=new` + `--remote-debugging-pipe` fd 3/4 wiring works on Mac.
- [ ] `go test ./internal/rpc` passes: unix socket rename-into-place, socket
      path length (104-byte limit), `LOCAL_PEERCRED` uid check accepts the
      same user (`peer_darwin.go`), `LOCAL_PEERPID`, and `ps -o ppid=,comm=`
      parsing for client names.

## 1. Test mode end to end (no real credentials)

```sh
bin/curd test-env run -- sh -c '
  curd fetch "$CURD_TEST_BASE/api/me" &&
  curd session open app api && curd browse open "$CURD_TEST_BASE/" &&
  curd browse text "#greeting" && curd session close'
```

- [ ] Prints the mock's `/api/me` JSON and `Hello alice`; exits 0.

## 2. Keychain and code identity (spec 5.6)

- [ ] Sign the binary with a stable identity and hardened runtime, no
      `get-task-allow`:
      `codesign --force --options runtime --sign "<identity>" bin/curd`.
      Check: `codesign -dv --entitlements - bin/curd`.
- [ ] `bin/curd setup` shows the keychain dialog for "Chrome Safe Storage";
      click **Always Allow**. It reports success and never prints the key.
- [ ] Set `keychain: always-allow` in `~/.config/curd/config.yaml`; restart the
      daemon (`curd daemon stop`); a fetch fetches the key with no dialog.
- [ ] Default `prompt` mode: exactly one keychain dialog per daemon start.
- [ ] `strict` mode: a dialog (or silent fetch with always-allow) on each
      credential reload, nothing cached.
- [ ] Another binary (e.g. `/usr/bin/security find-generic-password -w -s
      "Chrome Safe Storage"`) still prompts after Always Allow was given to curd.
- [ ] Rebuild + re-sign with the same identity: still no prompt (ACL survives).
      Ad-hoc signed build: prompts again (expected).
- [ ] Built with `CGO_ENABLED=0`: works via `/usr/bin/security` (then
      `security`, not curd, is the keychain client; documented limitation).

## 3. Consent dialog (spec 10)

- [ ] First `curd fetch <policy> <url>` shows the native dialog with domain,
      policy, requesting process name + pid, scope and duration.
- [ ] "Allow once": the next call prompts again. "Allow for 8h": later calls
      from the same git repo / tty reuse it (`curd grants ls`). "Deny" and
      the Esc key: `denied_no_grant`, exit 2.
- [ ] A write (`-X POST` on a write rule) shows a separate WRITE dialog with a
      caution icon and the method/path/body size.
- [ ] Unanswered dialog gives up after 5 minutes → deny.
- [ ] Quotes/newlines in a session key (`--session-key 'a"b'`) render as text.
- [ ] `curd policies approve <draft>` shows the approve dialog, listing
      hosts, rules, cookie names (or "ALL cookies"), localStorage keys,
      redirects mode and header allowlist, with "(+N more)" when long.
- [ ] `curd daemon stop` shows a "Stop the curd daemon?" dialog; Cancel
      leaves it running (exit 2).

## 4. Real site fetch (spec 17 build order: "one authenticated curd fetch end to end")

Pick a site you're logged into in Chrome; write a read-only policy:

```sh
curd policies new mysite --host app.mysite.com
$EDITOR ~/.config/curd/policies/mysite.yaml
curd fetch --explain mysite https://app.mysite.com/api/whoami
curd fetch mysite https://app.mysite.com/api/whoami
```

- [ ] Authenticated response. `curd audit tail` shows the record with the
      query string redacted and no header/cookie values.
- [ ] `curd status` shows the profile used and cookie counts only.
- [ ] Several Chrome profiles logged into the same site: error asks to pin
      `profile:`; pinning works.
- [ ] Log out of the site in Chrome, wait for/force a reload (401) →
      `auth_expired` with the "log into ... in Chrome" hint.
- [ ] User-Agent sent matches Chrome's (`chrome.UserAgent`, "Macintosh; Intel
      Mac OS X 10_15_7" form) — check against a request-echo endpoint.

## 5. Browser sessions on a real site (spec 9)

- [ ] `curd session open mysite` (hoist): a visible Chrome window opens on a
      temp profile; `curd browse open https://app.mysite.com/` is logged in.
- [ ] **Spec 9.1 "to verify":** launching with a temp profile and no
      `--use-mock-keychain` — does Chrome touch the real "Chrome Safe
      Storage" item (keychain prompt)? Record the answer in the spec.
- [ ] `curd session open mysite --login`: log in by hand in the window;
      `curd browse text body` output has no session cookie values, and
      `curd browse capture list`/`get` show no login form body. The login
      phase ends by itself once the site sets its session cookie
      (`curd browse login`); check multi-step logins (username, then
      password page) still complete.
- [ ] A read-only session on a site that uses WebSockets: the page's socket
      is refused (blocked entry `websocket_not_granted`) and the UI degrades
      rather than breaking navigation.
- [ ] Navigation to an unrelated site is blocked; a write in the UI fails with
      the session read-only and shows as `blocked_write` in
      `curd browse capture list`.
- [ ] `curd session close`: the window closes, the temp profile directory is
      gone, no stray Chrome processes (`pgrep -fl user-data-dir`).
- [ ] Spec 9.6 / 16.6 "to verify": the verb set (no `js`) covers a real
      exploration task (e.g. a GraphQL dashboard's build history), and capture
      sees preflights and redirects.
- [ ] Spec 9.5: whether hoisting triggers new-device alerts or logs out the
      real browser (refresh-token rotation).

## 6. Explore → distill → verify → approve on a real site (spec 16)

- [ ] `curd session open mysite --explore`, do a task with browse verbs,
      `curd browse capture list`, `curd distill draft mysite-api <ids>`,
      `curd distill verify mysite-api --minimize`, `curd policies approve
      mysite-api`, then plain `curd fetch mysite-api ...` works with no browser.
