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

- [x] `keychain_darwin_cgo.go` compiles and vets with cgo (never compiled before).
- [x] `go test ./internal/fixture` passes with **Google Chrome**: it builds a
      profile with `--use-mock-keychain` and decrypts it. This pins the mock
      keychain password (spec 15.1 "to verify"). `chrome.MockProvider` tries
      `mock_password`, `peanuts`, `mock` with 1003 PBKDF2 iterations; if none
      works, the test fails with a decryption error — find the real password in
      Chromium's `MockAppleKeychain` and update `internal/chrome/keys.go`.
- [x] The same test confirms the cookie DB location (`Default/Cookies` vs
      `Default/Network/Cookies`), meta version ≥ 24 and the SHA256(host_key)
      plaintext prefix on the installed Chrome version (spec 5.1).
- [x] `go test ./internal/browser ./e2e` pass with Google Chrome: headless
      `--headless=new` + `--remote-debugging-pipe` fd 3/4 wiring works on Mac.
- [x] `go test ./internal/rpc` passes: unix socket rename-into-place, socket
      path length (104-byte limit), `LOCAL_PEERCRED` uid check accepts the
      same user (`peer_darwin.go`), `LOCAL_PEERPID`, and `ps -o ppid=,comm=`
      parsing for client names.

Result (2026-10-18, macOS 26 arm64, Google Chrome 155.0.8059.82, Go 1.27.2):
all of section 0 passes. The mock keychain password is `mock_password`
(`peanuts` and `mock` fail); cookies are at `Default/Cookies`; `meta.version`
is 24 with the SHA256(host_key) prefix. `TestPeerInfo` now also runs on
darwin and passes.

## 1. Test mode end to end (no real credentials)

```sh
bin/curd test-env run -- sh -c '
  curd fetch "$CURD_TEST_BASE/api/me" &&
  curd session open app api && curd browse open "$CURD_TEST_BASE/" &&
  curd browse text "#greeting" && curd session close'
```

- [x] Prints the mock's `/api/me` JSON and `Hello alice`; exits 0 (2026-10-18).

## 2. Keychain and code identity (spec 5.6)

- [x] Sign the binary with a stable identity and hardened runtime, no
      `get-task-allow`: `make sign IDENTITY="<identity>"`. Without a
      Developer ID, create a local one in Keychain Access → Certificate
      Assistant → Create a Certificate… (type "Code Signing"); spec 5.6
      asks whether a local certificate works, so record the answer.
      Check: `codesign -dv --entitlements - bin/curd`.
- [x] `bin/curd setup` shows the keychain dialog for "Chrome Safe Storage";
      click **Always Allow**. It reports success and never prints the key.
- [x] Set `keychain: always-allow` in `~/.config/curd/config.yaml`; restart the
      daemon (`curd daemon stop`); a fetch fetches the key with no dialog.
- [x] Default `prompt` mode: exactly one keychain dialog per daemon start.
- [ ] `strict` mode: a dialog (or silent fetch with always-allow) on each
      credential reload, nothing cached.
- [x] Another binary (e.g. `/usr/bin/security find-generic-password -w -s
      "Chrome Safe Storage"`) still prompts after Always Allow was given to curd.
- [x] Rebuild + re-sign with the same identity: still no prompt (ACL survives).
      Ad-hoc signed build: prompts again (expected).
- [ ] Built with `CGO_ENABLED=0`: works via `/usr/bin/security` (then
      `security`, not curd, is the keychain client; documented limitation).

## 3. Consent dialog (spec 10)

- [x] First `curd fetch <policy> <url>` shows the native dialog with domain,
      policy, requesting process name + pid, scope and duration.
- [x] "Allow once": the next call prompts again. "Allow for 8h": later calls
      from the same git repo / tty reuse it (`curd grants ls`). "Deny" and
      the Esc key: `denied_no_grant`, exit 2.
- [x] A write (`-X POST` on a write rule) shows a separate WRITE dialog with a
      caution icon and the method/path/body size.
- [ ] Unanswered dialog gives up after 5 minutes → deny.
- [x] Quotes/newlines in a session key (`--session-key 'a"b'`) render as text.
- [x] `curd policies approve <draft>` shows the approve dialog, listing
      hosts, rules, cookie names (or "ALL cookies"), localStorage keys,
      redirects mode and header allowlist, with "(+N more)" when long.
- [x] `curd daemon stop` shows a "Stop the curd daemon?" dialog; Cancel
      leaves it running (exit 2).

## 4. Real site fetch (spec 17 build order: "one authenticated curd fetch end to end")

Pick a site you're logged into in Chrome; write a read-only policy:

```sh
curd policies new mysite --host app.mysite.com
$EDITOR ~/.config/curd/policies/mysite.yaml
curd fetch --explain mysite https://app.mysite.com/api/whoami
curd fetch mysite https://app.mysite.com/api/whoami
```

- [x] Authenticated response. `curd audit tail` shows the record with the
      query string redacted and no header/cookie values.
- [x] `curd status` shows the profile used and cookie counts only.
- [ ] Several Chrome profiles logged into the same site: error asks to pin
      `profile:`; pinning works.
- [ ] Log out of the site in Chrome, wait for/force a reload (401) →
      `auth_expired` with the "log into ... in Chrome" hint.
- [x] User-Agent sent matches Chrome's (`chrome.UserAgent`, "Macintosh; Intel
      Mac OS X 10_15_7" form) — check against a request-echo endpoint.

## 5. Browser sessions on a real site (spec 9)

- [x] `curd session open mysite` (hoist): a visible Chrome window opens on a
      temp profile; `curd browse open https://app.mysite.com/` is logged in.
- [x] **Spec 9.1 "to verify":** launching with a temp profile and no
      `--use-mock-keychain` — does Chrome touch the real "Chrome Safe
      Storage" item (keychain prompt)? Record the answer in the spec.
- [x] `curd session open mysite --login`: log in by hand in the window;
      `curd browse text body` output has no session cookie values, and
      `curd browse capture list`/`get` show no login form body. The login
      phase ends by itself once the site sets its session cookie
      (`curd browse login`); check multi-step logins (username, then
      password page) still complete.
- [ ] A read-only session on a site that uses WebSockets: the page's socket
      is refused (blocked entry `websocket_not_granted`) and the UI degrades
      rather than breaking navigation.
- [x] Navigation to an unrelated site is blocked; a write in the UI fails with
      the session read-only and shows as `blocked_write` in
      `curd browse capture list`.
- [x] `curd session close`: the window closes, the temp profile directory is
      gone, no stray Chrome processes (`pgrep -fl user-data-dir`).
- [ ] Spec 9.6 / 16.6 "to verify": the verb set (no `js`) covers a real
      exploration task (e.g. a GraphQL dashboard's build history), and capture
      sees preflights and redirects.
- [ ] Spec 9.5: whether hoisting triggers new-device alerts or logs out the
      real browser (refresh-token rotation).

## 6. Explore → distill → verify → approve on a real site (spec 16)

- [x] `curd session open mysite --explore`, do a task with browse verbs,
      `curd browse capture list`, `curd distill draft mysite-api <ids>`,
      `curd distill verify mysite-api --minimize`, `curd policies approve
      mysite-api`, then plain `curd fetch mysite-api ...` works with no browser.

## Results: 2026-10-18 run (macOS 26 arm64, Chrome 155.0.8059.82, github.com)

Sections 2–6 were run against github.com with a self-signed "curd local"
code-signing certificate.

Answers to the spec's open questions:

- **Spec 5.6:** a local self-signed code-signing certificate works. The
  designated requirement is `identifier "org.domnit.curd" and certificate
  leaf = H"…"`, so Always Allow survives a rebuild and re-sign. `security`
  and an ad-hoc build are still prompted (an ad-hoc build gets
  `source_error`). `security find-identity -v` lists 0 valid identities
  because the self-signed root isn't trusted; `codesign` uses it anyway.
- **Spec 9.1:** Chrome on a temp profile without `--use-mock-keychain`
  does *not* touch "Chrome Safe Storage". Only curd's own prompt appeared.
- **Spec 9.6 / 16.6:** the verbs covered a real exploration
  (notifications and a profile's contributions) with no `js`. Capture saw
  the login redirects (302s). No CORS preflights occurred on GitHub, so
  preflights are still unobserved.

Bugs found and fixed in this run:

- Esc did nothing on consent dialogs. macOS doesn't bind Esc to a cancel
  button that is also the default button. The dialogs no longer set a
  default button.
- A fetch with no matching cookies or localStorage in any profile went out
  anonymous and came back as a 200 sign-in page. It now reloads once, then
  fails with `auth_expired` and a "log into … in Chrome" hint, without
  sending anything.
- In `--login` sessions, GitHub's anonymous cookies (`_gh_sess`, `_octo`,
  `tz`, …) ended the login phase before the user had submitted anything,
  so the real login POST was blocked. The phase now ends only after a login
  submission produces a new cookie that the policy's `credentials.cookies`
  allows. GitHub's password → 2FA login then completed, and `login_end`
  fired after the 2FA step.
- `distill verify --minimize` kept every header whenever two headers were
  each redundant on their own but not together. It now uses greedy
  elimination (GitHub: 7 headers down to `x-requested-with`), and prints
  "needed headers: none" when nothing is needed.
- In a visible window, Chrome's own `browser_ui` targets (the omnibox popup)
  sit in the session's context and filled capture with `chrome://` entries.
  curd now resumes and detaches them without closing them. The omnibox
  dropdown is blank in curd windows with or without this change; that is
  accepted.
- `capture list` padded every row to the longest URL (30 KB). The URL column
  is now capped at 120 characters.
- After the user clicks Deny, the hint no longer reads as "request it
  again": it says the user declined and not to re-prompt unless asked.
- Keychain status -128 and -25300 now produce readable messages.

Still open or not run:

- `strict` keychain mode, `CGO_ENABLED=0` via `/usr/bin/security`, the
  5-minute dialog timeout, several profiles with the same site, the log-out →
  `auth_expired` path, `websocket_not_granted` (GitHub's socket goes to the
  non-policy host `alive.github.com`), and spec 9.5 (new-device alerts or
  logouts after hoisting).
- Response bodies redact every held cookie value, including non-secret
  ones like `dotcom_user` (the username), which shows up as
  `{cookie:dotcom_user}` throughout GitHub pages. That is by design
  (spec 16.2), but it hurts readability. It could exempt cookies the policy
  marks non-secret.

