# curd

> [!WARNING]
> **Unreviewed alpha. This code is vibe-coded.** An AI wrote most of it and no
> human has reviewed it carefully. It handles your browser logins. Expect bugs,
> including security bugs. Don't rely on it for anything that matters, and read
> the [threat model](notes/spec.md#3-threat-model) before you run it.

**Cookie Ushering Retrieval Daemon.** curd lets scripts and agents use the
logins you already have in Chrome without ever handling the credentials.

## Why

Say you want a script or an AI agent to read your CI dashboard, your issue
tracker or some internal tool. The usual options aren't great:

- **Mint an API token.** Many sites don't offer one, or it grants far more
  than you want. You then have a long-lived secret sitting in a dotfile.
- **Paste cookies into the script.** The script, and anything it logs, now
  holds your session.
- **Give the agent a browser.** It can do anything you can, on any site.

curd takes another approach. You're already logged in to the site in Chrome.
curd reads that login, keeps it to itself and makes requests *for* the caller.
The caller names a URL and gets the response back. It never sees a cookie or
token, and no command will return one.

## How it works

A local daemon reads cookies and localStorage tokens from your Chrome profile
and keeps them in memory. It serves two things over a unix socket:

- **A fetch broker** (`curd fetch`). This is a curl-like HTTP client that
  checks each request against a policy and then adds the credentials itself.
- **A browser tool** (`curd session` / `curd browse`). This is a small set of
  verbs that drive a throwaway Chrome that is already logged in. curd holds
  the only DevTools connection, and raw CDP is never exposed.

Three things gate every request:

| | What it is | Who controls it |
|---|---|---|
| **Policy** | A YAML file per site that says what's *possible*: which hosts, which cookies or tokens, which methods and paths. It can also say which request bodies pass, such as "GraphQL queries only". | You write it, or draft it from a browsing session and approve it. |
| **Grant** | Scoped, expiring consent that says what's allowed *right now*. It's read-only by default. A write needs its own grant. | You, through a native macOS dialog that the caller can't click. |
| **Audit** | A log of every request: method, host, path and decision. | Always on. |

When curd says no, it says why and what to do next (a `hint:` line). Examples
are "request a grant with ...", "this path isn't in the policy" and "log in to
the site in Chrome again".

curd is a policy and hygiene layer. It is **not** a security boundary against
malware that already runs as your user. See
[spec §3, Threat model](notes/spec.md#3-threat-model).

## Requirements

- macOS and Google Chrome. Chrome cookie decryption uses the macOS keychain.
- Go, to build it.

## Getting started

### 1. Build

```sh
go build -o bin/curd ./cmd/curd
```

Put `bin/curd` on your `PATH`, or call it by path. The daemon starts on
demand.

### 2. Allow keychain access (optional)

```sh
curd setup
```

curd needs the "Chrome Safe Storage" key to decrypt cookies. `setup` asks
macOS once so you can pick **Always Allow**. Otherwise you get a keychain
prompt each time the daemon starts. See `curd setup --help` for the
`keychain:` setting in `~/.config/curd/config.yaml`.

### 3. Write a policy for a site

```sh
curd policies new example --host app.example.com
```

This writes `~/.config/curd/policies/example.yaml`. The template is
read-only (GET and HEAD) and commented. Edit it to narrow the paths or name
the cookies it may use:

```yaml
name: example
match:
  hosts: [app.example.com]
credentials:
  cookies: [session]          # only send this cookie
allow:
  - methods: [GET, HEAD]
    paths: ['^/api/.*$']      # anchored regexps over the path
redirects: same-host-only
ttl_default: 8h
```

Check it with `curd policies validate <file>`. Policies reload when the file
changes. `curd policies ls` shows what each policy allows.

For other options, such as tokens from localStorage, GraphQL inspectors,
write rules and header allowlists, see `curd guide` or
[spec §6, Policy and grants](notes/spec.md#6-policy-and-grants).

### 4. Fetch

```sh
curd fetch https://app.example.com/api/me
```

The first time, a dialog asks whether to allow `example`. You can allow it
once, for a session (with a duration), or deny it. After that, later calls
from the same git repo or terminal reuse the grant without asking.

The body goes to stdout and notes go to stderr, so pipes stay clean:

```sh
curd fetch https://app.example.com/api/items | jq '.items[].name'
```

Fetch takes the curl flags you'd expect: `-X`, `-H`, `-d`/`--data-binary`,
`--json-body`, `-i`, `-o`, `-f` and `-s`.

### 5. See and revoke what's allowed

```sh
curd grants ls             # what's authorized right now
curd grants revoke all     # drop everything
```

## Everyday use

**Dry run.** Show which policy and rule match a request, and whether a grant
covers it. Nothing is sent.

```sh
curd fetch --explain https://app.example.com/api/me
```

**Writes.** A write is anything but GET, HEAD or OPTIONS, unless the policy
marks it read. The policy rule must have `scope: write`, and you approve a
separate write grant:

```sh
curd fetch --write example -X POST https://app.example.com/api/upload \
    --data-binary @report.csv
```

**Name the policy** when more than one covers a host: `curd fetch example <url>`.

**Unattended scripts.** Pass `--no-prompt`. A missing grant then fails with
exit code 2 instead of popping a dialog. To grant ahead of time, run one of
these:

```sh
curd grants request example --ttl 2h     # prints a token for CURD_TOKEN
curd run --policy example -- ./nightly.sh   # grant lives as long as the script
```

**Agents.** Point the agent at `curd guide`. It's a self-contained
explanation written for agents. If your harness has a per-conversation id,
export it as `CURD_SESSION_KEY` so parallel chats don't share grants.

**Logged out?** On a 401 or 403, curd reloads credentials from Chrome and
retries once. If that fails you get `auth_expired`. Log in to the site in
Chrome again and retry.

**Exit codes.** `0` ok, `1` error, `2` denied, `3` daemon unreachable, `22`
HTTP status ≥ 400 with `-f`.

## Exploring a site with no policy yet

If you don't know a site's API, use the site in a curd browser session and
let curd turn what you did into a policy. The loop is explore, capture,
distill, verify, approve:

```sh
curd session open example --explore             # throwaway Chrome, logged in, read-only
curd browse open https://app.example.com/builds
curd browse click 'a.build-row'
curd browse capture list                        # network traffic, credentials replaced by placeholders
curd distill draft example-api c12 c15          # draft policy and matching fetch commands
curd distill verify example-api --minimize      # replay through curd fetch, trim to what's needed
curd policies approve example-api               # you confirm in a dialog; the draft is inert until then
curd session close
```

The session can't leave the policy's hosts. Writes the page tries are blocked
and recorded, so you still see what they look like. Everything the verbs
return has credentials replaced with placeholders such as `{cookie:session}`.
If you'd rather sign in by hand in the window, use `--login` instead of
reusing your Chrome profile's login. See
[spec §9, Browser sessions](notes/spec.md#9-browser-sessions) and
[§16, Exploration and policy distillation](notes/spec.md#16-exploration-and-policy-distillation).

## Test mode

Test mode is a separate daemon instance with synthetic credentials, a mock
upstream and scripted consent. It never touches your real profile or
keychain. Use it to try curd out or to test scripts against it:

```sh
curd test-env run -- sh -c 'curd fetch "$CURD_TEST_BASE/api/me"'
```

See [spec §15, Test mode and fixtures](notes/spec.md#15-test-mode-and-fixtures).

## Documentation

- `curd --help` and `curd guide` cover the CLI and the mental model.
- [notes/spec.md](notes/spec.md) is the full design: goals, threat model,
  policy format, protocol, browser sessions and consent.
- [notes/plan.md](notes/plan.md) describes the code layout.
- [notes/manual-testing.md](notes/manual-testing.md) lists what has been and
  still needs to be checked on a real Mac (keychain, consent dialog, signing,
  real sites).

## Development

```sh
make hooks   # pre-commit: gofmt, vet, darwin cross-build, go test -short
make test    # everything, including tests that launch Chrome/Chromium
```
