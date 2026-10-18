# curd: Cookie Ushering Retrieval Daemon

*Spec v0.2, draft. curd ushers scoped, authorized requests through using the browser logins the user already has.*

## 1. Summary

A local daemon that lets scripts and agents use the user's existing browser logins without ever handling the credentials. It reads cookies and localStorage tokens from the user's Chrome profile, holds them in memory, and exposes two things:

1. A **fetch broker**: a policy-enforcing HTTP client that injects credentials server-side.
2. **A browser tool**: a small first-party set of browse verbs driving an ephemeral, pre-authenticated browser, for tasks that need real browser use. curd keeps the only CDP connection; no raw CDP is ever exposed.

Access is granted per domain with scoped, expiring grants, each tied to a session token. Callers never receive cookie or token values. One binary is both the CLI and, as \`curd daemon\`, the long-lived process.

## 2. Goals and non-goals

**Goals**

- No keychain prompt per call. With a signed binary the user can make it a one-time setup (section 5.6).
- Callers (skills, scripts, agents) never see credential values.
- Per-domain, per-method, per-path policy, with body inspectors (for example, blocking GraphQL mutations).
- Read-only by default; writes are an explicit, separate grant.
- Every request audited.
- One policy file governs both the fetch broker and browser sessions.

**Non-goals**

- Defending against malicious code already running as the user (see section 3).
- Cross-machine use, CI, or headless operation.
- A general browser automation framework. The browse verbs (section 9.6) are a deliberately small surface for exploration and credentialed tasks, not a Playwright replacement.
- Windows or Linux in v1. macOS and Chrome first.
- Circumventing bot protection or site terms of service.

## 3. Threat model

**In scope**

- A buggy or prompt-injected agent using a granted session beyond its intended scope.
- Credential leakage into model context, logs, transcripts, or error messages.
- Cookie leakage via redirects or subdomain confusion.
- Accidental mutations from a tool meant to be read-only.

**Out of scope**

- Other processes running as the same user. localStorage is unencrypted on disk, and a keychain `Always Allow` click opens the cookie key to them too when the daemon runs as an interpreter script. A signed standalone binary scopes that access to the daemon alone (section 5.6).
- A compromised machine.

The daemon is a **policy and hygiene layer**, not a security boundary against local malware. The docs and UX should say so plainly.

## 4. Architecture

```
callers: curd CLI (fetch / browse / ...) | scripts    [MCP wrapper: later]
              |  JSON-RPC over unix socket (0600, peer-uid check)
              |  session token (crd_...) scopes each call
              v
        +-------------------------------+
        | curd daemon                   |
        |  grant store   policy engine  |
        |  fetch broker  browser mgr    |
        |  token store   capture/distill|
        |  audit log     consent UI     |
        +--------+----------------------+
                 |
     credential sources (in-memory cache)
       - Chrome cookies (keychain + SQLite)
       - Chrome localStorage (LevelDB)
     browser: ephemeral Chrome, curd holds the sole CDP connection
```

## 5. Credential sources

### 5.1 Cookies (Chrome, macOS)

- Copy the profile's `Cookies` SQLite file to a temp path before reading (avoids the lock).
- Get the `Chrome Safe Storage` key from the macOS Keychain once at startup, derive the AES key, and decrypt **only rows matching granted domains**. Whether the key is cached or fetched on demand depends on the keychain mode in section 5.6.
- Verify the exact decryption scheme against the installed Chrome version at build time. Newer versions prepend extra bytes to the decrypted plaintext, so the implementation needs a version check and tests.

### 5.2 localStorage

- Copy `Local Storage/leveldb/` to a temp dir (skip the `LOCK` file), open with a LevelDB reader that also replays the write-ahead `.log`.
- Keys are origin-prefixed. Values carry a one-byte encoding marker (UTF-16 or Latin-1).
- Extract only keys named in the policy's `credentials.local_storage` section.
- Not encrypted, so no consent gate at the source level. Policy and grants are the only gate.

### 5.3 Profile discovery

- Glob `Default`, `Profile *` under Chrome's user data dir.
- Pick the profile that contains cookies for the domain. If several do, require the policy to pin a profile, or ask the user once and persist the choice.

### 5.4 Refresh

- Reload from disk on a short TTL (default 5 minutes) and on 401/403 from upstream, then retry once.
- Apply `Set-Cookie` from responses to the in-memory jar so rotation within a session works. No write-back to Chrome.

### 5.5 Source interface

Sources implement `load(domains, policy) -> credentials`, so a CDP or extension-based source can be added later without touching the broker.

### 5.6 Keychain access and code identity

The daemon ships as its own signed binary, not a script run by an interpreter. That makes keychain `Always Allow` a reasonable choice. Whether to use it is up to the user.

- **Why it matters.** Keychain ACLs on legacy items, including Chrome's `Safe Storage` entry, are tied to the code identity of the requesting app. For a script, that identity is the interpreter, so every script run by it inherits the access. For a signed binary, only the daemon has it; any other process still triggers a prompt.
- **Modes.** `prompt` (default): the user answers the keychain dialog each time the daemon starts. `always-allow`: the user adds the daemon to the item's ACL once and the key is fetched silently. `strict`: the key is never cached; it is fetched for each reload and discarded after decrypting.
- **Consent moves into the daemon.** With always-allow the keychain no longer gates anything, so the native grant dialogs (section 10) are the only consent step. Recommended setup: `always-allow` with on-demand key fetch, so no long-lived key sits in memory.
- **Signing requirements.** Use a stable signing identity (Developer ID, or a local code-signing certificate; a self-signed local certificate was verified to keep the ACL across rebuilds, 2026-10-18). Ad-hoc signatures change with every build and break the ACL. Enable the hardened runtime, do not add the `get-task-allow` entitlement, and never load user-writable code at runtime, so other same-user processes cannot inject into the daemon or attach a debugger to inherit its access.
- **Setup.** `curd setup` triggers a one-time keychain dialog to add the binary to Chrome's `Safe Storage` item. The daemon works without it, with one prompt per start.
- **Limits.** This does not protect localStorage, which is plain on disk, and does not stop same-user processes from connecting to the socket. Where possible, check the connecting client's code signature; scripts under a shared interpreter will all look identical.

## 6. Policy and grants

A **policy** says what is possible for a site. A **grant** says what is currently authorized, for whom, and until when.

### 6.1 Policy file

One file per site at `~/.config/curd/policies/<name>.yaml`:

```yaml
name: internal-dashboard
profile: Default              # optional pin
match:
  hosts: [app.example.com, '*.example.com']   # exact or explicit wildcard only
credentials:
  cookies: [session, '__Host-*']   # name allowlist; default is all cookies for matched hosts
  local_storage:
    - origin: https://app.example.com
      keys: [authToken]
      inject_as: 'header:Authorization:Bearer {value}'
allow:
  - methods: [GET, HEAD]
    paths: ['^/api/.*']
  - methods: [POST]
    paths: ['^/graphql$']
    inspect: graphql_query_only    # rejects mutation and subscription operations
request:
  header_allowlist: [accept, content-type, x-csrf-token]
  max_body_bytes: 1048576
response:
  strip_headers: [set-cookie]
  max_body_bytes: 10485760
redirects: same-host-only
ttl_default: 8h
```

### 6.2 Inspectors

- `graphql_query_only`: parse the body, reject any operation that is not a query. This is the main read-only guard for GraphQL endpoints that tunnel everything through one POST.
- `exec:<path>`: an external program receives the request on stdin and returns allow or deny, for any check not worth building in.

### 6.3 Grants

A grant is `{token, policies, scopes, mode, bound_to, expires_at}. Consent produces a grant and returns an opaque session token; the token is how later calls say which grant they are using`.

| Mode | Lifetime |
| --- | --- |
| once | a single request |
| session | until TTL or daemon exit |
| standing (deferred) | persisted across restarts, re-confirmed after its TTL. Post-v1; once and session cover exploration and scripting. |

Scopes are `read` (default) and `write`. Write is never implied by read and always needs its own confirmation. A grant may cover several policies named together at consent time.

**Session tokens.** Consent binds to a session, not to a pid and executable, which for agents are near-meaningless (every CLI call is a fresh process with the same exe, and two agents look identical).

- **Opaque and server-side.** The token is a random id (prefix `crd_`, so transcript and log redactors can strip it) pointing at a daemon-side grant. It is not a signed, self-describing blob. Revocation is instant; a leaked token reveals nothing about the credentials, which are sites' cookies, not this token.
- **Not a site credential.** The token is a capability for curd's own unix socket, which already requires the same uid. Off-machine transcript leakage grants nothing. Only a same-user local process could reuse it, and that is out of scope (section 3). The token's job is scoping and attribution, not secrecy.
- **Lifetime.** Idle timeout plus an absolute maximum. Renewing past the maximum needs a fresh dialog.
- **Consent on first use.** An agent already running in a shell cannot be wrapped from outside, so the primary path is lazy: the agent just runs `curd fetch <policy> ...` with no token, curd finds no grant and fires the native consent dialog, and on approval mints a grant. The token is printed (prefix `crd_`) for reuse, and curd also keeps a default grant keyed to the caller's scoping key (below) so later calls in the same session do not each prompt.
- **Session scoping key.** Which later calls share a grant is decided by a scoping key, resolved in order: (1) the value of a caller-named env var, default `CURD_SESSION_KEY`, if set — a harness that exposes a per-chat id (such as Cursor's chat id, or Claude Code's session id if it ever surfaces one as an env var) sets this, giving clean per-session grants and separating concurrent chats; (2) an explicit `--session-key <value>` on the call, where an agent that knows nothing better can pass something stable like `$(git rev-parse --show-toplevel)` or `$PWD`; (3) curd's own zero-config default, the git repo root or the controlling tty, both steadier than raw `$PWD`; (4) absent all of these, the grant is uid-global with a TTL. The key is a non-secret grouping label, not a capability: it only decides how grants are grouped, while the socket's uid check remains the real boundary, so a same-uid process reusing another session's key is the already-excluded local-process case (section 3). Directory-based keys are approximate: an agent that changes directory mid-task, or splits work across a monorepo, may re-prompt or over-share, which is why an explicit per-chat env var is preferred where available.
- **Explicit delivery (optional).** `curd run -- <command>` remains as a convenience for the launch-the-agent case (a human or harness starting the agent): it mints a grant, puts the token in the child's environment as `CURD_TOKEN`, runs the command, then revokes. It is not required for in-session use and does not apply to an already-running agent. A token reused explicitly travels via `--token` or `CURD_TOKEN`; this puts the token in the transcript, which is acceptable because it is a socket capability, not a site credential (section 3).
- **Delegation (post-v1 affordance).** Because tokens are opaque and server-side, the design can later add `grants.derive(token, narrower_scope)` to mint a weaker child token for a subagent (narrow only, never widen). The token model is built to allow this, but the narrowing logic (a scope lattice over domains, methods, paths, read/write, TTL) is not built in v1, since it only matters once agents spawn subagents with their own curd access.
- **Optional lineage binding.** `bound_to` can restrict a grant to the launched process tree; the default is uid only.
- **Audit.** The log stores a token hash, never the token.

### 6.4 Policy tamper resistance

Optional, and worth building only when curd is the agent's *sole* path to the credentials: hash policies at load and require native confirmation before a changed policy (or a widened method set) takes effect, so the agent cannot quietly loosen its own guardrail. If the agent also has raw shell with keychain access, it can bypass curd entirely and this check buys little, so it is not in v1. (It defends against the in-scope prompt-injected-agent threat, not the out-of-scope local-malware one.)

## 7. Interfaces

### 7.1 Socket and protocol

- Unix socket at `~/.local/run/curd.sock`, mode 0600. Verify peer uid via `LOCAL_PEERCRED`; record peer pid and executable path for audit (best effort).
- JSON-RPC 2.0, newline-delimited.

### 7.2 Methods

| Method | Purpose |
| --- | --- |
| `fetch(token, policy, method, url, headers?, body?)` | Brokered request. Returns `{status, headers, body, truncated}`. |
| `browse(token, verb, args)` | Drive the session's browser with a first-party verb (section 9). Never exposes CDP. |
| `open_session(token, policy[], ttl, allow_writes?)` | Start the ephemeral authenticated browser. Returns `{session_id, expires_at}`. No CDP endpoint is returned. |
| `close_session(token, session_id)` | Tear down the browser and temp profile. |
| `grants.request(policy[], scopes, ttl)` | Triggers the consent dialog. Returns a session token. |
| `grants.derive(token, narrower_scope)` | Mint a weaker child token (section 6.3). Post-v1. |
| `grants.list(token?)` / `grants.revoke(token_or_id)` | Inspect and revoke. |
| `status()` | Daemon health and source status. Policy names only, never values. |

There is deliberately **no** `get_credential` method.

### 7.3 CLI

One binary, `curd`, with subcommands. The daemon is `curd daemon`.

- `curd daemon` / `curd status`: run and inspect the long-lived process.
- `curd fetch <policy> [curl-style args]`: brokered request (replaces the old `authed-curl`).
- `curd browse <verb> [args]`: drive the session browser (section 9).
- `curd session open <policy...> [--ttl] [--write]` / `curd session close`: manage a browser session.
- `curd run -- <command>`: optional convenience for the launch-the-agent case. Mints a grant, puts the token in the child's environment as `CURD_TOKEN`, runs the command, then revokes. Not required for an already-running agent, which uses consent on first use (section 6.3).
- `curd grants ls | revoke <id>`
- `curd audit tail`
- `curd setup`: one-time keychain ACL setup (section 5.6).

Subcommands take the token from `CURD_TOKEN` or `--token` if present; otherwise the first credentialed call prompts for consent and the grant is reused via the session scoping key (section 6.3). A scoping key can be set explicitly with `--session-key` or the `CURD_SESSION_KEY` env var.

- `curd test-env up | down | run` (section 15.7).

### 7.4 MCP wrapper (out of scope for v1)

An MCP wrapper is not built for v1. For a local, single-user tool an agent that can run `curd fetch` and `curd browse` from a shell already has the full interface, and consent is owned by the native dialog (section 10) rather than client elicitation, so a wrapper adds little. It stays easy to add later: it would be thin and stateless, forwarding to the socket with the session token, and nothing in the daemon depends on it. The one thing it could add is surfacing consent inline in a client with good elicitation support, instead of via the native dialog.

### 7.5 Self-documenting for agents

curd's main user is an agent that cannot see this spec; it sees only what the binary tells it at the moment of use. So the CLI carries the mental model the way a skill does, and failures teach rather than just block.

- **Discovery explains the flow, not just flags.** `curd --help` and each subcommand's `--help` describe what curd does: cookies come from the browser profile, first use of a site triggers a consent dialog, grants are read-only by default and writes need a separate grant, and the explore to capture to distill to verify loop (section 16). `curd guide` prints the mental model in full. `curd policies ls` and `curd grants ls` let an agent orient before acting.
- **Errors name the fix.** Every denial and error states the next action: `denied_no_grant` says how to request one, `denied_method` says the write needs a write grant, `denied_path` shows the allowed paths, `auth_expired` says the user may need to be logged into the site in Chrome. A failure should leave the agent knowing what to do next.
- **Structured output on demand.** `--json` on any command that returns data (captures, grants, verify diffs, status) gives an agent a stable parse target instead of scraped text.
- **Dry-run.** `curd fetch --explain` reports which policy and grant would apply and whether the request is allowed, without sending it, so an agent can check its understanding before acting.

This is a hard interface requirement, not polish: an agent's success depends on it, and help and error text are tested like any other behavior.

## 8. Fetch broker behavior

For each `fetch` call:

1. Resolve the policy by host. No matching policy: deny.
2. Check for an active grant covering the method's scope. None: trigger consent or deny.
3. Check method, path, and inspector against the policy.
4. Build the upstream request:
   - Drop caller-supplied `Cookie`, `Authorization`, `Host`, and any header not in the allowlist.
   - Inject cookies by standard matching rules (domain, path, Secure) and any localStorage-derived header.
5. Send with a browser-like header set (User-Agent matching the installed Chrome). TLS/JA3 impersonation is out of scope: the targets are the user's own logged-in services, not anti-bot-protected sites, so a matching UA suffices. Revisit only if a real target turns out to fingerprint the TLS stack.
6. Redirects: follow only as the policy allows, re-evaluate the policy on each hop, never send credentials to an unmatched host.
7. Response: apply `Set-Cookie` to the jar, then strip it; enforce size caps; apply optional redaction.
8. Write the audit record.

**Errors:** `denied_no_policy`, `denied_no_grant`, `denied_method`, `denied_path`, `denied_inspector`, `auth_expired` (after one refresh retry), `upstream_error`.

## 9. Browser sessions

### 9.1 Launch

- Start Chrome with a fresh temp `--user-data-dir` (required for remote debugging since Chrome 136, and it also keeps the session off the real profile).
- Use `--remote-debugging-pipe`, never a port. curd holds the only connection to the browser; agents reach it only through \`browse\` verbs (section 9.6).

**Keychain.** Production sessions do not pass `--use-mock-keychain`. It makes the profile's encryption key a fixed, publicly known value, so anything persisted there would be readable by any process that can read the directory. Instead, credentials never reach disk: they are seeded only into the off-the-record context described in 9.2. The mock keychain is for test mode only (section 15.1).

**Verified** (Chrome 155, macOS, 2026-10-18): it does not; no keychain prompt appears for a temp profile without `--use-mock-keychain`. Original question: whether Chrome still touches the real `Safe Storage` item when it launches with a temp profile and no persisted cookies. If it does, the options are to accept the prompt, or to fall back to the mock keychain, which is acceptable only because nothing sensitive is ever stored in that profile. Section 9.4 adds a check for that guarantee.

### 9.2 Seeding

Two ways to get an authenticated browser, preferred first:

**Interactive login (preferred).** Open the temp browser to the site's login page and let the user sign in there directly. Nothing is hoisted: the session is created fresh inside the off-the-record context by the user's own login. This sidesteps credential seeding entirely, works regardless of where the site keeps its token (cookie, localStorage, sessionStorage, IndexedDB), and avoids the rotation-conflict and fingerprint problems of hoisting. The cost is a one-time human login per session.

**Cookie hoisting (alternative).** When no human is present, seed the session from the credential sources. All seeding goes into an off-the-record context created with `Target.createBrowserContext`; its storage is in-memory and never written to disk.

- Cookies for granted hosts via CDP `Storage.setCookies`.
- localStorage via script injection on first navigation to each origin (`Page.addScriptToEvaluateOnNewDocument` with an origin check), or `DOMStorage.setDOMStorageItem`.
- sessionStorage and IndexedDB are not seeded. If a real target turns out to keep its session token in one of these, the fix is to prefer interactive login for that site rather than to build seeding for them; seeding those stores stays a follow-up to investigate only if a concrete need appears (section 14).

### 9.3 Enforcement

- curd holds the sole CDP connection and never exposes it. Agents drive the browser only through first-party `browse` verbs (section 9.6), so credential-reading CDP methods (`Network.getAllCookies`, `Storage.getCookies`, `DOMStorage.*`, raw `Runtime.evaluate`) are not reachable: there is no API surface for them. This is an allowlist of verbs, not a denylist over raw CDP.
- curd enables `Fetch` interception on its own connection and applies the same method/path/inspector policy to every request the browser makes, and blocks navigation to hosts outside the policy.
- All browsing happens in one off-the-record context (section 9.2). curd creates targets only in that context; the agent cannot create another.

Because the agent reaches the browser only through `browse` verbs, there is no path for it to create another browser context or target, so it cannot write credentials into the default context's on-disk stores.

### 9.4 Lifetime

TTL-bound. On close or expiry: kill the process and delete the temp profile. In test mode, also assert that the profile's cookie database never contained any injected value.

### 9.5 Known limitations

- Refresh-token rotation can log the real browser out or invalidate the temp session. Keep sessions short.
- A fresh browser has a different fingerprint and may trigger re-auth or new-device alerts.

### 9.6 Browse verbs

curd exposes a small, first-party command surface over its sole CDP connection, in the spirit of tools like Rodney. The agent calls these through `curd browse <verb>` or the `browse` method; it never speaks CDP. The surface is an allowlist, so capabilities curd does not implement (reading cookies, dumping storage, arbitrary script on credentialed origins) do not exist for the agent.

Initial verbs: `open <url>`, `back`, `forward`, `reload`, `url`, `title`, `text <selector>`, `html <selector>`, `exists <selector>`, `visible <selector>`, `click <selector>`, `type <selector> <text>`, `focus <selector>`, `waitstable`, `waitidle`, `screenshot`, `pages`, `newpage`, `closepage`, `capture <subcommand>` (section 16).

**The `js` escape hatch is gated.** Arbitrary JavaScript can read `document.cookie` and localStorage, which would defeat the whole model, so `browse js` is not available by default. It requires an explicit `js` grant, is refused on any policy origin (only allowed on origins with no credentials loaded), and every evaluation is audited. Prefer the structured verbs; `js` is a last resort for a page the verbs cannot handle.

**Why first-party rather than exposing CDP.** It turns a denylist over a huge protocol into an allowlist over a dozen verbs, removes the TCP bootstrap, ticket, pid-binding, context-id rewriting, and event-stream redaction entirely, and keeps everything on the one unix socket with the token and policy model. The cost is maintaining the verb set instead of reusing Playwright MCP or Chrome DevTools MCP; the surface is deliberately small. Build on a CDP library such as `rod`, `chromedp`, or Playwright-as-a-library internally.

**To verify:** that the chosen verb set covers the real exploration tasks (a GraphQL dashboard's build history, a chat app's emoji upload, a usage page) without needing `js`.

## 10. Consent UX

- First request for a domain triggers a **native macOS dialog** (`osascript`), owned by the daemon so callers cannot drive it. It shows the domain, requesting process name and pid, scope (read or write), and duration.
- Choices: Allow once, Allow for duration, Deny.
- Write scope needs a separate explicit choice. Optional per-request confirmation for non-idempotent methods shows method, path, and a body summary.
- Revocation via CLI at any time; expiry silently ends grants.

## 11. Audit log

JSONL at `~/.local/state/curd/audit.jsonl`.

Fields: timestamp, client pid and executable, grant id, policy, method, path (query string redacted by default), decision, status, bytes, duration.

Never log headers, bodies, cookies, or token values. Rotate by size.

## 12. Security requirements

- Credentials exist only in daemon memory and are zeroed on exit.
- No credential value appears in any response, log, error message, or crash report.
- Socket permissions and peer-uid check enforced.
- Callers cannot supply their own `Cookie`, `Authorization`, or `Host`.
- No implicit subdomain matching; wildcards must be explicit.
- Redirects and cross-host credential sending governed as in section 8.
- Per-grant rate limit (optional, add if a runaway agent becomes a real problem).
- Policy tamper detection (optional) as in section 6.4.

## 13. Milestones

| Milestone | Scope |
| --- | --- |
| M1 | Daemon, cookie source, fetch broker, policy, CLI, audit. Includes test mode (section 15). Replaces the existing hand-written per-site scripts. |
| M2 | localStorage source, `inject_as`, native consent dialog, once and session grant modes. |
| M3 | Browser sessions and browse verbs: temp profile, interactive login or cookie hoisting into an off-the-record context, origin allowlist, first-party verb set (section 9.6). Session tokens; curd run optional. |
| M4 | Exploration and policy distillation (section 16): capture, redaction, the capture API, and distill with verify. Depends on M3. |
| M5 | Deferred, build only on demand: gated js verb, standing (persisted) grants, grants.derive delegation, the MCP wrapper (section 7.4), and sessionStorage/IndexedDB seeding. |

## 14. Open questions

- Follow-up: do any real target sites keep their session token in sessionStorage or IndexedDB rather than a cookie or localStorage? If so, interactive login (section 9.2) is the intended answer; building seeding for those stores is only worth it if a concrete, common case appears.
- Pin one Chrome profile per policy, or auto-detect?
- Is write-back of rotated cookies ever worth it?
- Firefox and Safari support?
- Better client identity than pid and path (code signing, parent-process chain)?
- Should delegated child tokens (grants.derive) be able to extend TTL within the parent's maximum, or only shorten it? Also: what is the best zero-config default scoping key (git repo root vs controlling tty), given that Claude Code does not currently expose a per-session env var while some harnesses like Cursor do?

## 15. Test mode and fixtures

Test mode runs curd end to end with no real Chrome profile, no keychain, no real logins, and no human at the consent dialog. It is for the project's own e2e tests, CI, and autonomous agents developing the daemon or skills that use it.

### 15.1 Mock keychain

Chromium has a switch, `--use-mock-keychain`, that makes Chrome on macOS derive its cookie key from a fixed built-in test password instead of the real keychain item. The derivation is unchanged (PBKDF2, salt `saltysalt`, 1003 iterations, AES-128), so the daemon can decrypt such a profile with no keychain access.

- **Chrome-made fixture profile.** Launch Chrome with a temp `--user-data-dir` and `--use-mock-keychain`, seed synthetic cookies and localStorage via CDP, then quit. The result is a real Chrome profile that exercises the real SQLite and LevelDB parsing.
- **Key provider interface.** `keychain` (real), `mock` (Chrome's fixed test password), `static` (key from test config, for hand-built fixtures).
- **Verified** (Chrome 155.0.8059.82, macOS, 2026-10-18): release Chrome honors `--use-mock-keychain` and the mock password is `mock_password`; pinned by `internal/fixture`'s Chrome-made-profile test. Original note: the exact mock password in current Chromium (older source hard-coded `mock_password`; newer source routes through a mock keychain class), and that release Chrome honors the switch, not only test builds. Pin both with a test that makes a fixture using the installed Chrome and decrypts it.

The mock keychain is for test mode and fixture creation only. Production browser sessions never use it (section 9.1).

### 15.2 Static source

A fixture file (YAML or JSON) can supply cookies and localStorage entries per origin directly, with no Chrome at all. This is the fastest path for unit-level e2e tests of policy, injection, and the fetch broker.

### 15.3 Mock upstream

A local HTTP server on 127.0.0.1 with scripted routes. It records every request so tests can assert exactly which `Cookie` and `Authorization` headers were injected, and can return `Set-Cookie`, redirects, 401s, and GraphQL mutations. Test policies keep realistic hostnames and map them to the mock with `test.host_map`, honored only in test mode. Plain HTTP is allowed only in test mode.

### 15.4 Scripted consent

Test mode replaces the native dialog with a scripted responder: `--consent=allow-all`, `--consent=deny-all`, or `--consent=script:<file>`. A script lists the expected prompts and answers, and the run fails if an unexpected prompt appears.

### 15.5 Isolation rules

These keep test mode from becoming a way around the real consent model.

- Test mode is a separate instance: its own socket path, state dir, policy dir, and audit log. It is chosen at launch and cannot be switched at runtime.
- In test mode the daemon refuses to open any real Chrome profile and never queries the real keychain.
- Outside test mode the daemon refuses fixture sources, the `mock` and `static` key providers, `test.host_map`, plain HTTP, and scripted consent. These checks sit in the credential-source layer and startup, not just flag parsing.
- Audit records from test mode are tagged as test.
- Because test mode only ever holds synthetic credentials, an agent that auto-approves every prompt exposes nothing real.

### 15.6 Coverage

| Scenario | Covered in test mode |
| --- | --- |
| Policy allow and deny by method, path, inspector (including GraphQL mutation block) | Yes |
| Cookie matching (domain, path, Secure) and explicit-wildcard host rules | Yes |
| Redirects, and no credentials sent to unmatched hosts | Yes |
| 401, reload, retry once | Yes |
| `Set-Cookie` applied to the jar and stripped from responses | Yes |
| Grant modes, expiry, revocation via scripted consent | Yes |
| localStorage extraction from a Chrome-made LevelDB fixture | Yes |
| Browser session seeding, origin allowlist, CDP filtering against the mock site | Yes |
| Audit log never contains credential values | Yes |
| Real-site behavior: bot detection, token rotation, fingerprint checks | No, manual |
| Real keychain ACL behavior and signing identity (section 5.6) | No, manual smoke test |

### 15.7 CLI

- `curd test-env up`: build fixtures, start the mock upstream and the test daemon, print the test socket path.
- `curd test-env down`: tear everything down and delete the fixtures.
- `curd test-env run -- <command>`: up, run the command with the test socket in its environment, then down. This is the entry point for CI and for agents.

## 16. Exploration and policy distillation

Some tasks need a browser the first time, to find the API and learn request shapes, but should run as plain brokered requests afterward. This section defines how an agent explores in a browser session and ends with a verified draft policy.

### 16.1 Workflow

1. **Explore.** The agent opens a browser session (section 9) and drives it with \`browse\` verbs (section 9.6). It does the task once through the UI.
2. **Capture.** The daemon records all network traffic on its own CDP connection. The agent reads it through the capture API, with credentials replaced by placeholders.
3. **Distill.** The agent selects the requests that matter. The daemon generates a draft policy and matching `curd fetch` commands.
4. **Replay-verify.** The agent re-runs each candidate request through the fetch broker with plain `curd fetch`, which reads cookies from the Chrome profile (its normal source) and sends the request with no browser. Because the user is logged into the site in that profile, this verifies against the exact credentials the production script will use: what verifies is what ships. The agent fixes what differs (a missing CSRF token, a dynamic parameter, a header) and repeats.
5. **Approve.** The draft stays inactive until the user confirms it in a native dialog (section 6.4).

This workflow assumes **profile-backed discovery**: the user is logged into the target site in their real Chrome, so discovery and the production script draw cookies from the same profile and verification with plain `curd fetch` is faithful. **Interactive-login discovery** (section 9.2), where the login lives only in the temp browser and never touches the profile, is a different mode: there is no profile credential to verify a distilled script against, so that mode suits ongoing browse-verb automation that logs in each run, not a distilled `curd fetch` script. Distill-to-a-script is for the profile-backed path.

### 16.2 Capture

- The daemon records requests, responses, the `ExtraInfo` events that carry raw headers, request and response bodies (size-capped, held in memory, discarded at session close), and each request's initiator.
- **Redaction at capture time.** `Cookie`, `Authorization`, and `Set-Cookie` values, and any other value equal to a credential the daemon holds, are replaced with placeholders such as `{cookie:session}` or `{ls:https://app.example.com:authToken}`. The scan covers headers, URLs, and request and response bodies, by exact match.
- **Redaction on everything the agent can read.** ``Anything a `browse` verb or the capture API returns (page text, response bodies, capture listings) goes through the same filter. Since the agent has no raw CDP access, there is no separate event stream to leak`` cookies.
- Redaction covers values the daemon holds. A secret minted server-side during the session and returned in a response body, such as a fresh CSRF token, is not a held credential and stays visible. The agent needs it to understand the request flow.

### 16.3 Capture and distill API

| Method | Purpose |
| --- | --- |
| `capture.list(session_id, filter?)` | Request summaries: id, method, URL, status, resource type, size, initiator. |
| `capture.get(id, parts?)` | One request or response with redacted headers and bodies. |
| `capture.find_source(session_id, value)` | Which earlier response, URL, or page content produced a given non-credential value, such as a CSRF token or an id. This traces request dependencies. |
| `capture.export(session_id, ids[])` | Redacted HAR. |
| `distill.draft(session_id, ids[])` | Draft policy YAML plus `curd fetch` commands. |
| `distill.verify(draft, capture_id)` | Replay through the broker under the draft policy and diff status and response shape against the capture. |

### 16.4 Distillation rules

- **Narrowest policy.** Method plus path regex per request, with numeric and UUID path segments generalized. No broader than what was captured.
- **Header allowlist.** Only the headers the request needs, found by removing headers one at a time during verify.
- **Credential scope.** Only the cookie names actually sent on those requests. For localStorage, a header value equal to a held localStorage value yields the `inject_as` rule.
- **GraphQL.** Add `graphql_query_only`, and optionally an allowlist of operation names or persisted-query hashes.
- **Writes.** Captured non-GET requests appear in the draft as disabled `write` entries, enabled only when the user includes them explicitly.
- **Status.** Drafts are marked `status: draft` and are inert until confirmed.

### 16.5 Writes during exploration

- By default an exploration session is read-only. The daemon intercepts non-safe methods and GraphQL mutations through the CDP `Fetch` domain, records them, fails them with a synthetic error, and marks them `blocked_write` in the capture. The agent still learns the request shape, for example for a write endpoint like an upload, without executing it.
- A write grant for the session lets them through, with the usual native confirmation. Recommend using it only on a throwaway account or workspace.
- Blocking a write can break UI flows that depend on it succeeding. That is an accepted cost.
- GET requests with side effects cannot be detected. Policy review covers that.

### 16.6 How the agent drives exploration

Because exploration uses the first-party `browse` verbs (section 9.6) rather than an external browser tool over CDP, the whole attach apparatus from earlier drafts, which exposed a filtering CDP endpoint over a loopback TCP port with a single-use ticket and pid binding, is gone. There is no TCP listener, no ticket, no context-id rewriting, and no CDP event-stream redaction. The agent calls `browse open`, `browse click`, `browse text`, and so on over the same unix socket, with the same session token, and curd captures traffic on its own sole CDP connection.

Capture is internal: curd already holds the CDP connection, so `Fetch` and `Network` events feed the capture store directly (section 16.2). The agent reads captures only through the capture API, which is redacted. Playwright MCP and Chrome DevTools MCP are not involved in the credentialed path at all.

**Pages and contexts.** curd creates all pages in the one off-the-record context (section 9.2) and the agent cannot create another, so there is no context confusion to manage and no cookie-returning call (`context.cookies()` and the like) to block, because those verbs do not exist.

**Limitation.** If the verb set cannot handle some page interaction, the fallback is the gated `js` verb (section 9.6), which needs its own grant and is refused on credentialed origins. A task that genuinely needs arbitrary scripting on a logged-in origin is a signal to use a full browser tool outside curd for that step, accepting that it then has whatever access that tool has.

**To verify.** That the `browse` verb set covers the real exploration tasks without `js` (tracked in section 9.6), and that capturing on curd's own `Fetch`/`Network` connection sees every request the page makes, including preflights and redirects.

The earlier open items about attaching Playwright MCP or Chrome DevTools MCP, the `ws+unix://` question, and the loopback connection-owner lookup no longer apply, since none of that machinery exists in this design.

### 16.7 Safety properties

- The agent never sees held credential values: redaction applies in the capture API and on the CDP stream.
- The session is broad (the whole UI, as the user) but the output is narrow (a draft policy for specific endpoints).
- Drafts are inert until confirmed, and the policy tamper rule (6.4) applies.
- Exploration sessions are audit-logged and tagged `explore`.

### 16.8 Testing and milestone

- In test mode, the mock upstream serves a flow with a CSRF token embedded in a page and echoed in a POST. Tests assert that distill produces a policy that passes verify, and that no held credential value appears in any capture API output or CDP stream.
- **This is milestone M4 (capture, redaction, the capture API, and distill with verify), which depends on the browser sessions in M3**.

## 17. Implementation

**Language: Go.** It fits the requirements with the least friction: a single statically-linked binary (which the keychain code-identity story in section 5.6 depends on, since there is no interpreter whose identity muddies the ACL), first-class concurrency for a daemon juggling the unix socket, the browser connection, and capture at once, and mature CDP libraries.

**Load-bearing library choice.** The browse-verb safety model (sections 9.3, 9.6) requires curd to hold the *sole* CDP connection and to intercept and filter at the `Fetch` and `Target` level. So whichever CDP library is used (`rod` or `chromedp`) must expose raw CDP commands and event subscription, not only a high-level API. Confirm this before building on it; it is the one choice that is expensive to reverse.

**Other pieces, all straightforward in Go:** cookie decryption is hand-rolled AES (keychain key via cgo to the macOS Security framework, or a thin wrapper); LevelDB reading via a Go reader or cgo bindings; SQLite for the cookie DB; the unix-socket RPC and native `osascript` dialog are standard.

**Build order: front-load the Chrome-internals unknowns.** These are the parts most likely to surprise, so implement and test them first, against the installed Chrome, before building the daemon around them:

- Cookie decryption for the installed Chrome version, including any version-specific plaintext prefix (section 5.1).
- LevelDB localStorage read with `.log` replay and the key/value encoding (section 5.2).
- The `--use-mock-keychain` behavior and current mock password, verified by making a fixture and decrypting it (section 15.1).
- One authenticated `curd fetch` end to end against a real logged-in site.
- The chosen CDP library holding the sole connection with `Fetch`/`Target` interception working (above).

Once these are proven, the rest (policy engine, grants, tokens, browse verbs, capture, distill) is ordinary application code and follows the milestones in section 13.
