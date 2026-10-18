# curd

**Cookie Ushering Retrieval Daemon.** curd lets scripts and agents use the
logins you already have in Chrome without ever handling the credentials.

A local daemon reads cookies and localStorage tokens from your Chrome profile
and keeps them in memory. It then serves two things over a unix socket:

- **A fetch broker** (`curd fetch`). This is a policy-enforcing HTTP client
  that injects the credentials itself. Callers never receive cookie or token
  values, and no command can return one.
- **A browser tool** (`curd session` / `curd browse`). This is a small,
  first-party set of verbs that drive an ephemeral, pre-authenticated Chrome.
  curd holds the only CDP connection, and raw CDP is never exposed.

Access is per site and governed by **policies**, YAML files that list allowed
hosts, methods, paths and body inspectors such as "GraphQL queries only".
Access is also governed by **grants**: scoped, expiring consent from a native
dialog. Grants are read-only by default; writes need their own grant. Every
request is audited.

curd is a policy and hygiene layer, not a security boundary against malware
already running as you. See `notes/spec.md` section 3 for the threat model.

## Quick start (macOS, Chrome)

```sh
go build -o bin/curd ./cmd/curd
bin/curd setup                                   # optional: one-time keychain "Always Allow"
bin/curd policies new mysite --host app.mysite.com   # read-only GET/HEAD template
bin/curd fetch mysite https://app.mysite.com/api/me  # first use shows a consent dialog
bin/curd guide                                   # the full mental model
```

## Exploring a site with no policy yet

If you don't know a site's API, explore it in the browser, then distill what
you did into a policy. The loop is explore, capture, distill, verify, approve:

```sh
curd session open mysite --explore
curd browse open https://app.mysite.com/builds
curd browse capture list
curd distill draft mysite-api c12 c15
curd distill verify mysite-api --minimize
curd policies approve mysite-api
```

## Test mode

Test mode is a separate daemon instance with synthetic credentials, a mock
upstream and scripted consent. It never touches the real profile or keychain:

```sh
curd test-env run -- sh -c 'curd fetch "$CURD_TEST_BASE/api/me"'
```

## Development

```sh
make hooks   # pre-commit: gofmt, vet, darwin cross-build, go test -short
make test    # everything, including tests that launch Chrome/Chromium
```

The code layout is in `notes/plan.md`. What still needs checking on a real
Mac (keychain, consent dialog, signing, real sites) is in
`notes/manual-testing.md`.
