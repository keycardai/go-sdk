# AGENTS.md

Context for coding agents working in keycardai/go-sdk. CLAUDE.md points here.

## What this repo is

The root Go module is `github.com/keycardai/go-sdk` (Go 1.23.0). `doc.go` marks it preview: APIs may change between minors until 1.0.

Packages (dependency direction in parentheses):

- `oauth`: OAuth 2.0 primitives: JWT sign/verify, JWKS keyring, token exchange (RFC 8693), discovery, device authorization, refresh, userinfo, application credentials (`ClientSecret`, `WebIdentity`, `WorkloadIdentity`). Depends on no sibling.
- `mcp`: MCP server/client auth: `RequireBearerAuth` (`net/http` middleware), `AuthMetadataHandler`, `AuthProvider`/`AccessContext`, `Grant` (depends on oauth). Re-exports moved credential types as deprecated aliases.
- `a2a`: agent-to-agent delegation client: card discovery, token exchange, JSON-RPC invoke (depends on oauth).
- `policy`: Cedar policy bundle encode/decode, digest, evaluation (depends on cedar-go and jcs, no sibling).
- `spiffe`: SPIFFE JWT-SVID workload identity source (depends on oauth). The optional `github.com/keycardai/go-sdk/spiffe` module (Go 1.24.0) keeps go-spiffe and gRPC out of the root module. Its `replace github.com/keycardai/go-sdk => ..` directive tests against the root checkout; downstream consumers use the declared root requirement.
- `examples/*`: runnable examples. Most are in the root module; `examples/mcp-server-official` and `examples/mcp-server-mark3labs` are separate modules with `replace github.com/keycardai/go-sdk => ../..`.

## Build, test, lint

For the root module, CI runs these commands (`.github/workflows/ci.yml`) on Go 1.23 and 1.25:

```sh
go vet ./...
go test -race -count=1 ./...
go build ./examples/...
```

The SPIFFE module runs separately (CI job `test-spiffe`, Go from `spiffe/go.mod`):

```sh
cd spiffe
go vet ./...
go test -race -count=1 ./...
```

The two MCP framework example modules run separately (CI job `test-examples`, Go from each example's go.mod):

```sh
cd examples/mcp-server-official   # and examples/mcp-server-mark3labs
go build ./...
go vet ./...
go test -race -count=1 ./...
```

`./...` from the root does not reach nested modules. Run the SPIFFE checks when you touch `spiffe` and the example checks when you touch `mcp`. No golangci-lint, Makefile or other linter config is in the repo; `go vet` is the lint gate.

## Commits and releases

Conventional commits, `type(scope): description`. Validated on PRs with `cz check --rev-range <merge-base>..HEAD` (`.cz.toml`).

- The root module has one version, so the scope does not select a package or module to release. Scopes include `oauth`, `mcp`, `a2a`, `policy`, `spiffe`, `examples`, multi-scope `mcp, oauth`, or none.
- Release-triggering types (`changelog_pattern`): `feat`, `fix`, `refactor`, `perf`, `test`, `build`, `ci`, `revert`, with any or no scope. `docs` and `chore` do not release.
- Breaking change: `!` after the type/scope (`fix(oauth)!: ...`). `major_version_zero = true`, so breaking changes land as minors while the module is 0.x.
- Merge to `main` runs `main.yml`, which runs `scripts/bump.py`: `cz bump --changelog --yes`, then pushes the bump commit and a `v<version>` tag to main using the release app token. The Go module proxy serves the tag; there is no publish workflow.
- The SPIFFE module requires separate `spiffe/vX.Y.Z` tags, which `scripts/bump.py` does not produce. Before tagging SPIFFE, ensure its declared root requirement contains the OAuth APIs it uses.
- Never hand-edit the root `.cz.toml` version, root release tags or `CHANGELOG.md`; the bump job owns them. A bad release is retracted in `go.mod` (see `retract v0.14.0`), not by editing tags.

## Spec first

- Behavior changes start as a PR in keycardai/keycard-sdk-spec (`specs/<area>/<name>.md`, with a Unit Tests table of rows and a Divergences section). Implement against the merged spec's rows.
- Tests here cite rows in a comment above the test, not in the name, e.g. `// Spec row 1: valid token, endpoint returns claims JSON.` (`oauth/userinfo_test.go`, `mcp/multizone_test.go`). Do the same for new spec-driven tests.

## Testing rule

- Tests, CI and examples are hermetic only: no live Keycard zone. Use `net/http/httptest` stand-ins as the existing tests do. keycardai/templates' eval owns live-zone coverage.
- Tests must pass under `-race`.

## Idioms and gotchas

- The root module stays free of go-spiffe, gRPC and MCP framework dependencies. Anything that needs `modelcontextprotocol/go-sdk` or `mark3labs/mcp-go` goes in an example module (stated in `ci.yml`). Root direct deps: `golang-jwt/jwt/v5`, `cedar-go`, `gowebpki/jcs`, `x/sync`. SPIFFE direct deps: the root module, `github.com/spiffe/go-spiffe/v2`, and `google.golang.org/grpc`.
- Errors: every `oauth` error implements the `KeycardError` marker interface; callers use `errors.As`. Concrete types include `ConfigurationError`, `HTTPError`, `OAuthError` (carries `Err` for unwrapping). `mcp` aliases oauth error types; `a2a` and `policy` have their own `errors.go`.
- Construction uses functional options (`mcp.WithZoneURL`, `oauth.WithAudiences`, ...).
- Credentials live in `oauth`; the `mcp` names are `// Deprecated:` aliases kept for compatibility. Add new credential code to `oauth`; keep the SPIFFE token source in `spiffe`.
- `NewZoneTokenVerifier` without `oauth.WithAudiences` accepts tokens for any resource in the zone and warns; keep examples audience-bound.
- With the official MCP go-sdk, auth must come from `req.Extra.TokenInfo`, not the handler context (stateful sessions freeze the initialize context). See README "Serving MCP".
