## v0.7.0 (2026-06-29)


- ci: match scoped commits in the cz changelog pattern (#20)
- The customize changelog_pattern lacked a scope group, so a scoped subject such
as "feat(oauth): ..." did not match. bump.py gates on `cz changelog --dry-run`,
which therefore reported no unreleased changes and skipped the release: the
impersonation feat (#12) merged but never cut a version. Add the optional
(\(.+\))? scope group so scoped conventional commits are recognized.
- Verified with cz against current main: `cz changelog --dry-run` now lists the
unreleased feat(oauth) commit, and `cz bump --dry-run` reports
0.6.0 -> 0.7.0 (MINOR). Unscoped commits still match; chore still does not.
- Co-authored-by: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
- feat(oauth): implement user impersonation via substitute-user token exchange (ECO-92) (#12)
- * feat(oauth): implement user impersonation via substitute-user token exchange
- Add TokenExchangeClient.Impersonate per
specs/delegated-access/impersonation.md. Mints the actor token from the
client's application credential via a client_credentials grant, then
performs an RFC 8693 exchange with an unsigned substitute-user subject
token carrying the target user identifier.
- - ImpersonateRequest: UserIdentifier (req), Resource (opt), Scopes (opt)
- buildSubstituteUserToken + SubstituteUserTokenType vendor URN
- Tests cover the spec unit-test table
- * docs(oauth): add runnable impersonation example
- Adds a background-agent example demonstrating user impersonation via
token exchange (oauth.TokenExchangeClient.Impersonate), matching the
Impersonation spec. Configured via environment variables; run with
`go run ./examples/impersonation`.
- Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
- * fix(oauth): require resource for impersonation and reuse the client-credentials grant
- Two follow-ups to align Impersonate with the spec and reduce duplication:
- - Require ImpersonateRequest.Resource. The impersonation spec marks resource
  as required (unit-test row 4: "resource omitted -> client-side validation
  error"); validate it before any network call, alongside UserIdentifier.
- Mint the actor token by reusing the existing ClientCredentialsClient instead
  of a hand-rolled client_credentials POST. TokenExchangeClient now lazily
  builds and caches a ClientCredentialsClient sharing its issuer, credentials,
  and HTTP client, so the grant logic and its error handling live in one place
  and the actor-token endpoint is discovered once.
- Tests updated: the two OAuth-error cases now pass a resource so they reach the
exchange, and the former resource-optional test is replaced by one asserting
local rejection when resource is missing.
- Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
- ---------
- Co-authored-by: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
Co-authored-by: Larry-Osakwe <larryosak@gmail.com>

## v0.6.0 (2026-06-29)


- feat: add dynamic client registration (#16)
- Implements the dynamic-client-registration spec (RFC 7591) in the oauth
package. Go previously parsed registration_endpoint during discovery but
had no call that posted to it.
- - RegisterClient(ctx, issuer, req, opts...) discovers the registration
  endpoint and POSTs the client metadata as JSON.
- RegistrationRequest models the RFC 7591 §2 metadata (all optional,
  RFC-minimal: only set fields are sent) with an AdditionalMetadata bag
  merged into the body; named fields win on conflict.
- RegistrationResponse parses client_id (required), client_secret,
  issuance/expiry timestamps, and the registration management
  token/URI, preserving the full raw body for AS-specific fields.
- WithInitialAccessToken authenticates the request with a Bearer initial
  access token (RFC 7591 §3.1); a structured 4xx error body surfaces as
  a typed *OAuthError, otherwise as an *HTTPError.
- Tests cover body merging (named over vendor keys, RFC-minimal omission),
response parsing, the missing-client_id error, the typed OAuth error,
and the initial-access-token header.
- Co-authored-by: Claude Opus 4.8 (1M context) <noreply@anthropic.com>

## v0.5.0 (2026-06-29)


- feat: add authorization-code-with-PKCE flow (ECO-90) (#15)
- * feat: add authorization-code-with-PKCE flow
- Implements the authorization-code-pkce spec in the oauth package, the
user-facing login primitive the Go SDK was missing entirely.
- - PKCE primitives: GenerateCodeVerifier (128-char, RFC 7636 §4.1),
  GenerateCodeChallenge (S256 / plain), GeneratePKCEPair.
- Building blocks: BuildAuthorizeURL and ExchangeAuthorizationCode
  (public client sends client_id in the body; confidential client uses
  HTTP Basic and omits it), reusing discovery and the shared token
  response shape.
- High-level Authenticate / AuthenticateFromChallenge: generate a PKCE
  pair and CSRF state, open the browser, run an RFC 8252 loopback server
  (default port 8765, 300s timeout), validate state, and exchange the
  code. ResolveIssuerFromChallenge resolves the issuer from an RFC 9728
  WWW-Authenticate challenge. Browser launch uses exec.Command (no
  shell) and is overridable for tests.
- Tests cover the PKCE primitives (incl. the RFC 7636 known-answer
vector), the authorize-URL builder, public/confidential code exchange,
OAuth error responses, the full loopback flow in-process via an injected
browser opener, CSRF state-mismatch rejection, and challenge-driven
issuer resolution.
- Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
- * fix: ignore non-GET requests to the loopback callback
- The loopback callback handler processed any HTTP method, so a stray
non-GET request (an OPTIONS probe, a scanner) with no query would fall
through to the missing-code branch and push an error to the one-shot
result channel, aborting the login before the real GET redirect arrived.
Guard the method: non-GET now returns 405 and is ignored, so only the
browser's GET redirect completes the flow.
- Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
- * test: add runnable Example functions for PKCE primitives
- ExampleGenerateCodeChallenge and ExampleBuildAuthorizeURL are Go testable
examples: `go test` runs them and verifies their output, so the PKCE
primitives are proven-to-run in CI without needing a live zone. They
also render as usage docs on pkg.go.dev.
- Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
- ---------
- Co-authored-by: Claude Opus 4.8 (1M context) <noreply@anthropic.com>

## v0.4.0 (2026-06-24)


- ci: push version bumps with the GH_REPO_ACCESS app token
- The "Merge to Main" bump job pushed the version-bump commit with the
default GITHUB_TOKEN, which cannot push to main: the org ruleset
requires changes via PR, so the push is rejected (GH013) and the job
fails on every releasable merge (e.g. #13, #14).
- Switch to the GH_REPO_ACCESS GitHub App token via
actions/create-github-app-token@v2, fed into checkout — the same token
python-sdk and typescript-sdk use to push releases. bump.py already sets
its own git identity, so only the token wiring changes.
- Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
- test: prove bearer middleware enforces issuer and audience binding
- Drives real signed JWTs through RequireBearerAuth with a hardened
verifier, covering the bearer-token-verification-middleware conformance
cases: a valid token populates client_id / scopes / resource / expiry;
an untrusted issuer and a token issued for a different audience are
rejected with 401 invalid_token; a non-bearer scheme returns 401; and a
nil verifier panics at construction (an auth boundary with no verifier
is a programming error caught at startup, not a runtime condition).
- Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
- feat!: enforce RFC 9068 claims and issuer/audience allowlists in JWT verifier
- Aligns the Go JWT verifier with the jwt-signing-and-verification spec
contract. The verify surface is fail-closed: algorithm and issuer are
checked against allowlists before any key resolution or network I/O, so
a token carrying an attacker-controlled iss cannot drive key lookup to
an untrusted endpoint.
- - NewJWTVerifier requires a trusted-issuer allowlist and returns a
  ConfigurationError on empty issuers or an unsupported algorithm.
- Adds WithAudiences and WithAlgorithms (default ["RS256"], "none"
  always rejected) alongside WithVerifierLeeway.
- Verify enforces the full RFC 9068 §2.2 required-claim set
  (iss, sub, aud, exp, iat, client_id), a present kid, and audience
  intersection when audiences are configured, matching Python and TS.
- The mcp bearer surface follows the spec's intended Go idiom of a
verifier-first middleware:
- - RequireBearerAuth takes the verifier as a required positional
  argument; trusted issuers and audience live on the verifier, not the
  middleware, so there is no second "issuer" concept and no internal
  construction that could fail silently.
- NewJWTOAuthTokenVerifier threads the issuer allowlist and forwards the
  oauth verifier options; NewZoneTokenVerifier is the single-zone
  convenience that builds the JWKS keyring for you.
- BREAKING CHANGE: NewJWTVerifier(keyring) becomes
NewJWTVerifier(keyring, issuers, opts...) (*JWTVerifier, error);
NewJWTOAuthTokenVerifier(keyring) becomes
NewJWTOAuthTokenVerifier(keyring, issuers, opts...) (*JWTOAuthTokenVerifier, error);
and RequireBearerAuth(opts...) becomes RequireBearerAuth(verifier, opts...)
(the WithVerifier option is removed).
- Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>

## v0.3.0 (2026-04-26)


- feat: add ClientCredentialsClient for autonomous workload access
- Add oauth.ClientCredentialsClient alongside TokenExchangeClient to
support RFC 6749 Section 4.4 client_credentials grants. This enables
workloads to authenticate directly (e.g., via OIDC workload identity)
and retrieve Vault-managed credentials without a subject_token.
- Follows the same patterns as TokenExchangeClient:
- Lazy metadata discovery via sync.Once
- Functional option configuration
- Shared deserializeTokenResponse for response parsing
- OAuthError for structured error handling
- Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>

## v0.2.0 (2026-04-01)


- ci: add commitizen for automated version bumping
- Set up commitizen for automatic version management with conventional
commits. On merge to main, detect unreleased changes and auto-bump
version with changelog generation and v-prefixed tags.
- - Add .cz.toml config with v${version} tag format
- Add scripts/bump.py for version bumping with push retry logic
- Add main.yml workflow for auto-bump on merge
- Add commit validation to CI for pull requests
- Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
- feat!: detailed error reporting for token exchange failures
- Port structured error reporting from Python SDK (keycardai/python-sdk#80).
- OAuth layer:
- Token exchange HTTP errors now return *OAuthError with ErrorCode,
  Message (error_description), and ErrorURI instead of fmt.Errorf
- Added test for non-JSON error responses
- MCP layer:
- ErrorDetail: rename Error field to Message, add Code and Description
  fields for structured OAuth error info
- GetErrors() named return: resourceErrors → resources
- ExchangeTokens uses errors.As to extract OAuthError fields into
  ErrorDetail, or RawError from generic errors
- BREAKING CHANGE: ErrorDetail.Error renamed to ErrorDetail.Message
(JSON key: "error" → "message"), new Code/Description fields added
- Refs: AGE-58
- Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
