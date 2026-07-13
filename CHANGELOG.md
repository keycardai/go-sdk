## v0.14.0 (2026-07-13)


- feat(policy): add policy bundle package with tar+gzip codec
- Adds github.com/keycardai/go-sdk/policy — a pure format layer for
Keycard policy bundles (Cedar schema + policy set + manifest). Includes
a deterministic tar+gzip codec, decompression-bomb protection, and a
JCS-canonical manifest digest (RFC 8785) for content-addressed ETags.
- Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>

## v0.13.1 (2026-07-08)


- fix: allow for non-actor impersonation (#29)
- * fix: allow for non-actor impersonation
- * fix: remove actor_token

## v0.13.0 (2026-06-30)


- feat(mcp)!: tighten WebIdentity assertion + storage; add seed AccessContext (ECO-94) (#27)
- * feat(mcp)!: tighten WebIdentity assertion + storage; add seed AccessContext (ECO-94)
- Closes the last two ECO-94 items.
- WebIdentity:
- Add WithClientID: the assertion's iss/sub are the registered OAuth client id, with a
  request-time resource_client_id override. Drop the key-id fallback for iss and the
  iss fallback for aud, per RFC 7523; PrepareTokenExchangeRequest now returns a
  WebIdentityConfigurationError when the client id or token endpoint is missing.
- Default key storage is now ./server_keys, falling back to the legacy ./mcp_keys when
  it exists, matching Python/TS.
- Add WithAudienceConfig to override the assertion audience.
- AccessContext:
- Add NewAccessContextWithTokens, the seed-token constructor present in Python/TS.
- BREAKING CHANGE: a WebIdentity credential now requires a client id (WithClientID or a
request-time resource_client_id) and a token endpoint; it no longer falls back to the
local key id. The default key storage directory is ./server_keys (with ./mcp_keys as a
legacy fallback).
- Aligns with the WebIdentity spec contract (iss=sub=client_id, aud=token_endpoint); where
Python and TS differ on client-id sourcing, this follows the TS model (optional
construction-time client id, request-time override).
- Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
- * fix(mcp): reject a WebIdentity credential without a client id at provider construction
- Addresses the #27 review: the bundled AuthProvider never supplies resource_client_id, so
a WebIdentity credential built without WithClientID would fail every exchange with a
runtime config error. NewAuthProvider now rejects it at construction (matching the
fail-loud principle from #23), and WithClientID's doc states it is required for the
provider flow.
- Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
- ---------
- Co-authored-by: Claude Opus 4.8 (1M context) <noreply@anthropic.com>

## v0.12.0 (2026-06-30)


- feat(mcp)!: move AccessContext to oauth and add the Grant decorator (ECO-94) (#26)
- * feat(mcp)!: move AccessContext to oauth and add the Grant decorator (ECO-94)
- Moves AccessContext, AccessContextStatus, ErrorDetail, and ResourceAccessError
from mcp to the oauth package (oauth/access_context.go), so the oauth client
surface can return them without importing mcp. The mcp package re-exports all of
them as type aliases, so existing mcp.AccessContext usage keeps compiling.
Matches the Python/TS layout, where AccessContext lives in oauth. Adds
AccessContext.Merge for stacked grants.
- Adds grant-decorator options to AuthProvider.Grant:
- WithUserIdentifier(func(*http.Request) (string, error)): impersonate the
  resolved user (RFC 8693 substitute-user, via oauth.Impersonate) per resource
  instead of exchanging the caller's token; a resolver error fails closed.
- WithRequestScopes(...): scopes requested for each resource's token.
Stacked Grant middlewares now merge into a single AccessContext on the request.
- BREAKING CHANGE: AuthProvider.Grant's signature is now
Grant(resources []string, opts ...GrantOption) (was Grant(resources ...string)),
to carry the options. The two examples are updated.
- Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
- * fix(mcp): steer impersonation to the verified subject and align grant merge with TS
- Addresses the #26 review:
- Expose AuthInfo.Subject (the verified sub claim) and steer WithUserIdentifier's
  doc and example to it, so the impersonation subject is derived from the verified
  token, not unverified request data (otherwise an impersonation footgun).
- AccessContext.Merge is now last-wins on the global error, matching the TypeScript
  convention for stacked grants.
- Document that WithRequestScopes is flat: caller scopes win over the credential's,
  and stacking single-resource grants gives per-resource scopes.
- Assert requestScopes reach the impersonation exchange; add AccessContext.Merge tests.
- Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
- * feat(mcp): support per-resource request scopes (WithRequestScopesByResource)
- Adds WithRequestScopesByResource(map[string][]string) so a single multi-resource
Grant can request different scopes per resource, with WithRequestScopes as the
fallback for resources absent from the map. Closes the per-resource half of the
TypeScript requestScopes surface (string | string[] | Record<resource, scopes>)
rather than leaving it to the stack-single-resource-grants workaround.
- Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
- ---------
- Co-authored-by: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
- feat(mcp): serve public JWKS at /.well-known/jwks.json (ECO-94) (#25)
- * feat(mcp): serve public JWKS at /.well-known/jwks.json (ECO-94)
- Add a WithPublicJWKS metadata option that serves a JWKS document (e.g. from
WebIdentityCredential.PublicJWKS()) at /.well-known/jwks.json with CORS headers,
so an authorization server can fetch the resource's public keys to verify its
private_key_jwt client assertions. The route is only registered when the option
is set. Completes the oauth-metadata-endpoints item of ECO-94.
- Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
- * fix(mcp): advertise jwks_uri in protected-resource metadata
- When WithPublicJWKS is set, the protected-resource metadata now also advertises
the JWKS location via the RFC 9728 jwks_uri field (origin + /.well-known/jwks.json),
so the one option both serves and advertises the JWKS, matching how Python couples
them. Addresses the #25 review.
- Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
- ---------
- Co-authored-by: Claude Opus 4.8 (1M context) <noreply@anthropic.com>

## v0.11.0 (2026-06-30)


- feat(mcp)!: validate application credential construction and type EKS runtime errors (ECO-94) (#23)
- * feat(mcp)!: validate application credential construction and type EKS runtime errors (ECO-94)
- NewClientSecret and NewMultiZoneClientSecret now return an error and reject
an empty client_id, client_secret, an empty zone map, or a zone entry missing
its issuer or credentials. They surface ClientSecretConfigurationError instead
of building a credential that fails opaquely during token exchange.
- EKSWorkloadIdentityCredential.PrepareTokenExchangeRequest returns the new
EKSWorkloadIdentityRuntimeError when the token file cannot be read or is empty
at request time, distinct from the construction-time
EKSWorkloadIdentityConfigurationError (e.g. the file is rotated away after the
credential is built).
- BREAKING CHANGE: NewClientSecret and NewMultiZoneClientSecret now return
(*ClientSecretCredential, error). Callers must handle the returned error.
- WebIdentity construction tightening (client_id + token_endpoint requirement,
storage-dir default change, audience_config) is left to a follow-up.
- Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
- * fix(mcp): preserve the read cause in EKS workload-identity errors
- EKSWorkloadIdentityRuntimeError and EKSWorkloadIdentityConfigurationError now
carry an Err field and Unwrap(), storing the os.ReadFile cause instead of
formatting it away with %v. This restores errors.Is(err, os.ErrNotExist) and
errors.Is(err, os.ErrPermission) on a failed token read, which distinguishes a
missing/unmounted token path from a mounted-but-unreadable one. Matches the
Err/Unwrap() convention adopted in the oauth and a2a error types.
- Also document that NewClientSecret uses its inputs verbatim, and assert the
config-vs-runtime error split (and the unwrapped os.ErrNotExist) in the tests.
- Addresses the #23 review.
- Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
- ---------
- Co-authored-by: Claude Opus 4.8 (1M context) <noreply@anthropic.com>

## v0.10.1 (2026-06-30)


- fix: advertise path-inserted protected-resource metadata and default authorization_servers (ACC-591) (#21)
- * fix: advertise path-inserted protected-resource metadata and default authorization_servers
- RFC 9728 path insertion was not applied on the advertising side: the bearer
challenge and the Protected Resource Metadata both resolved the resource to the
bare origin. A server that binds its token audience to a sub-path endpoint
(e.g. https://host/mcp, the common case) therefore rejected every token, because
the client requested a token for resource=origin, which never matched.
- - middleware: protectedResourceMetadataURL appends the request path, so a resource
  at /mcp advertises .well-known/oauth-protected-resource/mcp.
- metadata: AuthMetadataHandler also serves the path-inserted PRM route and resolves
  `resource` to the origin plus the path after the well-known prefix.
- metadata: emit `authorization_servers: [issuer]` by default. It was omitted unless
  the request carried MCP-Protocol-Version: 2025-03-26, and then set to the origin
  instead of the issuer.
- Fixes ACC-591. Part of ECO-94 (oauth-metadata-endpoints).
- Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
- * fix: address review on path-inserted PRM
- - normalize a trailing slash on the resolved resource so the path-inserted form
  ".../oauth-protected-resource/" maps to the origin, matching an origin-bound
  audience exactly (parity with Python's _create_resource_url rstrip)
- register the path-inserted route as a subtree (".../oauth-protected-resource/")
  rather than a named-but-unused {resourcePath...} wildcard; the handler derives
  the resource from r.URL.Path for both routes
- add tests for the two newly-covered branches: authorization_servers omitted when
  no issuer is configured, the trailing-slash resource normalization, and the
  root-path bare challenge
- Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
- * fix(mcp): document that an issuer is effectively required for AuthMetadataHandler
- Without WithIssuer the protected-resource metadata advertises no
authorization_servers and the authorization-server proxy route is not
registered, so clients cannot discover the authorization server. Note this on
the handler. Addresses #21 review.
- Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
- ---------
- Co-authored-by: Claude Opus 4.8 (1M context) <noreply@anthropic.com>

## v0.10.0 (2026-06-30)


- feat(a2a): add agent-to-agent delegation client (ECO-95) (#24)
- * feat(a2a): add agent-to-agent delegation client (ECO-95)
- Adds the a2a package implementing Keycard's agent-to-agent delegation
contract: discover a target agent's card, exchange the inbound user token
for one scoped to the target (RFC 8693, authenticated with the calling
agent's own credential), and invoke the target's JSON-RPC endpoint with the
exchanged token. The user remains the subject at each hop; the authorization
server records the calling agent in the token's act chain. This mirrors the
Python (keycardai-a2a) and TypeScript (@keycardai/a2a) delegation surface.
- - ServiceDiscovery: agent-card discovery at /.well-known/agent-card.json
  with a TTL cache (default 15 minutes) and on-demand refresh; validates that
  the card carries a name.
- DelegationClient.Invoke: discover, exchange, invoke. Surfaces discovery,
  exchange (OAuth), and JSON-RPC invocation failures as distinct error types,
  and does not invoke the target when the exchange fails.
- Conformance tests for the spec's five Testing cases, a runnable example
  (examples/a2a), and a go test-verified godoc example.
- Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
- * fix(a2a): per-call invoke timeout, route discovery via the client, reject empty results
- Addresses the #24 review:
- WithInvokeTimeout bounds a whole Invoke (discovery, exchange, invocation) via the
  context, independent of any HTTP client timeout, so it still applies when a caller
  supplies an http.Client with no Timeout. Restores parity with the TS per-invoke timeout.
- A caller-supplied WithHTTPClient now also governs agent-card discovery unless an
  explicit ServiceDiscovery is provided.
- ServiceDiscovery deduplicates concurrent first-time lookups with singleflight, matching
  the oauth keyring.
- A JSON-RPC result carrying no message is now an InvocationError rather than a silent
  empty success.
- Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
- ---------
- Co-authored-by: Claude Opus 4.8 (1M context) <noreply@anthropic.com>

## v0.9.0 (2026-06-30)


- feat: oauth conformance polish - discovery/token-exchange/jwks/error-model (ECO-94) (#22)
- * feat: oauth conformance polish (discovery, token-exchange, jwks, error model)
- Aligns the oauth package with the spec divergence tables (ECO-94):
- - discovery: validate the response issuer matches the requested issuer
  (RFC 8414 section 3.3, trailing slash ignored) via a typed IssuerMismatchError,
  and preserve unknown fields on AuthorizationServerMetadata.Extra.
- token-exchange: add TokenResponse.IDToken; default token_type to "Bearer"
  (RFC 6750). Client-credentials and authorization-code inherit via the shared
  deserializeTokenResponse.
- jwks keyring: bound the key cache (WithMaxKeyCacheSize, default 256) with
  overflow eviction; return typed JWKSDiscoveryError / JWKSUriValidationError /
  JWKSFetchError / JWKSKeyNotFoundError instead of generic errors.
- error model: add the KeycardError marker interface (errors.As discrimination)
  and a single parseOAuthErrorResponse helper, replacing the RFC 6749 error
  parsing duplicated across token-exchange, client-credentials, authorization-code,
  and registration.
- Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
- * fix(oauth): preserve error cause in JWKS errors and trim issuer on both sides
- JWKSDiscoveryError and JWKSFetchError now carry the underlying cause via an
Err field and Unwrap(), instead of formatting it away with %v. This restores
errors.Is (e.g. context.DeadlineExceeded on a JWKS fetch timeout) and
errors.As to a nested *IssuerMismatchError through the keyring to discovery
path, matching the typed-error model the rest of this PR builds.
- Also trim the trailing slash on both sides of the discovery issuer comparison
so it no longer depends on the top-of-function normalization, and add a
reflection test guarding knownASMetadataFields against drift from the struct's
json tags.
- Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
- * refactor(oauth): align jwt.go struct tags via gofmt
- Pre-existing gofmt drift in JWTClaims struct-tag alignment, cleaned up so the
oauth package is gofmt-clean.
- Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
- ---------
- Co-authored-by: Claude Opus 4.8 (1M context) <noreply@anthropic.com>

## v0.8.0 (2026-06-29)


- feat!: add multi-zone support to the auth provider (ECO-93) (#17)
- * feat!: add multi-zone support to the auth provider
- Implements the multi-zone-support spec: one AuthProvider instance can
serve many Keycard zones, routing each request by the token's issuer.
- - NewMultiZoneClientSecret(map[issuer]ClientAuth): a self-describing,
  zone-keyed credential. ApplicationCredential.Auth now takes the zone
  issuer and resolves per-zone credentials (assertion-based credentials
  ignore it; an unknown zone returns nil, fail-closed).
- AuthProvider detects multi-zone from the credential and keeps a
  per-zone TokenExchangeClient, so discovery/client caches are
  zone-scoped. Grant routes the exchange to AuthInfo.Issuer;
  ExchangeTokensForZone selects a zone explicitly. An unresolved or
  unconfigured zone fails closed with a global AccessContext error.
- Inbound: AuthInfo gains Issuer (the verified iss);
  NewMultiZoneTokenVerifier trusts several zones and resolves each
  token's key from its own zone's JWKS (the Phase 1 multi-issuer
  verifier already isolates keys per issuer).
- Zone resolution is the verified token's iss; the spec calls the
resolution layer an intended per-framework idiom, so a pluggable
request-based resolver can be added later if a customer needs one.
- Tests cover the spec's six unit cases: per-zone credential resolution,
issuer-routed exchange, no cross-zone leakage, fail-closed on
unresolved/unknown zones, and an end-to-end Grant routed by the token
issuer.
- BREAKING CHANGE: ApplicationCredential.Auth() becomes
Auth(issuer string). Custom credential implementations must update the
method signature.
- Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
- * refactor: address multi-zone review on the auth provider
- - Collapse the separate `zones` set and `clients` cache into one zone-keyed
  map: a key's presence marks a configured zone, its value is the lazily
  created client (nil until first use).
- Fix clientForZone returning the nil placeholder on first use (it now treats
  present-but-nil as "create"), the bug surfaced by the combined map.
- resolveZone takes the mutex for its membership read, since clients is now
  mutated under the lock by clientForZone.
- Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
- * refactor: do not mint a client for an unconfigured zone
- clientForZone created a token-exchange client even when the zone was absent from
the map (not configured). It now returns nil for an unknown zone and only builds
a client for a configured one (present, created lazily on first use). The exchange
flow already resolves the zone first; it now also fails closed if the client is nil.
- Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
- ---------
- Co-authored-by: Claude Opus 4.8 (1M context) <noreply@anthropic.com>

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
