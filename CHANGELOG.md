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
