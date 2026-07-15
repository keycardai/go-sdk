# Keycard Go SDK

> **Preview.** APIs may change between minor versions while this SDK is in
> preview.

Go SDK for [Keycard](https://keycard.cloud) — OAuth 2.0 and MCP authentication.

## Installation

```bash
go get github.com/keycardai/go-sdk
```

Import the sub-package you need:

```go
import "github.com/keycardai/go-sdk/oauth"  // Pure OAuth 2.0 primitives
import "github.com/keycardai/go-sdk/mcp"    // MCP-specific OAuth integration
import "github.com/keycardai/go-sdk/a2a"    // Agent-to-agent delegation
```

## Packages

### `oauth` — Pure OAuth 2.0 Primitives

No MCP dependency. Use standalone for JWT operations, JWKS key discovery, token exchange, and OAuth metadata discovery.

- **JWT signing/verification** — `JWTSigner`, `JWTVerifier`
- **JWKS keyring** — `JWKSOAuthKeyring` with two-level caching and request deduplication
- **Token exchange** — `TokenExchangeClient` (RFC 8693)
- **Discovery** — `FetchAuthorizationServerMetadata` (RFC 8414)

### `mcp` — MCP OAuth Integration

Builds on `oauth` to provide server-side and client-side MCP authentication.

- **Bearer auth middleware** — `RequireBearerAuth` (standard `net/http` middleware), audience-bound via `oauth.WithAudiences`
- **Token exchange orchestration** — `AuthProvider`, `AccessContext`; the `Grant` decorator with `WithUserIdentifier` (impersonation) and `WithRequestScopes`
- **Application credentials** — `ClientSecret`, `WebIdentity` (RFC 7523), `WorkloadIdentity` (platform OIDC tokens via pluggable sources); multi-zone via `NewMultiZoneClientSecret`
- **Metadata endpoints** — `AuthMetadataHandler` (`.well-known` endpoints, including `WithPublicJWKS`)

### `a2a` — Agent-to-Agent Delegation

One agent calling another on the user's behalf: discover the target agent's card, exchange the user's token for one scoped to the target (RFC 8693), and invoke its JSON-RPC endpoint.

- **Delegation** — `DelegationClient`, `ServiceDiscovery`

## Quick Start

### Protect an endpoint with bearer auth

```go
mux := http.NewServeMux()

mux.Handle("/.well-known/", mcp.AuthMetadataHandler(
    mcp.WithIssuer("https://your-zone.keycard.cloud"),
    mcp.WithScopesSupported([]string{"mcp:tools"}),
))

// The verifier trusts only tokens issued by this zone.
verifier, _ := mcp.NewZoneTokenVerifier("https://your-zone.keycard.cloud")

protected := mcp.RequireBearerAuth(
    verifier,
    mcp.WithRequiredScopes("mcp:tools"),
)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    info := mcp.AuthInfoFromRequest(r)
    fmt.Fprintf(w, "Hello, %s!", info.ClientID)
}))

mux.Handle("GET /api/hello", protected)
```

### Delegated access via token exchange

```go
cred, _ := mcp.NewClientSecret(clientID, clientSecret)
authProvider, _ := mcp.NewAuthProvider(
    mcp.WithZoneURL("https://your-zone.keycard.cloud"),
    mcp.WithApplicationCredential(cred),
)

verifier, _ := mcp.NewZoneTokenVerifier("https://your-zone.keycard.cloud")

handler := mcp.RequireBearerAuth(
    verifier,
    mcp.WithRequiredScopes("mcp:tools"),
)(authProvider.Grant([]string{"https://api.github.com"})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    ac := mcp.AccessContextFromRequest(r)

    token, err := ac.Access("https://api.github.com")
    if err != nil {
        http.Error(w, err.Error(), http.StatusBadGateway)
        return
    }

    // Use token.AccessToken to call the GitHub API
    fmt.Fprintf(w, "GitHub token: %s", token.AccessToken)
})))
```

### Standalone token exchange (without middleware)

```go
cred, _ := mcp.NewClientSecret(clientID, clientSecret)
authProvider, _ := mcp.NewAuthProvider(
    mcp.WithZoneURL("https://your-zone.keycard.cloud"),
    mcp.WithApplicationCredential(cred),
)

ac := authProvider.ExchangeTokens(ctx, userBearerToken, "https://api.github.com")
if ac.HasErrors() {
    log.Printf("Exchange failed: %v", ac.GetError())
}

token, _ := ac.Access("https://api.github.com")
// Use token.AccessToken
```

### Using WebIdentity (private_key_jwt)

```go
webIdentity := mcp.NewWebIdentity(
    mcp.WithClientID("your-client-id"), // required: the assertion's iss/sub
    mcp.WithServerName("my-mcp-server"),
    mcp.WithStorageDir("./server_keys"),
)

authProvider, _ := mcp.NewAuthProvider(
    mcp.WithZoneURL("https://your-zone.keycard.cloud"),
    mcp.WithApplicationCredential(webIdentity),
)
```

## Credential Types

| Type               | Auth Method                      | Use Case                                                 |
| ------------------ | -------------------------------- | -------------------------------------------------------- |
| `ClientSecret`     | HTTP Basic Auth                  | Simple deployments with client_id/secret                 |
| `WebIdentity`      | `private_key_jwt` (RFC 7523)     | Zero-secret deployments, auto-generates RSA keys         |
| `WorkloadIdentity` | Platform OIDC token (jwt-bearer) | EKS, AKS, GKE, Cloud Run, Fly Machines, custom sources   |

`WorkloadIdentity` takes a pluggable token source: `FileTokenSource` (projected token files: EKS, AKS, any Kubernetes projected service-account token), `GCPMetadataTokenSource` (GKE, GCE, Cloud Run), `FlyTokenSource` (Fly Machines), or any `IdentityTokenFunc`:

When the zone-side application credential is resolved by ID (a token-federation credential), pass that ID with `WithWorkloadClientID`; it is sent as the `client_id` form parameter alongside the assertion.

```go
source, _ := mcp.NewFileTokenSource() // discovers the projected token file from env
credential, _ := mcp.NewWorkloadIdentity(source)
```

`EKSWorkloadIdentity` is deprecated: it is an alias for `WorkloadIdentity` with a `FileTokenSource` limited to EKS env-var discovery. Existing code keeps working; new code should use `NewWorkloadIdentity`.

## Error Handling

The SDK uses Go-idiomatic error types. Use `errors.As` to check specific error types:

```go
token, err := ac.Access("https://api.github.com")
if err != nil {
    var rae *mcp.ResourceAccessError
    if errors.As(err, &rae) {
        // Resource token unavailable
    }
}
```

The `AccessContext` is a non-throwing result container — it never panics. Check status before accessing tokens:

```go
ac := authProvider.ExchangeTokens(ctx, userToken, "res1", "res2")

switch ac.Status() {
case mcp.StatusSuccess:
    // All resources exchanged successfully
case mcp.StatusPartialError:
    // Some resources failed — check individually
case mcp.StatusError:
    // Global error — no resources available
}
```

## Publishing

Go modules are published by pushing git tags:

```bash
git tag v0.1.0
git push origin v0.1.0
```

[pkg.go.dev](https://pkg.go.dev) indexes automatically. To trigger manually:

```bash
GOPROXY=proxy.golang.org go list -m github.com/keycardai/go-sdk@v0.1.0
```
