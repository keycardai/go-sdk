# Keycard Go SDK

> **Preview.** This SDK has not reached parity with the Keycard Python
> SDK. APIs may change between minor versions. The preview label will
> be removed once feature parity is reached.

Go SDK for [Keycard](https://keycard.cloud) — OAuth 2.0 and MCP authentication.

## Installation

```bash
go get github.com/keycardai/credentials-go
```

Import the sub-package you need:

```go
import "github.com/keycardai/credentials-go/oauth"  // Pure OAuth 2.0 primitives
import "github.com/keycardai/credentials-go/mcp"    // MCP-specific OAuth integration
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

- **Bearer auth middleware** — `RequireBearerAuth` (standard `net/http` middleware)
- **Token exchange orchestration** — `AuthProvider`, `AccessContext`
- **Application credentials** — `ClientSecret`, `WebIdentity` (RFC 7523), `EKSWorkloadIdentity`
- **Metadata endpoints** — `AuthMetadataHandler` (`.well-known` endpoints)

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
authProvider, _ := mcp.NewAuthProvider(
    mcp.WithZoneURL("https://your-zone.keycard.cloud"),
    mcp.WithApplicationCredential(mcp.NewClientSecret(clientID, clientSecret)),
)

verifier, _ := mcp.NewZoneTokenVerifier("https://your-zone.keycard.cloud")

handler := mcp.RequireBearerAuth(
    verifier,
    mcp.WithRequiredScopes("mcp:tools"),
)(authProvider.Grant("https://api.github.com")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
authProvider, _ := mcp.NewAuthProvider(
    mcp.WithZoneURL("https://your-zone.keycard.cloud"),
    mcp.WithApplicationCredential(mcp.NewClientSecret(clientID, clientSecret)),
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
    mcp.WithServerName("my-mcp-server"),
    mcp.WithStorageDir("./keys"),
)

authProvider, _ := mcp.NewAuthProvider(
    mcp.WithZoneURL("https://your-zone.keycard.cloud"),
    mcp.WithApplicationCredential(webIdentity),
)
```

## Credential Types

| Type | Auth Method | Use Case |
|------|-------------|----------|
| `ClientSecret` | HTTP Basic Auth | Simple deployments with client_id/secret |
| `WebIdentity` | `private_key_jwt` (RFC 7523) | Zero-secret deployments, auto-generates RSA keys |
| `EKSWorkloadIdentity` | Pod identity token | AWS EKS workloads |

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
GOPROXY=proxy.golang.org go list -m github.com/keycardai/credentials-go@v0.1.0
```
