# `mcp`: MCP OAuth integration

Server-side and client-side MCP authentication for Keycard: `RequireBearerAuth`
(bearer auth middleware), `AuthMetadataHandler` (`.well-known` endpoints),
`AuthProvider` / `AccessContext` (token exchange), and the `Grant` decorator.
See the [root README](../README.md) for wiring examples with the official
`modelcontextprotocol/go-sdk` and with `mark3labs/mcp-go`.

## Preserve MCP request headers at proxies and WAFs

From protocol version `2026-07-28` (SEP-2243) an MCP client sends `Mcp-Method`
and `Mcp-Name` alongside every `tools/call`, `prompts/get`, and
`resources/read`, and `MCP-Protocol-Version` on every request; the server
rejects a request whose headers are missing or disagree with the JSON-RPC body.
`RequireBearerAuth` forwards those headers untouched, but a proxy, load
balancer, API gateway, or WAF in front of the server may not: allowlist
`Mcp-Method`, `Mcp-Name`, and `MCP-Protocol-Version` (plus any `Mcp-Param-*`
headers your tools declare) so they arrive verbatim. When they are stripped,
every tool call on a `2026-07-28` session fails with an HTTP 400 from the MCP
transport even though the bearer token is perfectly valid, a failure easily
misread as a Keycard auth problem. The distinguishing signal is the status and
the challenge: header validation returns 400 with a JSON-RPC error naming the
missing header and no `WWW-Authenticate`, whereas Keycard auth failures return
401 or 403 with a `WWW-Authenticate` challenge.

## Route-level and per-tool scopes

`RequireBearerAuth` takes `WithRequiredScopes(...)` for scopes every request on
the route must carry; a token missing one is rejected with a 403 and an
`insufficient_scope` challenge before any handler runs. All MCP tools share one
HTTP route, so that option can only express scopes common to every tool.
Per-tool requirements are checked inside the tool handler with two helpers that
read the identity the middleware stored on the request context:

```go
// Just the gap: the required scopes the token does not grant, in order.
missing := keycard.MissingToolScopes(ctx, "files:read", "files:write")

// Assert and get the identity back in one call.
info, err := keycard.RequireToolScopes(ctx, "files:read", "files:write")
if err != nil {
    // err is an *oauth.InsufficientScopeError naming the missing scopes, or saying
    // the call is unauthenticated when the context carries no AuthInfo.
}
```

Both helpers treat a context without `AuthInfo` as granting nothing.
`RequireToolScopes` returns the same `*AuthInfo` the context holds, so the
handler needs no second `AuthInfoFromContext` call. No new error type is
involved: the middleware already type-switches on `oauth.InsufficientScopeError`
for verifier failures, and `errors.As` resolves it here too.

What the client sees is not the 403 with a `WWW-Authenticate` challenge the
middleware sends for route-level scopes: by the time a tool handler runs, the
MCP transport has accepted the HTTP request and is writing a JSON-RPC response.
Verified against `modelcontextprotocol/go-sdk` v1.7.0 and `mark3labs/mcp-go`
v1.0.0:

| Library | Handler returns `err` | Handler context carries the call's auth? |
| --- | --- | --- |
| `modelcontextprotocol/go-sdk`, generic `AddTool` | `CallToolResult` with `IsError: true` and `err.Error()` as text content (any error other than a `*jsonrpc.Error`) | Stateful mode: no, the context descends from the request that opened the session. Read `req.Extra.TokenInfo` and wrap it with `ContextWithAuthInfo`. `Stateless: true`: yes |
| `modelcontextprotocol/go-sdk`, low-level `ToolHandler` | JSON-RPC error response with `err.Error()` as the message | Same as above |
| `mark3labs/mcp-go` | JSON-RPC error response, code `-32603`, `err.Error()` as the message; return `mcp.NewToolResultError(err.Error())` for a tool error result instead | Yes, each handler context derives from the inbound HTTP request |

With `mark3labs/mcp-go`:

```go
func deleteFile(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
    info, err := keycard.RequireToolScopes(ctx, "files:write")
    if err != nil {
        return mcp.NewToolResultError(err.Error()), nil
    }
    // info is the caller; proceed
}
```

With the official SDK in stateful mode, wired through its `auth.RequireBearerToken`
as the root README shows:

```go
func deleteFile(ctx context.Context, req *mcpsdk.CallToolRequest, in deleteInput) (*mcpsdk.CallToolResult, any, error) {
    caller, _ := req.Extra.TokenInfo.Extra["keycard"].(*keycard.AuthInfo)
    info, err := keycard.RequireToolScopes(keycard.ContextWithAuthInfo(ctx, caller), "files:write")
    if err != nil {
        return nil, nil, err // flattened into a tool error result by the SDK
    }
    // ...
}
```
