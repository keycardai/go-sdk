# MCP server with `mark3labs/mcp-go`

Serves MCP over streamable HTTP with Keycard's `RequireBearerAuth` as the HTTP
auth layer; handlers read the caller's auth with `keycard.AuthInfoFromContext`
(see the package comment in `main.go`).

This example is its own Go module, with a `replace` directive pointing at the
repository root.

```bash
export KEYCARD_ZONE_URL=https://your-zone.keycard.cloud
export MCP_SERVER_URL=http://localhost:8080   # the public URL clients reach
go run .
```

## Preserve MCP request headers at proxies and WAFs

If you front this server with a proxy, load balancer, API gateway, or WAF,
allowlist the `Mcp-Method`, `Mcp-Name`, and `MCP-Protocol-Version` request
headers so they reach the server verbatim. On MCP protocol version
`2026-07-28` (SEP-2243) the server rejects a `tools/call` whose `Mcp-Method` or
`Mcp-Name` is missing or disagrees with the JSON-RPC body, so a stripping
intermediary turns valid calls into HTTP 400s while the bearer token is
perfectly valid — easily misread as a Keycard auth failure. The tell is that
header validation returns 400 with no `WWW-Authenticate`, whereas Keycard auth
failures return 401 or 403 with a challenge.

`mark3labs/mcp-go` v0.58.0, the version pinned here, caps at protocol version
`2025-11-25` (`mcp.LATEST_PROTOCOL_VERSION`), so SEP-2243 header validation
does not apply to this example today; the v1.0.0 beta line (`v1.0.0-beta.1`)
sets `LATEST_PROTOCOL_VERSION` to `2026-07-28` and validates these headers, so
the guidance above becomes load-bearing once this example moves to it.
