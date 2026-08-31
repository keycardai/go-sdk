# MCP server with the official `modelcontextprotocol/go-sdk`

Serves MCP over streamable HTTP with Keycard verifying bearer tokens through the
official SDK's `auth.TokenVerifier` seam, so tool handlers always see the auth
for the call in flight (see the package comment in `main.go`).

This example is its own Go module, with a `replace` directive pointing at the
repository root.

```bash
export KEYCARD_ZONE_URL=https://your-zone.keycard.cloud
export MCP_SERVER_URL=http://localhost:8080   # the public URL clients reach
go run .
```

## Preserve MCP request headers at proxies and WAFs

The SDK client sends `Mcp-Method` and `Mcp-Name` with every `tools/call` and
`MCP-Protocol-Version` on every request once the session negotiates
`2026-07-28` (SEP-2243), and the server rejects any request whose headers are
missing or disagree with the JSON-RPC body. If you front this server with a
proxy, load balancer, API gateway, or WAF, allowlist those headers so they
arrive verbatim. Stripping them makes every tool call fail with an HTTP 400
from the MCP transport while the bearer token is perfectly valid; the 400 with
a JSON-RPC error naming the missing header and no `WWW-Authenticate` is what
distinguishes it from a Keycard auth failure (401/403 with a challenge).
`headers_test.go` pins both the success and the stripped-header rejection.

Which sessions are affected depends on the transport configuration: with the
default stateful handler used in `main.go` the official SDK's streamable
transport does not serve `2026-07-28`, so sessions fall back to `2025-11-25`
and the headers are advisory. With `StreamableHTTPOptions{Stateless: true}` the
SEP-2575 `server/discover` handshake negotiates `2026-07-28` and the headers
become mandatory.
