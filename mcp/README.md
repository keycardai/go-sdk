# `mcp` — MCP OAuth integration

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
transport even though the bearer token is perfectly valid — a failure easily
misread as a Keycard auth problem. The distinguishing signal is the status and
the challenge: header validation returns 400 with a JSON-RPC error naming the
missing header and no `WWW-Authenticate`, whereas Keycard auth failures return
401 or 403 with a `WWW-Authenticate` challenge.
