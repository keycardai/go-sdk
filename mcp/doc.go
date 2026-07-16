// Package mcp provides MCP-specific OAuth integration for the Keycard SDK.
//
// This package builds on [github.com/keycardai/go-sdk/oauth] to provide:
//
//   - Bearer auth middleware for protecting HTTP endpoints ([RequireBearerAuth])
//   - Token exchange orchestration for delegated access ([AuthProvider], [AccessContext])
//   - Well-known metadata endpoint handlers ([AuthMetadataHandler])
//   - JWT token verification ([JWTOAuthTokenVerifier])
//
// Application credentials (ClientSecret, WebIdentity, WorkloadIdentity and its
// token sources) live in [github.com/keycardai/go-sdk/oauth]; this package
// re-exports them as deprecated aliases for backward compatibility.
package mcp
