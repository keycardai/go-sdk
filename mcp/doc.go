// Package mcp provides MCP-specific OAuth integration for the Keycard SDK.
//
// This package builds on [github.com/keycardai/go-sdk/oauth] to provide:
//
//   - Bearer auth middleware for protecting HTTP endpoints ([RequireBearerAuth])
//   - Token exchange orchestration for delegated access ([AuthProvider], [AccessContext])
//   - Application credential implementations ([ClientSecret], [WebIdentity], [EKSWorkloadIdentity])
//   - Well-known metadata endpoint handlers ([AuthMetadataHandler])
//   - JWT token verification ([JWTOAuthTokenVerifier])
//   - Private key management for client assertions ([PrivateKeyManager])
package mcp
