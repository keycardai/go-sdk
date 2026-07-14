// Package oauth provides pure OAuth 2.0 primitives for the Keycard SDK.
//
// This package has no MCP dependency and can be used standalone. It provides:
//
//   - JWT signing and verification ([JWTSigner], [JWTVerifier])
//   - JWKS key discovery with two-level caching ([JWKSOAuthKeyring])
//   - RFC 8693 token exchange ([TokenExchangeClient])
//   - OAuth authorization server metadata discovery ([FetchAuthorizationServerMetadata])
//   - Application credentials ([ClientSecretCredential], [WebIdentityCredential],
//     [WorkloadIdentityCredential] with pluggable [IdentityTokenSource] implementations)
//   - Custom error types for OAuth error handling
package oauth
