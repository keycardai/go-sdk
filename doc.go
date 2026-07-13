// Package keycardai provides the Keycard Go SDK for OAuth 2.0 and MCP authentication.
//
// Preview: this SDK has not reached parity with the Keycard Python SDK.
// APIs may change between minor versions until 1.0.
//
// The SDK is organized into sub-packages:
//
//   - [github.com/keycardai/go-sdk/oauth] — Pure OAuth 2.0 primitives: JWT signing/verification,
//     JWKS key discovery with caching, RFC 8693 token exchange, and OAuth server metadata discovery.
//
//   - [github.com/keycardai/go-sdk/mcp] — MCP-specific OAuth integration: bearer auth middleware,
//     token exchange orchestration (AuthProvider), application credentials, and well-known metadata endpoints.
//
//   - [github.com/keycardai/go-sdk/policy] — Keycard policy bundle format: content-addressed Cedar
//     schema + policy set serialization with tar+gzip codec and JCS-canonical manifest digest.
//
// Import the sub-package you need:
//
//	import "github.com/keycardai/go-sdk/oauth"   // OAuth primitives only
//	import "github.com/keycardai/go-sdk/mcp"     // MCP integration (includes oauth)
//	import "github.com/keycardai/go-sdk/policy"  // Policy bundle codec
package keycardai
