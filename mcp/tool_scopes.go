package mcp

import (
	"context"
	"strings"

	"github.com/keycardai/go-sdk/oauth"
)

// ContextWithAuthInfo returns a copy of ctx carrying info, so that
// AuthInfoFromContext, MissingToolScopes, and RequireToolScopes can read it.
// RequireBearerAuth does this for every request it admits; call it yourself only
// where the handler context does not descend from that request, such as a tool
// handler in the official modelcontextprotocol/go-sdk in stateful mode, whose
// per-call identity arrives in req.Extra.TokenInfo rather than in ctx.
func ContextWithAuthInfo(ctx context.Context, info *AuthInfo) context.Context {
	return context.WithValue(ctx, authInfoKey, info)
}

// MissingToolScopes returns the entries of required that the token stored in ctx
// by RequireBearerAuth does not grant, in the order given. An unauthenticated
// context (no AuthInfo) grants nothing, so every required scope is reported.
//
// All MCP tools share one HTTP route, so route-level WithRequiredScopes can only
// express scopes every tool needs. Per-tool requirements are checked inside the
// tool handler with this helper or with RequireToolScopes.
func MissingToolScopes(ctx context.Context, required ...string) []string {
	granted := map[string]struct{}{}
	if info := AuthInfoFromContext(ctx); info != nil {
		for _, scope := range info.Scopes {
			granted[scope] = struct{}{}
		}
	}
	missing := make([]string, 0, len(required))
	for _, scope := range required {
		if _, ok := granted[scope]; !ok {
			missing = append(missing, scope)
		}
	}
	return missing
}

// RequireToolScopes asserts that the token stored in ctx by RequireBearerAuth grants
// every scope in required and returns that same *AuthInfo. It returns an
// *oauth.InsufficientScopeError when ctx carries no AuthInfo (the message says the
// call is unauthenticated) or when scopes are missing (the message names them).
//
// The error does not become an HTTP 403 with a WWW-Authenticate challenge: by the
// time a tool handler runs, the MCP transport has accepted the request and is
// writing a JSON-RPC response. What the client sees depends on the library:
//
//   - modelcontextprotocol/go-sdk: a handler registered with the generic AddTool
//     returning any error other than a *jsonrpc.Error gets a CallToolResult with
//     IsError true and the error text as content. A low-level ToolHandler returning
//     the error produces a JSON-RPC error response instead.
//   - mark3labs/mcp-go: a handler returning an error produces a JSON-RPC error
//     response with code -32603 and the error text as the message. Return
//     mcp.NewToolResultError(err.Error()) to send a tool error result instead.
//
// Whether ctx carries the auth for the call in flight also depends on the library.
// mark3labs/mcp-go derives each handler's context from the inbound HTTP request, so
// RequireBearerAuth's context is the one the handler sees. The official SDK derives
// the handler context from the request that opened the session, so in stateful mode
// it carries the session-opening identity, not the current call's; read the call's
// identity from req.Extra.TokenInfo and wrap it with ContextWithAuthInfo before
// calling this helper. Its Stateless mode opens a session per request, so the
// request context reaches the handler directly.
func RequireToolScopes(ctx context.Context, required ...string) (*AuthInfo, error) {
	info := AuthInfoFromContext(ctx)
	if info == nil {
		return nil, &oauth.InsufficientScopeError{
			Message: "tool call is unauthenticated: no access token information is available on the request context",
		}
	}
	if missing := MissingToolScopes(ctx, required...); len(missing) > 0 {
		return nil, &oauth.InsufficientScopeError{
			Message: "tool call requires additional scopes: " + strings.Join(missing, " "),
		}
	}
	return info, nil
}
