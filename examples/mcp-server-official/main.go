// Package main demonstrates serving MCP with the official
// modelcontextprotocol/go-sdk, using Keycard to verify bearer tokens.
//
// The Keycard verifier plugs into the official SDK's own auth.TokenVerifier
// seam (see KeycardTokenVerifier). Verification runs on every HTTP request, so
// tool handlers always see the auth for the call in flight via
// req.Extra.TokenInfo. Do not read auth from the handler's context here: for
// stateful sessions the official SDK hands tool handlers the context the
// session was created with, so anything stored on the initialize request's
// context goes stale as the client rotates tokens.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	keycard "github.com/keycardai/go-sdk/mcp"
)

// keycardExtraKey is the TokenInfo.Extra key under which KeycardTokenVerifier
// stores the verified Keycard AuthInfo.
const keycardExtraKey = "keycard"

// KeycardTokenVerifier adapts a Keycard TokenVerifier to the official go-sdk's
// auth.TokenVerifier seam. The full Keycard AuthInfo rides in TokenInfo.Extra
// (read it back with KeycardAuthInfo), and setting UserID activates the
// transport's session-hijack binding: every request on a session must present
// a token for the same user.
func KeycardTokenVerifier(v keycard.TokenVerifier) auth.TokenVerifier {
	return func(ctx context.Context, token string, _ *http.Request) (*auth.TokenInfo, error) {
		info, err := v.VerifyAccessToken(ctx, token)
		if err != nil {
			// auth.RequireBearerToken maps errors that unwrap to auth.ErrInvalidToken
			// to a 401. Wrap with %w on both sides so the Keycard cause stays
			// inspectable through errors.Is / errors.As.
			return nil, fmt.Errorf("%w: %w", auth.ErrInvalidToken, err)
		}
		return &auth.TokenInfo{
			Scopes: info.Scopes,
			// auth.RequireBearerToken rejects a zero Expiration, so tokens must
			// carry exp (Keycard access tokens always do).
			Expiration: time.Unix(info.ExpiresAt, 0),
			UserID:     info.Subject,
			Extra:      map[string]any{keycardExtraKey: info},
		}, nil
	}
}

// KeycardAuthInfo extracts the Keycard AuthInfo that KeycardTokenVerifier
// stored for the call in flight. Returns nil if the request did not pass
// through auth.RequireBearerToken with a Keycard verifier.
func KeycardAuthInfo(extra *mcp.RequestExtra) *keycard.AuthInfo {
	if extra == nil || extra.TokenInfo == nil {
		return nil
	}
	info, _ := extra.TokenInfo.Extra[keycardExtraKey].(*keycard.AuthInfo)
	return info
}

type whoamiOutput struct {
	Subject  string   `json:"subject" jsonschema:"the authenticated user (the token's sub claim)"`
	ClientID string   `json:"client_id" jsonschema:"the OAuth client the token was issued to"`
	Scopes   []string `json:"scopes,omitempty" jsonschema:"the scopes granted to the token"`
}

// whoami reports the caller's identity as seen on this call. It reads auth
// from req.Extra.TokenInfo, which the transport populates per HTTP request.
func whoami(_ context.Context, req *mcp.CallToolRequest, _ any) (*mcp.CallToolResult, whoamiOutput, error) {
	info := KeycardAuthInfo(req.Extra)
	if info == nil {
		return nil, whoamiOutput{}, fmt.Errorf("no Keycard auth info on request")
	}
	return nil, whoamiOutput{
		Subject:  info.Subject,
		ClientID: info.ClientID,
		Scopes:   info.Scopes,
	}, nil
}

// newHandler assembles the MCP server and wraps its streamable transport with
// the official SDK's bearer middleware, backed by the Keycard verifier.
func newHandler(verifier keycard.TokenVerifier, requiredScopes ...string) http.Handler {
	server := mcp.NewServer(&mcp.Implementation{Name: "keycard-official-example", Version: "0.1.0"}, nil)
	mcp.AddTool(server, &mcp.Tool{
		Name:        "whoami",
		Description: "Report the authenticated caller for this call",
	}, whoami)

	streamable := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, nil)

	return auth.RequireBearerToken(KeycardTokenVerifier(verifier), &auth.RequireBearerTokenOptions{
		Scopes: requiredScopes,
	})(streamable)
}

func main() {
	zoneURL := os.Getenv("KEYCARD_ZONE_URL")
	if zoneURL == "" {
		log.Fatal("KEYCARD_ZONE_URL environment variable is required")
	}

	// The verifier trusts only tokens issued by this zone and resolves keys
	// from its JWKS.
	verifier, err := keycard.NewZoneTokenVerifier(zoneURL)
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()

	// Serve OAuth metadata endpoints.
	mux.Handle("/.well-known/", keycard.AuthMetadataHandler(
		keycard.WithIssuer(zoneURL),
		keycard.WithScopesSupported([]string{"mcp:tools"}),
		keycard.WithResourceName("Official go-sdk MCP Server"),
	))

	mux.Handle("/mcp", newHandler(verifier, "mcp:tools"))

	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})

	addr := ":8080"
	if port := os.Getenv("PORT"); port != "" {
		addr = ":" + port
	}
	log.Printf("Listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}
