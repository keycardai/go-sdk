// Package main demonstrates serving MCP with mark3labs/mcp-go, using
// Keycard's RequireBearerAuth as the HTTP auth layer.
//
// mark3labs derives each tool handler's context from the inbound HTTP request
// on every call, so wrapping the streamable server with the Keycard middleware
// is enough: handlers read the caller's auth with keycard.AuthInfoFromContext
// and it is always the auth for the call in flight.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	keycard "github.com/keycardai/go-sdk/mcp"
	"github.com/keycardai/go-sdk/oauth"
)

// whoami reports the caller's identity as seen on this call. The AuthInfo
// comes from the handler's context, which mark3labs derives from the HTTP
// request that carried this call.
func whoami(ctx context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	info := keycard.AuthInfoFromContext(ctx)
	if info == nil {
		return mcp.NewToolResultError("no Keycard auth info in context"), nil
	}
	return mcp.NewToolResultText(fmt.Sprintf(
		"subject=%s client_id=%s scopes=%s",
		info.Subject, info.ClientID, strings.Join(info.Scopes, " "),
	)), nil
}

// newHandler assembles the MCP server and wraps its streamable transport with
// Keycard's bearer middleware.
func newHandler(verifier keycard.TokenVerifier, requiredScopes ...string) http.Handler {
	s := server.NewMCPServer("keycard-mark3labs-example", "0.1.0")
	s.AddTool(mcp.NewTool("whoami",
		mcp.WithDescription("Report the authenticated caller for this call"),
	), whoami)

	streamable := server.NewStreamableHTTPServer(s)

	return keycard.RequireBearerAuth(
		verifier,
		keycard.WithRequiredScopes(requiredScopes...),
	)(streamable)
}

func main() {
	zoneURL := os.Getenv("KEYCARD_ZONE_URL")
	if zoneURL == "" {
		log.Fatal("KEYCARD_ZONE_URL environment variable is required")
	}

	serverURL := os.Getenv("MCP_SERVER_URL")
	if serverURL == "" {
		serverURL = "http://localhost:8080"
	}

	// The verifier trusts only tokens issued by this zone and resolves keys
	// from its JWKS. WithAudiences binds accepted tokens to this resource
	// server (the /mcp resource the metadata handler advertises); without it,
	// a token the zone minted for any other resource server would also pass
	// the scope and expiry checks here.
	verifier, err := keycard.NewZoneTokenVerifier(zoneURL, oauth.WithAudiences(serverURL+"/mcp"))
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()

	// Serve OAuth metadata endpoints.
	mux.Handle("/.well-known/", keycard.AuthMetadataHandler(
		keycard.WithIssuer(zoneURL),
		keycard.WithScopesSupported([]string{"mcp:tools"}),
		keycard.WithResourceName("mark3labs MCP Server"),
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
