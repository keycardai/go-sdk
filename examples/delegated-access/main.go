// Package main demonstrates delegated access via token exchange with Keycard.
//
// This example shows how to use AuthProvider to exchange user tokens for
// third-party API tokens (e.g., GitHub), enabling your MCP server to
// access external APIs on behalf of the user.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/keycardai/credentials-go/mcp"
)

func main() {
	zoneURL := os.Getenv("KEYCARD_ZONE_URL")
	clientID := os.Getenv("KEYCARD_CLIENT_ID")
	clientSecret := os.Getenv("KEYCARD_CLIENT_SECRET")

	if zoneURL == "" || clientID == "" || clientSecret == "" {
		log.Fatal("KEYCARD_ZONE_URL, KEYCARD_CLIENT_ID, and KEYCARD_CLIENT_SECRET are required")
	}

	credential, err := mcp.NewClientSecret(clientID, clientSecret)
	if err != nil {
		log.Fatal(err)
	}

	authProvider, err := mcp.NewAuthProvider(
		mcp.WithZoneURL(zoneURL),
		mcp.WithApplicationCredential(credential),
	)
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()

	// Serve OAuth metadata endpoints
	mux.Handle("/.well-known/", mcp.AuthMetadataHandler(
		mcp.WithIssuer(zoneURL),
		mcp.WithScopesSupported([]string{"mcp:tools"}),
		mcp.WithResourceName("Delegated Access Example"),
	))

	verifier, err := mcp.NewZoneTokenVerifier(zoneURL)
	if err != nil {
		log.Fatal(err)
	}

	// Chain: bearer auth -> grant -> handler
	apiHandler := mcp.RequireBearerAuth(
		verifier,
		mcp.WithRequiredScopes("mcp:tools"),
	)(authProvider.Grant([]string{"https://api.github.com"})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ac := mcp.AccessContextFromRequest(r)

		if ac.HasErrors() {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadGateway)
			resources, globalError := ac.GetErrors()
			json.NewEncoder(w).Encode(map[string]any{
				"resources":    resources,
				"global_error": globalError,
			})
			return
		}

		token, err := ac.Access("https://api.github.com")
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}

		// Use the exchanged token to call GitHub API
		githubReq, _ := http.NewRequestWithContext(r.Context(), "GET", "https://api.github.com/user", nil)
		githubReq.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token.AccessToken))

		resp, err := http.DefaultClient.Do(githubReq)
		if err != nil {
			http.Error(w, fmt.Sprintf("GitHub API error: %v", err), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
	})))

	mux.Handle("GET /api/github-user", apiHandler)

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
