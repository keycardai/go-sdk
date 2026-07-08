// Package main demonstrates user impersonation via Keycard token exchange.
//
// A confidential client (the "background agent") obtains a resource-scoped
// access token on behalf of a named user, without the user being present.
// The user must have previously granted access (a delegated grant) for the
// requested resource. Impersonation is forbidden by default and must be
// explicitly permitted by server-side Keycard policy.
//
// It performs an RFC 8693 token exchange authenticated with the client's own
// credentials, where the subject token is an unsigned substitute-user
// assertion carrying the target user id. The issued token's "sub" is the
// target user; the server records this service in its "act" chain for audit.
//
// Configuration (environment variables):
//
//	KEYCARD_ZONE_URL       Keycard zone URL for metadata discovery (required)
//	KEYCARD_CLIENT_ID      Confidential client ID (required)
//	KEYCARD_CLIENT_SECRET  Confidential client secret (required)
//	KEYCARD_USER           Target user identifier, becomes "sub" (required)
//	KEYCARD_RESOURCE       Target resource URI (optional)
//	KEYCARD_SCOPES         Space-separated scopes (optional)
//
// Setup in Keycard Console:
//
//	1. Create a provider and a resource (e.g. https://api.github.com).
//	2. Register this confidential client (password credential) and add the
//	   resource as a dependency.
//	3. Ensure the target user has a delegated grant for the resource.
//	4. Add a policy permitting this application to impersonate.
//
// Run:
//
//	go run ./examples/impersonation
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/keycardai/go-sdk/oauth"
)

func main() {
	zoneURL := os.Getenv("KEYCARD_ZONE_URL")
	clientID := os.Getenv("KEYCARD_CLIENT_ID")
	clientSecret := os.Getenv("KEYCARD_CLIENT_SECRET")
	user := os.Getenv("KEYCARD_USER")
	resource := os.Getenv("KEYCARD_RESOURCE")
	scopesEnv := strings.TrimSpace(os.Getenv("KEYCARD_SCOPES"))

	if zoneURL == "" || clientID == "" || clientSecret == "" || user == "" {
		log.Fatal("KEYCARD_ZONE_URL, KEYCARD_CLIENT_ID, KEYCARD_CLIENT_SECRET, and KEYCARD_USER are required")
	}

	var scopes []string
	if scopesEnv != "" {
		scopes = strings.Fields(scopesEnv)
	}

	fmt.Println("═══ Background Agent (impersonation) ═══")
	fmt.Println("  Auth:            client_credentials")
	fmt.Printf("  On behalf of:    %s\n", user)
	if resource != "" {
		fmt.Printf("  Access resource: %s\n", resource)
	}
	fmt.Println()

	client := oauth.NewTokenExchangeClient(
		zoneURL,
		oauth.WithClientCredentials(clientID, clientSecret),
	)

	token, err := client.Impersonate(context.Background(), oauth.ImpersonateRequest{
		UserIdentifier: user,
		Resource:       resource,
		Scopes:         scopes,
	})
	if err != nil {
		var oauthErr *oauth.OAuthError
		if errors.As(err, &oauthErr) {
			// invalid_grant: user unknown or not impersonatable by this client.
			// unauthorized_client: this client is not permitted to impersonate.
			log.Fatalf("OAuth error: %s - %s", oauthErr.ErrorCode, oauthErr.Message)
		}
		log.Fatalf("impersonation failed: %v", err)
	}

	fmt.Printf("Access Token: %s...\n", preview(token.AccessToken))
	fmt.Printf("Token Type:   %s\n", token.TokenType)
	if token.ExpiresIn > 0 {
		fmt.Printf("Expires In:   %ds\n", token.ExpiresIn)
	}
	if len(token.Scope) > 0 {
		fmt.Printf("Scope:        %s\n", strings.Join(token.Scope, " "))
	}
}

// preview returns a short, non-sensitive prefix of the access token for display.
func preview(token string) string {
	if len(token) <= 6 {
		return token
	}
	return token[:6]
}
