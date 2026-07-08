// Package main demonstrates the authorization-code-with-PKCE login flow: it opens
// the browser, runs a loopback callback server, and exchanges the code for a token.
//
// Configure in Keycard before running:
//   - A zone (KEYCARD_ZONE_URL), e.g. https://your-zone.keycard.cloud
//   - A public OAuth client (KEYCARD_CLIENT_ID) registered with token-endpoint auth
//     method "none" and the loopback redirect URI http://127.0.0.1:8765/callback
//
// Run:
//
//	KEYCARD_ZONE_URL=... KEYCARD_CLIENT_ID=... go run ./examples/authorization-code-pkce
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/keycardai/go-sdk/oauth"
)

func main() {
	zoneURL := os.Getenv("KEYCARD_ZONE_URL")
	clientID := os.Getenv("KEYCARD_CLIENT_ID")
	if zoneURL == "" || clientID == "" {
		log.Fatal("KEYCARD_ZONE_URL and KEYCARD_CLIENT_ID environment variables are required")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	fmt.Println("Opening your browser to sign in...")
	token, err := oauth.Authenticate(ctx, zoneURL, oauth.AuthenticateRequest{
		ClientID: clientID,
		Scopes:   []string{"openid"},
	})
	if err != nil {
		log.Fatalf("authentication failed: %v", err)
	}

	fmt.Printf("Signed in. Token type %s, expires in %ds.\n", token.TokenType, token.ExpiresIn)
	fmt.Println(token.AccessToken)
}
