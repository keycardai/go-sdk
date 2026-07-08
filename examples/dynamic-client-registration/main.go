// Package main demonstrates dynamic client registration (RFC 7591): it registers a
// new OAuth client with a zone and prints the issued client_id.
//
// Configure in Keycard before running:
//   - A zone (KEYCARD_ZONE_URL) whose authorization server advertises a
//     registration_endpoint.
//   - Optionally KEYCARD_INITIAL_ACCESS_TOKEN, if the zone requires the registration
//     request to be authenticated.
//
// Run:
//
//	KEYCARD_ZONE_URL=... go run ./examples/dynamic-client-registration
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
	if zoneURL == "" {
		log.Fatal("KEYCARD_ZONE_URL environment variable is required")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var opts []oauth.RegisterOption
	if iat := os.Getenv("KEYCARD_INITIAL_ACCESS_TOKEN"); iat != "" {
		opts = append(opts, oauth.WithInitialAccessToken(iat))
	}

	resp, err := oauth.RegisterClient(ctx, zoneURL, oauth.RegistrationRequest{
		ClientName:              "go-sdk example",
		RedirectURIs:            []string{"http://127.0.0.1:8765/callback"},
		GrantTypes:              []string{"authorization_code"},
		TokenEndpointAuthMethod: "none",
	}, opts...)
	if err != nil {
		log.Fatalf("registration failed: %v", err)
	}

	fmt.Printf("Registered client_id: %s\n", resp.ClientID)
	if resp.ClientSecret != "" {
		fmt.Println("A client_secret was issued (confidential client).")
	}
}
