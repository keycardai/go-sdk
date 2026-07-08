// Package main demonstrates authorization-server discovery (RFC 8414): it fetches a
// Keycard zone's OAuth metadata and prints the advertised endpoints. This is the first
// call every other operation makes against a zone.
//
// Configure before running:
//   - KEYCARD_ZONE_URL, e.g. https://your-zone.keycard.cloud
//
// Run:
//
//	KEYCARD_ZONE_URL=... go run ./examples/discovery
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

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	metadata, err := oauth.FetchAuthorizationServerMetadata(ctx, zoneURL)
	if err != nil {
		log.Fatalf("discovery failed: %v", err)
	}

	fmt.Printf("issuer:                 %s\n", metadata.Issuer)
	fmt.Printf("authorization_endpoint: %s\n", metadata.AuthorizationEndpoint)
	fmt.Printf("token_endpoint:         %s\n", metadata.TokenEndpoint)
	fmt.Printf("jwks_uri:               %s\n", metadata.JWKSURI)
	fmt.Printf("registration_endpoint:  %s\n", metadata.RegistrationEndpoint)
	if len(metadata.ScopesSupported) > 0 {
		fmt.Printf("scopes_supported:       %v\n", metadata.ScopesSupported)
	}
}
