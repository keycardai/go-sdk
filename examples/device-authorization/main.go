// Package main demonstrates the device authorization grant (RFC 8628). A process
// with no browser asks the zone for a user code, prints it, and polls until a person
// approves the request on another device.
//
// Configure in Keycard before running:
//   - A zone (KEYCARD_ZONE_URL), e.g. https://your-zone.keycard.cloud
//   - An OAuth client (KEYCARD_CLIENT_ID) with the device code grant enabled. For a
//     confidential client, also set KEYCARD_CLIENT_SECRET. Without it the example
//     runs as a public client and sends only client_id.
//   - Optional: KEYCARD_SCOPES, space-separated (default "openid"). With openid, the
//     zone adds its userinfo resource, so policy must allow it for this client.
//   - Optional: KEYCARD_RESOURCES, space-separated resource URLs. Each must be a
//     Resource in the zone, or the request fails with invalid_target.
//
// Run:
//
//	KEYCARD_ZONE_URL=... KEYCARD_CLIENT_ID=... go run ./examples/device-authorization
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"

	"github.com/keycardai/go-sdk/oauth"
)

func main() {
	zoneURL := os.Getenv("KEYCARD_ZONE_URL")
	clientID := os.Getenv("KEYCARD_CLIENT_ID")
	if zoneURL == "" || clientID == "" {
		log.Fatal("KEYCARD_ZONE_URL and KEYCARD_CLIENT_ID environment variables are required")
	}
	scopes := strings.Fields(os.Getenv("KEYCARD_SCOPES"))
	if len(scopes) == 0 {
		scopes = []string{"openid"}
	}
	resources := strings.Fields(os.Getenv("KEYCARD_RESOURCES"))

	var auth oauth.DeviceAuthorizationOption
	if secret := os.Getenv("KEYCARD_CLIENT_SECRET"); secret != "" {
		cred, err := oauth.NewClientSecret(clientID, secret)
		if err != nil {
			log.Fatalf("client secret credential: %v", err)
		}
		auth = oauth.WithDeviceCredential(cred)
	} else {
		auth = oauth.WithDevicePublicClient(clientID)
	}

	client, err := oauth.NewDeviceAuthorizationClient(zoneURL, auth)
	if err != nil {
		log.Fatalf("device authorization client: %v", err)
	}

	// Ctrl-C cancels the wait or the request in progress.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	da, err := client.RequestDeviceAuthorization(ctx, oauth.DeviceAuthorizationRequest{
		Scopes:    scopes,
		Resources: resources,
	})
	if err != nil {
		log.Fatalf("device authorization request failed: %v", err)
	}

	verifyAt := da.VerificationURIComplete
	if verifyAt == "" {
		verifyAt = da.VerificationURI
	}
	fmt.Printf("On another device, open:\n\n  %s\n\nand confirm the code:\n\n  %s\n\n", verifyAt, da.UserCode)
	fmt.Printf("Waiting for approval (expires at %s)...\n", da.ExpiresAt.Format("15:04:05"))

	token, err := client.WaitForToken(ctx, *da)
	if err != nil {
		var oauthErr *oauth.OAuthError
		if errors.As(err, &oauthErr) {
			switch oauthErr.ErrorCode {
			case "access_denied":
				log.Fatal("the request was denied")
			case "expired_token":
				log.Fatal("the code expired before anyone approved it; run the example again")
			}
		}
		log.Fatalf("waiting for approval failed: %v", err)
	}

	fmt.Printf("Approved. Token type %s, expires in %ds, scopes %v.\n", token.TokenType, token.ExpiresIn, token.Scope)
	fmt.Printf("refresh_token returned: %t\n", token.RefreshToken != "")
	fmt.Printf("id_token returned: %t\n", token.IDToken != "")
}
