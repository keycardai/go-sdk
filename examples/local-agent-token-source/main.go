// Package main demonstrates obtaining a resource token from the Keycard agent
// running on this machine, with no application credential.
//
// The agent brokers the token with the developer's own zone session and asks
// a human to approve the first request for each resource and scope set, so
// the first run blocks until someone answers the prompt. The example then
// sends a GET to the resource through a client that attaches the token.
//
// Configuration (environment variables):
//
//	KEYCARD_RESOURCE      Resource indicator to request a token for (required)
//	KEYCARD_RESOURCE_URL  URL to GET with the token (optional; default KEYCARD_RESOURCE)
//	KEYCARD_SCOPES        Space-separated scopes (optional)
//	KEYCARD_ORG           Organization id (required for the keycard agent daemon)
//	KEYCARD_ZONE          Zone id (required for the keycard agent daemon)
//	KEYCARD_APP_ID        Identifier of the Keycard application this acts for (optional)
//
// KEYCARD_SOCKET, when set, names the agent's socket. `keycard run` sets it;
// without it the SDK reaches the keycard agent daemon's default socket.
//
// Setup:
//
//  1. Sign in to the zone with the Keycard CLI: `keycard auth signin`.
//  2. In the Keycard Console, register the resource (for example
//     https://api.github.com) and its provider in the zone.
//  3. Either start the daemon with `keycard agent start` and set KEYCARD_ORG
//     and KEYCARD_ZONE, or run the example under the per-session server:
//     `keycard run -- go run ./examples/local-agent-token-source`.
//  4. To declare an application with KEYCARD_APP_ID, create it in the zone.
//
// Run, from the repository root:
//
//	go run ./examples/local-agent-token-source
package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"

	"github.com/keycardai/go-sdk/oauth"
)

func main() {
	resource := os.Getenv("KEYCARD_RESOURCE")
	if resource == "" {
		log.Fatal("KEYCARD_RESOURCE is required")
	}
	resourceURL := os.Getenv("KEYCARD_RESOURCE_URL")
	if resourceURL == "" {
		resourceURL = resource
	}
	scopes := strings.Fields(os.Getenv("KEYCARD_SCOPES"))

	// No timeout: the first request waits for a human to approve it. Ctrl-C
	// cancels.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	source, err := oauth.NewAgentTokenSource(
		oauth.WithAgentWorkload("local-agent-token-source example"),
		oauth.WithAgentOrg(os.Getenv("KEYCARD_ORG")),
		oauth.WithAgentZone(os.Getenv("KEYCARD_ZONE")),
		oauth.WithAgentAppID(os.Getenv("KEYCARD_APP_ID")),
	)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Requesting a token for %s; approve the prompt if one appears...\n", resource)
	token, err := source.ResourceToken(ctx, resource, scopes...)
	if err != nil {
		explain(err)
	}
	fmt.Printf("Token type:  %s\n", token.TokenType)
	if token.ExpiresIn != nil {
		fmt.Printf("Expires in:  %ds\n", *token.ExpiresIn)
	} else {
		fmt.Println("Expires in:  never")
	}
	if len(token.Scope) > 0 {
		fmt.Printf("Granted:     %s\n", strings.Join(token.Scope, " "))
	}

	client, err := oauth.NewResourceClient(source, resource, scopes...)
	if err != nil {
		log.Fatal(err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, resourceURL, nil)
	if err != nil {
		log.Fatal(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		explain(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	fmt.Printf("GET %s: %s\n%s\n", resourceURL, resp.Status, body)
}

// explain reports a failure with what the caller can do about it, then exits.
func explain(err error) {
	switch {
	case oauth.IsDeclined(err):
		log.Fatalf("declined: %v", err)
	case oauth.IsAuthorizationRequired(err):
		log.Fatalf("sign in or authorize first: %v", err)
	case oauth.IsPrompterUnavailable(err):
		log.Fatalf("no way to ask a human on this host: %v", err)
	case oauth.IsApplicationNotFound(err):
		log.Fatalf("KEYCARD_APP_ID names no application in the zone: %v", err)
	case oauth.IsRateLimited(err), oauth.IsUnavailable(err):
		log.Fatalf("try again shortly: %v", err)
	default:
		log.Fatal(err)
	}
}
