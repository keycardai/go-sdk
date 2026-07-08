// Package main demonstrates agent-to-agent (A2A) delegation: a calling agent delegates
// a task to a target agent on the user's behalf. The delegation client discovers the
// target's agent card, exchanges the inbound user token for one scoped to the target
// (RFC 8693, authenticated with the calling agent's own credential), and invokes the
// target's A2A JSON-RPC endpoint with the exchanged token.
//
// Configure before running:
//   - KEYCARD_ZONE_URL, e.g. https://your-zone.keycard.cloud (the authorization server)
//   - KEYCARD_A2A_CLIENT_ID / KEYCARD_A2A_CLIENT_SECRET (the calling agent's credential)
//   - A2A_TARGET_URL, the target agent's base URL, e.g. https://other-agent.example.com
//   - A2A_SUBJECT_TOKEN, the inbound user's verified access token
//   - A2A_MESSAGE, optional text to send (defaults to a greeting)
//
// Run:
//
//	KEYCARD_ZONE_URL=... KEYCARD_A2A_CLIENT_ID=... KEYCARD_A2A_CLIENT_SECRET=... \
//	A2A_TARGET_URL=... A2A_SUBJECT_TOKEN=... go run ./examples/a2a
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/keycardai/go-sdk/a2a"
)

func main() {
	zoneURL := os.Getenv("KEYCARD_ZONE_URL")
	clientID := os.Getenv("KEYCARD_A2A_CLIENT_ID")
	clientSecret := os.Getenv("KEYCARD_A2A_CLIENT_SECRET")
	targetURL := os.Getenv("A2A_TARGET_URL")
	subjectToken := os.Getenv("A2A_SUBJECT_TOKEN")
	if zoneURL == "" || clientID == "" || clientSecret == "" || targetURL == "" || subjectToken == "" {
		log.Fatal("set KEYCARD_ZONE_URL, KEYCARD_A2A_CLIENT_ID, KEYCARD_A2A_CLIENT_SECRET, A2A_TARGET_URL, and A2A_SUBJECT_TOKEN")
	}

	text := os.Getenv("A2A_MESSAGE")
	if text == "" {
		text = "Hello from the calling agent."
	}

	client, err := a2a.NewDelegationClient(zoneURL, clientID, clientSecret)
	if err != nil {
		log.Fatalf("building delegation client: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := client.Invoke(ctx, targetURL, subjectToken, a2a.NewTextMessage(text))
	if err != nil {
		log.Fatalf("delegating to %s: %v", targetURL, err)
	}

	fmt.Printf("Delegated to %q (%s)\n", result.AgentCard.Name, targetURL)
	for _, part := range result.Message.Parts {
		if part.Text != "" {
			fmt.Printf("Response: %s\n", part.Text)
		}
	}
}
