package a2a_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"

	"github.com/keycardai/go-sdk/a2a"
)

// ExampleDelegationClient_Invoke shows a calling agent delegating a task to a target
// agent on the user's behalf. The fake servers stand in for a Keycard zone and the
// target agent.
func ExampleDelegationClient_Invoke() {
	// A Keycard zone that performs the RFC 8693 token exchange.
	zone := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/oauth-authorization-server":
			_ = json.NewEncoder(w).Encode(map[string]string{
				"issuer":         "http://" + r.Host,
				"token_endpoint": "http://" + r.Host + "/token",
			})
		case "/token":
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "scoped-token", "token_type": "bearer"})
		}
	}))
	defer zone.Close()

	// The target agent: serves its card and a JSON-RPC endpoint.
	var agent *httptest.Server
	agent = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/agent-card.json":
			_ = json.NewEncoder(w).Encode(map[string]any{"name": "Weather Agent", "url": agent.URL + "/a2a/jsonrpc"})
		case "/a2a/jsonrpc":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"result": map[string]any{"message": map[string]any{
					"messageId": "m1",
					"role":      "agent",
					"parts":     []map[string]any{{"kind": "text", "text": "Sunny, 72F"}},
				}},
			})
		}
	}))
	defer agent.Close()

	client, err := a2a.NewDelegationClient(zone.URL, "calling-agent", "agent-secret")
	if err != nil {
		panic(err)
	}

	result, err := client.Invoke(context.Background(), agent.URL, "inbound-user-token", a2a.NewTextMessage("what's the weather?"))
	if err != nil {
		panic(err)
	}

	fmt.Printf("%s says: %s\n", result.AgentCard.Name, result.Message.Parts[0].Text)
	// Output: Weather Agent says: Sunny, 72F
}
