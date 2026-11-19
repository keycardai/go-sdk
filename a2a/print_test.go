package a2a

import (
	"testing"
	"time"

	"github.com/keycardai/go-sdk/internal/printed/printedtest"
)

// TestPrintLeavesOutSecrets checks that a DelegationClient prints its token exchange
// client's issuer and client ID, and that no fmt or slog form holds the client secret.
func TestPrintLeavesOutSecrets(t *testing.T) {
	client, err := NewDelegationClient("https://zone.example.com", "client-id", "client-secret", WithInvokeTimeout(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	printedtest.Check(t, client, "{Exchange:{Issuer:https://zone.example.com ClientID:client-id} InvokeTimeout:5s}", "client-secret")
}
