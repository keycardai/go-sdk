package a2a

import (
	"testing"
	"time"

	"github.com/keycardai/go-sdk/internal/printed"
	"github.com/keycardai/go-sdk/internal/printed/printedtest"
)

// TestPrintLeavesOutSecrets checks that a DelegationClient prints its token exchange
// client's issuer and client ID, and that no fmt or slog form holds the client secret.
func TestPrintLeavesOutSecrets(t *testing.T) {
	client, err := NewDelegationClient("https://zone.example.com", "client-id", "client-secret", WithInvokeTimeout(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	printedtest.Check(t, client, "{Exchange:{Issuer:https://zone.example.com ClientID:client-id Credential:<nil> Actor:<nil>} InvokeTimeout:5s}", "client-secret")
}

// TestPrintedFormsListEveryField checks that every exported field of each a2a type
// with a printed form is either printed or marked secret.
func TestPrintedFormsListEveryField(t *testing.T) {
	entry := func(v interface{ printed() printed.Struct }, secret ...string) printedtest.Type {
		return printedtest.Type{Value: v, Form: v.printed(), Secret: secret}
	}
	printedtest.CheckFields(t, ".", []printedtest.Type{
		entry(&DelegationClient{}),
	})
}
