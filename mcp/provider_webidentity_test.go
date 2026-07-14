package mcp

import (
	"errors"
	"testing"
)

func TestNewAuthProvider_WebIdentityRequiresClientID(t *testing.T) {
	// The provider cannot supply resource_client_id at request time, so a WebIdentity
	// credential without a client id is unusable; NewAuthProvider rejects it at construction.
	_, err := NewAuthProvider(
		WithZoneURL("https://zone.example.com"),
		WithApplicationCredential(NewWebIdentity(WithStorageDir(t.TempDir()))),
	)
	var cfgErr *AuthProviderConfigurationError
	if !errors.As(err, &cfgErr) {
		t.Fatalf("error: got %v, want AuthProviderConfigurationError", err)
	}

	if _, err := NewAuthProvider(
		WithZoneURL("https://zone.example.com"),
		WithApplicationCredential(NewWebIdentity(WithClientID("client-a"), WithStorageDir(t.TempDir()))),
	); err != nil {
		t.Errorf("with a client id, construction should succeed: %v", err)
	}
}
