package mcp

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/keycardai/go-sdk/internal/printed"
	"github.com/keycardai/go-sdk/internal/printed/printedtest"
	"github.com/keycardai/go-sdk/oauth"
)

// TestPrintLeavesOutSecrets checks the String output of each mcp type that holds a
// secret, and that no fmt or slog form holds a secret. The credential types are
// aliases of oauth types, which oauth tests.
func TestPrintLeavesOutSecrets(t *testing.T) {
	const issuer = "https://zone.example.com"

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyring, err := oauth.NewPEMPrivateKeyring(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), issuer, "kid-1")
	if err != nil {
		t.Fatal(err)
	}

	tokens := &OAuthTokens{AccessToken: "access-token", TokenType: "Bearer", RefreshToken: "refresh-token", ExpiresIn: 3600}
	store := NewInMemoryTokenStore()
	if err := store.Save(tokens); err != nil {
		t.Fatal(err)
	}
	credential, err := NewClientSecret("client-id", "client-secret")
	if err != nil {
		t.Fatal(err)
	}
	provider, err := NewAuthProvider(WithZoneURL(issuer), WithApplicationCredential(credential))
	if err != nil {
		t.Fatal(err)
	}
	multiZone, err := NewMultiZoneClientSecret(map[string]ClientAuth{
		issuer:                       {ClientID: "id-a", ClientSecret: "secret-a"},
		"https://zone-b.example.com": {ClientID: "id-b", ClientSecret: "secret-b"},
	})
	if err != nil {
		t.Fatal(err)
	}
	multiZoneProvider, err := NewAuthProvider(WithApplicationCredential(multiZone))
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		value   any
		want    string
		secrets []string
	}{
		{
			name:    "OAuthTokens",
			value:   tokens,
			want:    "{TokenType:Bearer ExpiresIn:3600}",
			secrets: []string{"access-token", "refresh-token"},
		},
		{
			name:    "InMemoryTokenStore",
			value:   store,
			want:    "{Tokens:{TokenType:Bearer ExpiresIn:3600}}",
			secrets: []string{"access-token", "refresh-token"},
		},
		{
			name: "AuthInfo",
			value: &AuthInfo{
				Token: "bearer-token", ClientID: "client-id", Subject: "user-1", SubProfile: "user",
				Aud: []string{"https://api.example.com"}, Act: map[string]any{"sub": "agent-1"},
				Scopes: []string{"read"}, ExpiresAt: 1767226200, Issuer: issuer,
			},
			want: "{ClientID:client-id Subject:user-1 SubProfile:user KeycardAppID: Aud:[https://api.example.com] " +
				"Act:map[sub:agent-1] Scopes:[read] Resource: " +
				"ExpiresAt:1767226200 Issuer:https://zone.example.com}",
			secrets: []string{"bearer-token"},
		},
		{
			name:    "single-zone AuthProvider",
			value:   provider,
			want:    "{Zones:[https://zone.example.com] Credential:*oauth.ClientSecretCredential}",
			secrets: []string{"client-secret"},
		},
		{
			name:    "multi-zone AuthProvider",
			value:   multiZoneProvider,
			want:    "{Zones:[https://zone-b.example.com https://zone.example.com] Credential:*oauth.ClientSecretCredential}",
			secrets: []string{"secret-a", "secret-b"},
		},
		{
			name:    "JSONWebTokenSigner",
			value:   NewJSONWebTokenSigner(keyring),
			want:    "{Signer:{Keyring:*oauth.PEMPrivateKeyring}}",
			secrets: []string{key.D.String()},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			printedtest.Check(t, tt.value, tt.want, tt.secrets...)
		})
	}
}

// TestPrintEmptyTokenStore checks that an empty store prints <nil> tokens with every
// form, including slog, which must not call LogValue on a nil *OAuthTokens.
func TestPrintEmptyTokenStore(t *testing.T) {
	printedtest.Check(t, NewInMemoryTokenStore(), "{Tokens:<nil>}", "LogValue panicked")
}

// TestPrintedFormsListEveryField checks that every exported field of each mcp type
// with a printed form is either printed or marked secret.
func TestPrintedFormsListEveryField(t *testing.T) {
	entry := func(v interface{ printed() printed.Struct }, secret ...string) printedtest.Type {
		return printedtest.Type{Value: v, Form: v.printed(), Secret: secret}
	}
	printedtest.CheckFields(t, ".", []printedtest.Type{
		entry(AuthInfo{}, "Token"),
		entry(&AuthProvider{}),
		entry(NewInMemoryTokenStore()),
		entry(&JSONWebTokenSigner{}),
		entry(OAuthTokens{}, "AccessToken", "RefreshToken"),
	})
}
