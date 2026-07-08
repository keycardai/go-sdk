package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keycardai/go-sdk/oauth"
)

// assertionClaims decodes (without verifying) the claims of a JWT client assertion.
func assertionClaims(t *testing.T, jwt string) map[string]any {
	t.Helper()
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWT: %q", jwt)
	}
	payload, err := oauth.Base64URLDecode(parts[1])
	if err != nil {
		t.Fatalf("decoding assertion payload: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("unmarshaling assertion claims: %v", err)
	}
	return claims
}

func TestWebIdentity_AssertionClaims(t *testing.T) {
	cred := NewWebIdentity(WithClientID("client-a"), WithStorageDir(t.TempDir()))

	req, err := cred.PrepareTokenExchangeRequest(context.Background(), "subject-token", "https://api.example.com",
		&PrepareOptions{TokenEndpoint: "https://zone.example.com/token"})
	if err != nil {
		t.Fatalf("PrepareTokenExchangeRequest: %v", err)
	}
	if req.ClientAssertionType != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
		t.Errorf("client_assertion_type: got %q", req.ClientAssertionType)
	}

	claims := assertionClaims(t, req.ClientAssertion)
	if claims["iss"] != "client-a" {
		t.Errorf("iss: got %v, want client-a", claims["iss"])
	}
	if claims["sub"] != "client-a" {
		t.Errorf("sub: got %v, want client-a", claims["sub"])
	}
	if claims["aud"] != "https://zone.example.com/token" {
		t.Errorf("aud: got %v, want the token endpoint", claims["aud"])
	}
}

func TestWebIdentity_RequiresClientID(t *testing.T) {
	cred := NewWebIdentity(WithStorageDir(t.TempDir())) // no client id configured

	_, err := cred.PrepareTokenExchangeRequest(context.Background(), "subject-token", "res",
		&PrepareOptions{TokenEndpoint: "https://zone.example.com/token"})

	var cfgErr *WebIdentityConfigurationError
	if !errors.As(err, &cfgErr) {
		t.Fatalf("error: got %v, want WebIdentityConfigurationError (no key-id fallback)", err)
	}
}

func TestWebIdentity_RequiresTokenEndpoint(t *testing.T) {
	cred := NewWebIdentity(WithClientID("client-a"), WithStorageDir(t.TempDir()))

	_, err := cred.PrepareTokenExchangeRequest(context.Background(), "subject-token", "res",
		&PrepareOptions{}) // no token endpoint, no audience override

	var cfgErr *WebIdentityConfigurationError
	if !errors.As(err, &cfgErr) {
		t.Fatalf("error: got %v, want WebIdentityConfigurationError (no issuer fallback)", err)
	}
}

func TestWebIdentity_ResourceClientIDOverrides(t *testing.T) {
	cred := NewWebIdentity(WithClientID("configured"), WithStorageDir(t.TempDir()))

	req, err := cred.PrepareTokenExchangeRequest(context.Background(), "subject-token", "res", &PrepareOptions{
		TokenEndpoint: "https://zone.example.com/token",
		AuthInfo:      map[string]string{"resource_client_id": "from-request"},
	})
	if err != nil {
		t.Fatalf("PrepareTokenExchangeRequest: %v", err)
	}
	if claims := assertionClaims(t, req.ClientAssertion); claims["iss"] != "from-request" {
		t.Errorf("iss: got %v, want from-request (resource_client_id overrides)", claims["iss"])
	}
}

func TestWebIdentity_AudienceConfigOverride(t *testing.T) {
	cred := NewWebIdentity(WithClientID("client-a"), WithAudienceConfig("https://custom.audience"), WithStorageDir(t.TempDir()))

	req, err := cred.PrepareTokenExchangeRequest(context.Background(), "subject-token", "res",
		&PrepareOptions{TokenEndpoint: "https://zone.example.com/token"})
	if err != nil {
		t.Fatalf("PrepareTokenExchangeRequest: %v", err)
	}
	if claims := assertionClaims(t, req.ClientAssertion); claims["aud"] != "https://custom.audience" {
		t.Errorf("aud: got %v, want the audience override", claims["aud"])
	}
}

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

func TestChooseStorageDir(t *testing.T) {
	base := t.TempDir()
	def := filepath.Join(base, "server_keys")
	legacy := filepath.Join(base, "mcp_keys")

	if got := chooseStorageDir(def, legacy); got != def {
		t.Errorf("neither exists: got %q, want default %q", got, def)
	}

	if err := os.Mkdir(legacy, 0o755); err != nil {
		t.Fatalf("mkdir legacy: %v", err)
	}
	if got := chooseStorageDir(def, legacy); got != legacy {
		t.Errorf("legacy only: got %q, want legacy %q", got, legacy)
	}

	if err := os.Mkdir(def, 0o755); err != nil {
		t.Fatalf("mkdir default: %v", err)
	}
	if got := chooseStorageDir(def, legacy); got != def {
		t.Errorf("both exist: got %q, want default %q", got, def)
	}
}
