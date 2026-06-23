package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keycardai/credentials-go/oauth"
)

func TestAccessContext_SetAndAccess(t *testing.T) {
	ac := NewAccessContext()

	token := &oauth.TokenResponse{
		AccessToken: "github-token",
		TokenType:   "bearer",
		ExpiresIn:   3600,
	}

	ac.SetToken("https://api.github.com", token)

	result, err := ac.Access("https://api.github.com")
	if err != nil {
		t.Fatalf("access: %v", err)
	}
	if result.AccessToken != "github-token" {
		t.Errorf("access_token: got %q", result.AccessToken)
	}
}

func TestAccessContext_Status(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		ac := NewAccessContext()
		ac.SetToken("res1", &oauth.TokenResponse{AccessToken: "t1"})
		if ac.Status() != StatusSuccess {
			t.Errorf("status: got %q, want success", ac.Status())
		}
	})

	t.Run("partial_error", func(t *testing.T) {
		ac := NewAccessContext()
		ac.SetToken("res1", &oauth.TokenResponse{AccessToken: "t1"})
		ac.SetResourceError("res2", ErrorDetail{Message: "failed"})
		if ac.Status() != StatusPartialError {
			t.Errorf("status: got %q, want partial_error", ac.Status())
		}
	})

	t.Run("error", func(t *testing.T) {
		ac := NewAccessContext()
		ac.SetError(ErrorDetail{Message: "global failure"})
		if ac.Status() != StatusError {
			t.Errorf("status: got %q, want error", ac.Status())
		}
	})
}

func TestAccessContext_AccessWithGlobalError(t *testing.T) {
	ac := NewAccessContext()
	ac.SetError(ErrorDetail{Message: "global failure"})

	_, err := ac.Access("https://api.github.com")
	if err == nil {
		t.Fatal("expected error")
	}

	if _, ok := err.(*ResourceAccessError); !ok {
		t.Errorf("expected ResourceAccessError, got %T", err)
	}
}

func TestAccessContext_AccessWithResourceError(t *testing.T) {
	ac := NewAccessContext()
	ac.SetResourceError("https://api.github.com", ErrorDetail{Message: "exchange failed"})

	_, err := ac.Access("https://api.github.com")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestAccessContext_SuccessfulAndFailedResources(t *testing.T) {
	ac := NewAccessContext()
	ac.SetToken("res1", &oauth.TokenResponse{AccessToken: "t1"})
	ac.SetToken("res2", &oauth.TokenResponse{AccessToken: "t2"})
	ac.SetResourceError("res3", ErrorDetail{Message: "failed"})

	successful := ac.SuccessfulResources()
	if len(successful) != 2 {
		t.Errorf("successful: got %d, want 2", len(successful))
	}

	failed := ac.FailedResources()
	if len(failed) != 1 || failed[0] != "res3" {
		t.Errorf("failed: got %v", failed)
	}
}

func TestAccessContext_SetTokenClearsError(t *testing.T) {
	ac := NewAccessContext()
	ac.SetResourceError("res1", ErrorDetail{Message: "failed"})
	ac.SetToken("res1", &oauth.TokenResponse{AccessToken: "t1"})

	if ac.HasResourceError("res1") {
		t.Error("error should be cleared after SetToken")
	}

	result, err := ac.Access("res1")
	if err != nil {
		t.Fatalf("access: %v", err)
	}
	if result.AccessToken != "t1" {
		t.Errorf("access_token: got %q", result.AccessToken)
	}
}

// capturingCredential captures PrepareOptions for test assertions.
type capturingCredential struct {
	capturedOpts *PrepareOptions
}

func (c *capturingCredential) Auth(_ string) *ClientAuth {
	return &ClientAuth{ClientID: "test-client", ClientSecret: "test-secret"}
}

func (c *capturingCredential) PrepareTokenExchangeRequest(_ context.Context, subjectToken, resource string, opts *PrepareOptions) (*oauth.TokenExchangeRequest, error) {
	c.capturedOpts = opts
	return &oauth.TokenExchangeRequest{
		SubjectToken:     subjectToken,
		Resource:         resource,
		SubjectTokenType: "urn:ietf:params:oauth:token-type:access_token",
	}, nil
}

func TestAuthProvider_ExchangeTokens_PassesTokenEndpoint(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/oauth-authorization-server":
			json.NewEncoder(w).Encode(map[string]string{
				"issuer":         "http://" + r.Host,
				"token_endpoint": "http://" + r.Host + "/token",
			})
		case "/token":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"access_token": "exchanged-token",
				"token_type":   "bearer",
			})
		}
	}))
	defer tokenServer.Close()

	cred := &capturingCredential{}
	provider, err := NewAuthProvider(
		WithZoneURL(tokenServer.URL),
		WithApplicationCredential(cred),
	)
	if err != nil {
		t.Fatalf("creating provider: %v", err)
	}

	provider.ExchangeTokens(context.Background(), "user-token", "https://api.github.com")

	if cred.capturedOpts == nil {
		t.Fatal("PrepareOptions was nil — TokenEndpoint not passed through")
	}

	expectedEndpoint := tokenServer.URL + "/token"
	if cred.capturedOpts.TokenEndpoint != expectedEndpoint {
		t.Errorf("TokenEndpoint: got %q, want %q", cred.capturedOpts.TokenEndpoint, expectedEndpoint)
	}
}

func TestNewAuthProvider_RequiresZoneURL(t *testing.T) {
	_, err := NewAuthProvider()
	if err == nil {
		t.Fatal("expected error when no zoneURL or zoneID is provided")
	}

	if _, ok := err.(*AuthProviderConfigurationError); !ok {
		t.Errorf("expected AuthProviderConfigurationError, got %T", err)
	}
}

func TestNewAuthProvider_BuildsZoneURLFromID(t *testing.T) {
	provider, err := NewAuthProvider(
		WithZoneID("my-zone"),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if provider.defaultZone != "https://my-zone.keycard.cloud" {
		t.Errorf("defaultZone: got %q", provider.defaultZone)
	}
}

func TestAuthProvider_ExchangeTokens(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/oauth-authorization-server":
			json.NewEncoder(w).Encode(map[string]string{
				"issuer":         "http://" + r.Host,
				"token_endpoint": "http://" + r.Host + "/token",
			})
		case "/token":
			r.ParseForm()
			resource := r.Form.Get("resource")

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"access_token": "delegated-" + resource,
				"token_type":   "bearer",
				"expires_in":   3600,
			})
		}
	}))
	defer tokenServer.Close()

	provider, err := NewAuthProvider(
		WithZoneURL(tokenServer.URL),
		WithApplicationCredential(NewClientSecret("client-id", "client-secret")),
	)
	if err != nil {
		t.Fatalf("creating provider: %v", err)
	}

	ac := provider.ExchangeTokens(context.Background(), "user-token", "https://api.github.com", "https://api.slack.com")

	if ac.Status() != StatusSuccess {
		t.Errorf("status: got %q, want success", ac.Status())
	}

	githubToken, err := ac.Access("https://api.github.com")
	if err != nil {
		t.Fatalf("github access: %v", err)
	}
	if githubToken.AccessToken != "delegated-https://api.github.com" {
		t.Errorf("github token: got %q", githubToken.AccessToken)
	}

	slackToken, err := ac.Access("https://api.slack.com")
	if err != nil {
		t.Fatalf("slack access: %v", err)
	}
	if slackToken.AccessToken != "delegated-https://api.slack.com" {
		t.Errorf("slack token: got %q", slackToken.AccessToken)
	}
}
