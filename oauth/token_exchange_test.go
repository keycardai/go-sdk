package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestTokenExchangeClient_ExchangeToken(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/oauth-authorization-server":
			json.NewEncoder(w).Encode(map[string]string{
				"issuer":         "http://" + r.Host,
				"token_endpoint": "http://" + r.Host + "/token",
			})
		case "/token":
			if r.Method != http.MethodPost {
				t.Errorf("expected POST, got %s", r.Method)
			}
			if err := r.ParseForm(); err != nil {
				t.Fatalf("parsing form: %v", err)
			}
			if r.Form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:token-exchange" {
				t.Errorf("unexpected grant_type: %s", r.Form.Get("grant_type"))
			}
			if r.Form.Get("subject_token") != "user-token-123" {
				t.Errorf("unexpected subject_token: %s", r.Form.Get("subject_token"))
			}
			if r.Form.Get("resource") != "https://api.github.com" {
				t.Errorf("unexpected resource: %s", r.Form.Get("resource"))
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"access_token": "exchanged-token-456",
				"token_type":   "bearer",
				"expires_in":   3600,
				"scope":        "repo user",
			})
		}
	}))
	defer tokenServer.Close()

	client := NewTokenExchangeClient(tokenServer.URL)

	resp, err := client.ExchangeToken(context.Background(), TokenExchangeRequest{
		SubjectToken: "user-token-123",
		Resource:     "https://api.github.com",
	})
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}

	if resp.AccessToken != "exchanged-token-456" {
		t.Errorf("access_token: got %q", resp.AccessToken)
	}
	if resp.TokenType != "bearer" {
		t.Errorf("token_type: got %q", resp.TokenType)
	}
	if resp.ExpiresIn != 3600 {
		t.Errorf("expires_in: got %d", resp.ExpiresIn)
	}
	if len(resp.Scope) != 2 || resp.Scope[0] != "repo" || resp.Scope[1] != "user" {
		t.Errorf("scope: got %v", resp.Scope)
	}
}

func TestTokenExchangeClient_BasicAuth(t *testing.T) {
	var receivedAuth string

	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/oauth-authorization-server":
			json.NewEncoder(w).Encode(map[string]string{
				"issuer":         "http://" + r.Host,
				"token_endpoint": "http://" + r.Host + "/token",
			})
		case "/token":
			receivedAuth = r.Header.Get("Authorization")
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"access_token": "token",
				"token_type":   "bearer",
			})
		}
	}))
	defer tokenServer.Close()

	client := NewTokenExchangeClient(tokenServer.URL,
		WithClientCredentials("my-client", "my-secret"),
	)

	_, err := client.ExchangeToken(context.Background(), TokenExchangeRequest{
		SubjectToken: "user-token",
	})
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}

	if receivedAuth == "" {
		t.Error("expected Authorization header")
	}
	if receivedAuth != "Basic bXktY2xpZW50Om15LXNlY3JldA==" {
		t.Errorf("unexpected Authorization header: %s", receivedAuth)
	}
}

func TestTokenExchangeClient_ErrorResponse(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/oauth-authorization-server":
			json.NewEncoder(w).Encode(map[string]string{
				"issuer":         "http://" + r.Host,
				"token_endpoint": "http://" + r.Host + "/token",
			})
		case "/token":
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error":             "invalid_grant",
				"error_description": "token expired",
			})
		}
	}))
	defer tokenServer.Close()

	client := NewTokenExchangeClient(tokenServer.URL)

	_, err := client.ExchangeToken(context.Background(), TokenExchangeRequest{
		SubjectToken: "expired-token",
	})
	if err == nil {
		t.Fatal("expected error")
	}

	var oauthErr *OAuthError
	if !errors.As(err, &oauthErr) {
		t.Fatalf("expected *OAuthError, got %T: %v", err, err)
	}
	if oauthErr.ErrorCode != "invalid_grant" {
		t.Errorf("error code: got %q, want %q", oauthErr.ErrorCode, "invalid_grant")
	}
	if oauthErr.Message != "token expired" {
		t.Errorf("message: got %q, want %q", oauthErr.Message, "token expired")
	}
}

func TestTokenExchangeClient_ErrorResponse_NonJSON(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/oauth-authorization-server":
			json.NewEncoder(w).Encode(map[string]string{
				"issuer":         "http://" + r.Host,
				"token_endpoint": "http://" + r.Host + "/token",
			})
		case "/token":
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("Internal Server Error"))
		}
	}))
	defer tokenServer.Close()

	client := NewTokenExchangeClient(tokenServer.URL)

	_, err := client.ExchangeToken(context.Background(), TokenExchangeRequest{
		SubjectToken: "some-token",
	})
	if err == nil {
		t.Fatal("expected error")
	}

	var oauthErr *OAuthError
	if errors.As(err, &oauthErr) {
		t.Fatalf("expected generic error, got *OAuthError: %v", err)
	}
	if !strings.Contains(err.Error(), "HTTP 500") {
		t.Errorf("error should contain HTTP status: got %q", err.Error())
	}
}

func TestTokenExchangeClient_TokenEndpoint(t *testing.T) {
	requestCount := 0
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/oauth-authorization-server" {
			requestCount++
			json.NewEncoder(w).Encode(map[string]string{
				"issuer":         "http://" + r.Host,
				"token_endpoint": "http://" + r.Host + "/token",
			})
		}
	}))
	defer tokenServer.Close()

	client := NewTokenExchangeClient(tokenServer.URL)

	// First call triggers discovery
	endpoint, err := client.TokenEndpoint(context.Background())
	if err != nil {
		t.Fatalf("TokenEndpoint: %v", err)
	}
	expectedEndpoint := tokenServer.URL + "/token"
	if endpoint != expectedEndpoint {
		t.Errorf("endpoint: got %q, want %q", endpoint, expectedEndpoint)
	}

	// Second call should use cache (no additional discovery request)
	endpoint2, err := client.TokenEndpoint(context.Background())
	if err != nil {
		t.Fatalf("TokenEndpoint (cached): %v", err)
	}
	if endpoint2 != expectedEndpoint {
		t.Errorf("cached endpoint: got %q, want %q", endpoint2, expectedEndpoint)
	}
	if requestCount != 1 {
		t.Errorf("expected 1 discovery request, got %d", requestCount)
	}
}

func TestTokenExchangeClient_ClientAssertionFields(t *testing.T) {
	var receivedAssertion, receivedAssertionType string

	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/oauth-authorization-server":
			json.NewEncoder(w).Encode(map[string]string{
				"issuer":         "http://" + r.Host,
				"token_endpoint": "http://" + r.Host + "/token",
			})
		case "/token":
			r.ParseForm()
			receivedAssertion = r.FormValue("client_assertion")
			receivedAssertionType = r.FormValue("client_assertion_type")
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"access_token": "token",
				"token_type":   "bearer",
			})
		}
	}))
	defer tokenServer.Close()

	client := NewTokenExchangeClient(tokenServer.URL)
	_, err := client.ExchangeToken(context.Background(), TokenExchangeRequest{
		SubjectToken:        "user-token",
		Resource:            "https://api.github.com",
		ClientAssertion:     "jwt-assertion-here",
		ClientAssertionType: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
	})
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}

	if receivedAssertion != "jwt-assertion-here" {
		t.Errorf("client_assertion: got %q", receivedAssertion)
	}
	if receivedAssertionType != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
		t.Errorf("client_assertion_type: got %q", receivedAssertionType)
	}
}

func TestTokenExchangeClient_RejectsInvalidTokenResponse(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
	}{
		{name: "carriage return", body: `{"access_token":"bad\rtoken"}`},
		{name: "control characters", body: `{"access_token":"bad\r\ntoken","token_type":"Bearer"}`},
		{name: "delete", body: `{"access_token":"bad\u007ftoken"}`},
		{name: "empty token", body: `{"access_token":""}`},
		{name: "line feed", body: `{"access_token":"bad\ntoken"}`},
		{name: "malformed JSON", body: `{"access_token":`},
		{name: "null", body: `{"access_token":"bad\u0000token"}`},
		{name: "tab", body: `{"access_token":"bad\ttoken"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case "/.well-known/oauth-authorization-server":
					json.NewEncoder(w).Encode(map[string]string{
						"issuer":         "http://" + r.Host,
						"token_endpoint": "http://" + r.Host + "/token",
					})
				case "/token":
					w.Write([]byte(tc.body))
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()

			client := NewTokenExchangeClient(server.URL)
			resp, err := client.ExchangeToken(context.Background(), TokenExchangeRequest{
				SubjectToken: "subject-token",
			})
			if err == nil {
				t.Fatalf("expected invalid token response to return an error, got response %#v", resp)
			}
			if resp != nil {
				t.Fatalf("expected nil response on error, got %#v", resp)
			}
		})
	}
}
