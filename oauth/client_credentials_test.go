package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestClientCredentialsClient_RequestToken(t *testing.T) {
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
			if r.Form.Get("grant_type") != "client_credentials" {
				t.Errorf("unexpected grant_type: %s", r.Form.Get("grant_type"))
			}
			if r.Form.Get("resource") != "urn:secret:my-app/api-key" {
				t.Errorf("unexpected resource: %s", r.Form.Get("resource"))
			}
			if r.Form.Get("subject_token") != "" {
				t.Errorf("subject_token should not be present, got: %s", r.Form.Get("subject_token"))
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"access_token": "vault-secret-456",
				"token_type":   "bearer",
				"expires_in":   3600,
			})
		}
	}))
	defer tokenServer.Close()

	client := NewClientCredentialsClient(tokenServer.URL)

	resp, err := client.RequestToken(context.Background(), ClientCredentialsRequest{
		Resource: "urn:secret:my-app/api-key",
	})
	if err != nil {
		t.Fatalf("request: %v", err)
	}

	if resp.AccessToken != "vault-secret-456" {
		t.Errorf("access_token: got %q", resp.AccessToken)
	}
	if resp.TokenType != "bearer" {
		t.Errorf("token_type: got %q", resp.TokenType)
	}
	if resp.ExpiresIn != 3600 {
		t.Errorf("expires_in: got %d", resp.ExpiresIn)
	}
}

func TestClientCredentialsClient_BasicAuth(t *testing.T) {
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

	client := NewClientCredentialsClient(tokenServer.URL,
		WithCCBasicAuth("my-client", "my-secret"),
	)

	_, err := client.RequestToken(context.Background(), ClientCredentialsRequest{
		Resource: "urn:secret:test",
	})
	if err != nil {
		t.Fatalf("request: %v", err)
	}

	if receivedAuth == "" {
		t.Error("expected Authorization header")
	}
	if receivedAuth != "Basic bXktY2xpZW50Om15LXNlY3JldA==" {
		t.Errorf("unexpected Authorization header: %s", receivedAuth)
	}
}

func TestClientCredentialsClient_ClientAssertion(t *testing.T) {
	var receivedAssertion, receivedAssertionType, receivedGrantType string

	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/oauth-authorization-server":
			json.NewEncoder(w).Encode(map[string]string{
				"issuer":         "http://" + r.Host,
				"token_endpoint": "http://" + r.Host + "/token",
			})
		case "/token":
			r.ParseForm()
			receivedGrantType = r.FormValue("grant_type")
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

	client := NewClientCredentialsClient(tokenServer.URL)
	_, err := client.RequestToken(context.Background(), ClientCredentialsRequest{
		Resource:            "urn:secret:my-app/slack-token",
		ClientAssertion:     "fly-oidc-jwt-here",
		ClientAssertionType: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
	})
	if err != nil {
		t.Fatalf("request: %v", err)
	}

	if receivedGrantType != "client_credentials" {
		t.Errorf("grant_type: got %q", receivedGrantType)
	}
	if receivedAssertion != "fly-oidc-jwt-here" {
		t.Errorf("client_assertion: got %q", receivedAssertion)
	}
	if receivedAssertionType != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
		t.Errorf("client_assertion_type: got %q", receivedAssertionType)
	}
}

func TestClientCredentialsClient_ClientAssertionWithClientID(t *testing.T) {
	var form url.Values
	var basicAuth bool

	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/oauth-authorization-server":
			json.NewEncoder(w).Encode(map[string]string{
				"issuer":         "http://" + r.Host,
				"token_endpoint": "http://" + r.Host + "/token",
			})
		case "/token":
			r.ParseForm()
			form = r.PostForm
			_, _, basicAuth = r.BasicAuth()
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"access_token": "token", "token_type": "bearer"})
		}
	}))
	defer tokenServer.Close()

	req := ClientCredentialsRequest{
		ClientAssertion:     "platform-token",
		ClientAssertionType: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
		ClientID:            "acr_123",
	}

	if _, err := NewClientCredentialsClient(tokenServer.URL).RequestToken(context.Background(), req); err != nil {
		t.Fatalf("request: %v", err)
	}
	if form.Get("client_assertion") != "platform-token" ||
		form.Get("client_assertion_type") != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" ||
		form.Get("client_id") != "acr_123" {
		t.Errorf("body should carry client_assertion, client_assertion_type, and client_id, got %v", form)
	}
	if basicAuth {
		t.Error("assertion request should not send HTTP Basic auth")
	}

	// client_id is never sent with HTTP Basic.
	client := NewClientCredentialsClient(tokenServer.URL, WithCCBasicAuth("my-client", "my-secret"))
	if _, err := client.RequestToken(context.Background(), ClientCredentialsRequest{ClientID: "acr_123"}); err != nil {
		t.Fatalf("request: %v", err)
	}
	if _, ok := form["client_id"]; ok {
		t.Errorf("client_id should not be in the body with HTTP Basic, got %q", form.Get("client_id"))
	}
}

func TestClientCredentialsClient_ErrorResponse(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/oauth-authorization-server":
			json.NewEncoder(w).Encode(map[string]string{
				"issuer":         "http://" + r.Host,
				"token_endpoint": "http://" + r.Host + "/token",
			})
		case "/token":
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{
				"error":             "access_denied",
				"error_description": "policy denied access",
			})
		}
	}))
	defer tokenServer.Close()

	client := NewClientCredentialsClient(tokenServer.URL)

	_, err := client.RequestToken(context.Background(), ClientCredentialsRequest{
		Resource: "urn:secret:forbidden",
	})
	if err == nil {
		t.Fatal("expected error")
	}

	var oauthErr *OAuthError
	if !errors.As(err, &oauthErr) {
		t.Fatalf("expected *OAuthError, got %T: %v", err, err)
	}
	if oauthErr.ErrorCode != "access_denied" {
		t.Errorf("error code: got %q, want %q", oauthErr.ErrorCode, "access_denied")
	}
	if oauthErr.Message != "policy denied access" {
		t.Errorf("message: got %q, want %q", oauthErr.Message, "policy denied access")
	}
}

func TestClientCredentialsClient_ErrorResponse_NonJSON(t *testing.T) {
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

	client := NewClientCredentialsClient(tokenServer.URL)

	_, err := client.RequestToken(context.Background(), ClientCredentialsRequest{
		Resource: "urn:secret:test",
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

func TestClientCredentialsClient_TokenEndpoint(t *testing.T) {
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

	client := NewClientCredentialsClient(tokenServer.URL)

	endpoint, err := client.TokenEndpoint(context.Background())
	if err != nil {
		t.Fatalf("TokenEndpoint: %v", err)
	}
	expectedEndpoint := tokenServer.URL + "/token"
	if endpoint != expectedEndpoint {
		t.Errorf("endpoint: got %q, want %q", endpoint, expectedEndpoint)
	}

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

func TestClientCredentialsClient_Scope(t *testing.T) {
	var receivedScope string

	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/oauth-authorization-server":
			json.NewEncoder(w).Encode(map[string]string{
				"issuer":         "http://" + r.Host,
				"token_endpoint": "http://" + r.Host + "/token",
			})
		case "/token":
			r.ParseForm()
			receivedScope = r.FormValue("scope")
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"access_token": "token",
				"token_type":   "bearer",
				"scope":        "read write",
			})
		}
	}))
	defer tokenServer.Close()

	client := NewClientCredentialsClient(tokenServer.URL)
	resp, err := client.RequestToken(context.Background(), ClientCredentialsRequest{
		Scope: "read write",
	})
	if err != nil {
		t.Fatalf("request: %v", err)
	}

	if receivedScope != "read write" {
		t.Errorf("scope: got %q, want %q", receivedScope, "read write")
	}
	if len(resp.Scope) != 2 || resp.Scope[0] != "read" || resp.Scope[1] != "write" {
		t.Errorf("response scope: got %v", resp.Scope)
	}
}
