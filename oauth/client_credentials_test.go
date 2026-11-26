package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
)

func newClientCredentialsTestServer(t *testing.T, check func(*http.Request)) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/oauth-authorization-server":
			json.NewEncoder(w).Encode(map[string]string{
				"issuer":         "http://" + r.Host,
				"token_endpoint": "http://" + r.Host + "/token",
			})
		case "/token":
			if err := r.ParseForm(); err != nil {
				t.Errorf("parsing form: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			check(r)
			json.NewEncoder(w).Encode(map[string]string{"access_token": "token", "token_type": "bearer"})
		default:
			t.Errorf("unexpected request: %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

// Spec row 4b: apply configured workload authentication with an optional client ID.
func TestClientCredentialsClient_WorkloadIdentity(t *testing.T) {
	for _, id := range []string{"workload-client", ""} {
		t.Run("client-id="+id, func(t *testing.T) {
			server := newClientCredentialsTestServer(t, func(r *http.Request) {
				want := url.Values{
					"grant_type":            {"client_credentials"},
					"scope":                 {"read"},
					"client_assertion":      {"workload-jwt"},
					"client_assertion_type": {clientAssertionTypeJWTBearer},
				}
				if id != "" {
					want.Set("client_id", id)
				}
				if got := r.PostForm.Encode(); got != want.Encode() {
					t.Errorf("form: got %q, want %q", got, want.Encode())
				}
				if got := r.Header.Get("Authorization"); got != "" {
					t.Errorf("unexpected Authorization: %q", got)
				}
			})
			calls := 0
			cred, err := NewWorkloadIdentity(IdentityTokenFunc(func(context.Context) (string, error) {
				calls++
				return "workload-jwt", nil
			}), WithWorkloadClientID(id))
			if err != nil {
				t.Fatal(err)
			}
			client := NewClientCredentialsClient(server.URL, WithCCCredential(cred))
			if _, err := client.RequestToken(context.Background(), ClientCredentialsRequest{Scope: "read"}); err != nil {
				t.Fatal(err)
			}
			if calls != 1 {
				t.Errorf("token source calls: got %d, want 1", calls)
			}
		})
	}
}

// Spec row 4c: reject mixed credential and Basic configuration without HTTP.
func TestClientCredentialsClient_RejectsMixedAuth(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected request: %s", r.URL.Path)
		http.NotFound(w, r)
	}))
	defer server.Close()
	cred, err := NewClientSecret("credential-id", "credential-secret")
	if err != nil {
		t.Fatal(err)
	}
	opts := []ClientCredentialsClientOption{WithCCCredential(cred), WithCCBasicAuth("basic-id", "basic-secret")}
	for range 2 {
		client := NewClientCredentialsClient(server.URL, opts...)
		_, err := client.RequestToken(context.Background(), ClientCredentialsRequest{})
		var configErr *ConfigurationError
		if !errors.As(err, &configErr) {
			t.Errorf("got %v, want ConfigurationError", err)
		}
		slices.Reverse(opts)
	}
}

// A request ClientID beside a configured credential, without a request
// assertion, is a configuration error rather than a silently dropped field.
func TestClientCredentialsClient_RejectsRequestClientIDWithCredential(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected request: %s", r.URL.Path)
		http.NotFound(w, r)
	}))
	defer server.Close()
	cred, err := NewWorkloadIdentity(IdentityTokenFunc(func(context.Context) (string, error) {
		t.Error("configured credential must not be called")
		return "workload-jwt", nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	client := NewClientCredentialsClient(server.URL, WithCCCredential(cred))
	_, err = client.RequestToken(context.Background(), ClientCredentialsRequest{ClientID: "acr_123"})
	var configErr *ConfigurationError
	if !errors.As(err, &configErr) {
		t.Errorf("got %v, want ConfigurationError", err)
	}
}

// Spec row 4d: a request assertion bypasses configured credentials and Basic auth.
func TestClientCredentialsClient_RequestAssertionPrecedence(t *testing.T) {
	cred, err := NewWorkloadIdentity(IdentityTokenFunc(func(context.Context) (string, error) {
		t.Error("configured credential must not be called")
		return "configured-jwt", nil
	}), WithWorkloadClientID("configured-id"))
	if err != nil {
		t.Fatal(err)
	}
	for name, opt := range map[string]ClientCredentialsClientOption{
		"credential": WithCCCredential(cred),
		"basic":      WithCCBasicAuth("basic-id", "basic-secret"),
	} {
		t.Run(name, func(t *testing.T) {
			server := newClientCredentialsTestServer(t, func(r *http.Request) {
				want := url.Values{
					"grant_type":            {"client_credentials"},
					"client_id":             {"request-id"},
					"client_assertion":      {"request-jwt"},
					"client_assertion_type": {clientAssertionTypeJWTBearer},
				}
				if got := r.PostForm.Encode(); got != want.Encode() {
					t.Errorf("form: got %q, want %q", got, want.Encode())
				}
				if got := r.Header.Get("Authorization"); got != "" {
					t.Errorf("unexpected Authorization: %q", got)
				}
			})
			client := NewClientCredentialsClient(server.URL, opt)
			if _, err := client.RequestToken(context.Background(), ClientCredentialsRequest{
				ClientID: "request-id", ClientAssertion: "request-jwt", ClientAssertionType: clientAssertionTypeJWTBearer,
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

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
