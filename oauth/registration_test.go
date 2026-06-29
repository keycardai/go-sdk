package oauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// registrationServer serves discovery metadata advertising its own /register endpoint
// and records the registration request it receives.
type registrationServer struct {
	*httptest.Server
	lastBody  map[string]any
	lastAuth  string
	regStatus int
	regBody   string
}

func newRegistrationServer() *registrationServer {
	rs := &registrationServer{
		regStatus: http.StatusCreated,
		regBody:   `{"client_id":"generated-id","client_secret":"generated-secret","client_id_issued_at":1700000000,"client_secret_expires_at":0,"registration_access_token":"rat","registration_client_uri":"https://zone/register/generated-id"}`,
	}
	mux := http.NewServeMux()
	rs.Server = httptest.NewServer(mux)
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                rs.URL,
			"registration_endpoint": rs.URL + "/register",
		})
	})
	mux.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		rs.lastAuth = r.Header.Get("Authorization")
		_ = json.NewDecoder(r.Body).Decode(&rs.lastBody)
		w.WriteHeader(rs.regStatus)
		_, _ = w.Write([]byte(rs.regBody))
	})
	return rs
}

func TestRegisterClient_BodyMergesNamedFieldsOverVendorKeys(t *testing.T) {
	rs := newRegistrationServer()
	defer rs.Close()

	_, err := RegisterClient(context.Background(), rs.URL, RegistrationRequest{
		ClientName:              "My Tool",
		RedirectURIs:            []string{"http://127.0.0.1:8765/callback"},
		TokenEndpointAuthMethod: "none",
		AdditionalMetadata: map[string]any{
			"software_statement": "vendor-value",
			"client_name":        "should-be-overridden",
		},
	}, WithRegistrationHTTPClient(rs.Client()))
	if err != nil {
		t.Fatalf("RegisterClient: %v", err)
	}

	if rs.lastBody["client_name"] != "My Tool" {
		t.Errorf("named client_name should win over vendor key, got %v", rs.lastBody["client_name"])
	}
	if rs.lastBody["software_statement"] != "vendor-value" {
		t.Errorf("vendor key should be merged into the body, got %v", rs.lastBody["software_statement"])
	}
	if rs.lastBody["token_endpoint_auth_method"] != "none" {
		t.Errorf("token_endpoint_auth_method: got %v", rs.lastBody["token_endpoint_auth_method"])
	}
	if _, ok := rs.lastBody["scope"]; ok {
		t.Error("unset fields should be omitted (RFC-minimal)")
	}
}

func TestRegisterClient_ParsesResponse(t *testing.T) {
	rs := newRegistrationServer()
	defer rs.Close()

	resp, err := RegisterClient(context.Background(), rs.URL, RegistrationRequest{
		ClientName: "My Tool",
	}, WithRegistrationHTTPClient(rs.Client()))
	if err != nil {
		t.Fatalf("RegisterClient: %v", err)
	}

	if resp.ClientID != "generated-id" {
		t.Errorf("client_id: got %q", resp.ClientID)
	}
	if resp.ClientSecret != "generated-secret" {
		t.Errorf("client_secret: got %q", resp.ClientSecret)
	}
	if resp.ClientIDIssuedAt != 1700000000 {
		t.Errorf("client_id_issued_at: got %d", resp.ClientIDIssuedAt)
	}
	if resp.ClientSecretExpiresAt != 0 {
		t.Errorf("client_secret_expires_at: got %d", resp.ClientSecretExpiresAt)
	}
	if resp.RegistrationAccessToken != "rat" {
		t.Errorf("registration_access_token: got %q", resp.RegistrationAccessToken)
	}
	if resp.RegistrationClientURI != "https://zone/register/generated-id" {
		t.Errorf("registration_client_uri: got %q", resp.RegistrationClientURI)
	}
	if resp.Raw["client_id"] != "generated-id" {
		t.Error("raw body should be preserved")
	}
}

func TestRegisterClient_MissingClientID(t *testing.T) {
	rs := newRegistrationServer()
	defer rs.Close()
	rs.regBody = `{"client_secret":"secret-without-id"}`

	_, err := RegisterClient(context.Background(), rs.URL, RegistrationRequest{}, WithRegistrationHTTPClient(rs.Client()))
	if err == nil {
		t.Fatal("expected an error when the response has no client_id")
	}
}

func TestRegisterClient_OAuthError(t *testing.T) {
	rs := newRegistrationServer()
	defer rs.Close()
	rs.regStatus = http.StatusBadRequest
	rs.regBody = `{"error":"invalid_client_metadata","error_description":"bad redirect_uri"}`

	_, err := RegisterClient(context.Background(), rs.URL, RegistrationRequest{
		RedirectURIs: []string{"not-a-uri"},
	}, WithRegistrationHTTPClient(rs.Client()))
	if err == nil {
		t.Fatal("expected an error for the OAuth error response")
	}
	oauthErr, ok := err.(*OAuthError)
	if !ok {
		t.Fatalf("expected *OAuthError, got %T: %v", err, err)
	}
	if oauthErr.ErrorCode != "invalid_client_metadata" {
		t.Errorf("error code: got %q, want invalid_client_metadata", oauthErr.ErrorCode)
	}
}

func TestRegisterClient_InitialAccessToken(t *testing.T) {
	rs := newRegistrationServer()
	defer rs.Close()

	_, err := RegisterClient(context.Background(), rs.URL, RegistrationRequest{
		ClientName: "My Tool",
	}, WithRegistrationHTTPClient(rs.Client()), WithInitialAccessToken("iat-123"))
	if err != nil {
		t.Fatalf("RegisterClient: %v", err)
	}
	if rs.lastAuth != "Bearer iat-123" {
		t.Errorf("Authorization header: got %q, want Bearer iat-123", rs.lastAuth)
	}
}
