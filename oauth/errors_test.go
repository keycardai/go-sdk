package oauth

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestHTTPError(t *testing.T) {
	err := &HTTPError{Message: "not found", Status: 404}
	if err.Error() != "HTTP 404: not found" {
		t.Errorf("got %q", err.Error())
	}

	err2 := &HTTPError{Message: "something went wrong"}
	if err2.Error() != "something went wrong" {
		t.Errorf("got %q", err2.Error())
	}
}

func TestOAuthError(t *testing.T) {
	err := &OAuthError{ErrorCode: "invalid_grant", Message: "token expired"}
	if err.Error() != "oauth error invalid_grant: token expired" {
		t.Errorf("got %q", err.Error())
	}
}

func TestInvalidTokenError(t *testing.T) {
	err := &InvalidTokenError{Message: "bad signature"}
	if err.Error() != "bad signature" {
		t.Errorf("got %q", err.Error())
	}
	if err.ErrorCode() != "invalid_token" {
		t.Errorf("got %q", err.ErrorCode())
	}

	// Test errors.As
	var target *InvalidTokenError
	if !errors.As(err, &target) {
		t.Error("errors.As should match InvalidTokenError")
	}
}

func TestInsufficientScopeError(t *testing.T) {
	err := &InsufficientScopeError{Message: "need admin"}
	if err.Error() != "need admin" {
		t.Errorf("got %q", err.Error())
	}
	if err.ErrorCode() != "insufficient_scope" {
		t.Errorf("got %q", err.ErrorCode())
	}
}

func TestKeycardErrorMarker(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"ConfigurationError", &ConfigurationError{Message: "bad config"}, true},
		{"HTTPError", &HTTPError{Message: "not found", Status: 404}, true},
		{"OAuthError", &OAuthError{ErrorCode: "invalid_grant", Message: "expired"}, true},
		{"InvalidTokenError", &InvalidTokenError{Message: "bad signature"}, true},
		{"InsufficientScopeError", &InsufficientScopeError{Message: "need scope"}, true},
		{"IssuerMismatchError", &IssuerMismatchError{Message: "mismatch"}, true},
		{"JWKSFetchError", &JWKSFetchError{Message: "fetch failed"}, true},
		{"JWKSKeyNotFoundError", &JWKSKeyNotFoundError{Message: "no key"}, true},
		{"TokenEndpointDiscoveryError", &TokenEndpointDiscoveryError{Message: "no endpoint"}, true},
		{"InvalidMetadataError", &InvalidMetadataError{Message: "bad json"}, true},
		{"generic error", errors.New("some other error"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var kc KeycardError
			if got := errors.As(tt.err, &kc); got != tt.want {
				t.Errorf("errors.As(KeycardError): got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseOAuthErrorResponse(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		wantNil  bool
		wantCode string
		wantMsg  string
		wantURI  string
	}{
		{
			name:     "full RFC 6749 error",
			body:     `{"error":"invalid_grant","error_description":"token expired","error_uri":"https://e.example/err"}`,
			wantCode: "invalid_grant",
			wantMsg:  "token expired",
			wantURI:  "https://e.example/err",
		},
		{
			name:     "error code only falls back to code as message",
			body:     `{"error":"server_error"}`,
			wantCode: "server_error",
			wantMsg:  "server_error",
		},
		{name: "no error field", body: `{"status":"ok"}`, wantNil: true},
		{name: "invalid json", body: `not json`, wantNil: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{Body: io.NopCloser(strings.NewReader(tt.body))}
			got := parseOAuthErrorResponse(resp)
			if tt.wantNil {
				if got != nil {
					t.Fatalf("expected nil, got %+v", got)
				}
				return
			}
			if got == nil {
				t.Fatal("expected an *OAuthError, got nil")
			}
			if got.ErrorCode != tt.wantCode || got.Message != tt.wantMsg || got.ErrorURI != tt.wantURI {
				t.Errorf("got {%q,%q,%q}, want {%q,%q,%q}", got.ErrorCode, got.Message, got.ErrorURI, tt.wantCode, tt.wantMsg, tt.wantURI)
			}
		})
	}
}
