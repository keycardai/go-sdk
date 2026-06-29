package mcp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAuthMetadataHandler_ProtectedResource(t *testing.T) {
	handler := AuthMetadataHandler(
		WithScopesSupported([]string{"mcp:tools", "read"}),
		WithResourceName("Test Server"),
	)

	req := httptest.NewRequest("GET", "/.well-known/oauth-protected-resource", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200", rec.Code)
	}

	var metadata ProtectedResourceMetadata
	if err := json.NewDecoder(rec.Body).Decode(&metadata); err != nil {
		t.Fatalf("decoding: %v", err)
	}

	if metadata.ResourceName != "Test Server" {
		t.Errorf("resource_name: got %q", metadata.ResourceName)
	}
	if len(metadata.ScopesSupported) != 2 {
		t.Errorf("scopes: got %v", metadata.ScopesSupported)
	}
	if metadata.Resource != "http://example.com" {
		t.Errorf("resource: got %q, want http://example.com (origin)", metadata.Resource)
	}
}

func TestAuthMetadataHandler_AuthorizationServersDefault(t *testing.T) {
	handler := AuthMetadataHandler(
		WithIssuer("https://zone.example.com"),
		WithScopesSupported([]string{"mcp:tools"}),
	)

	req := httptest.NewRequest("GET", "/.well-known/oauth-protected-resource", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	var metadata ProtectedResourceMetadata
	json.NewDecoder(rec.Body).Decode(&metadata)

	if len(metadata.AuthorizationServers) != 1 || metadata.AuthorizationServers[0] != "https://zone.example.com" {
		t.Errorf("authorization_servers: got %v, want [https://zone.example.com]", metadata.AuthorizationServers)
	}
}

func TestAuthMetadataHandler_PathInsertedResource(t *testing.T) {
	handler := AuthMetadataHandler(WithIssuer("https://zone.example.com"))

	// RFC 9728 path insertion: a resource mounted at /mcp is advertised under
	// .well-known/oauth-protected-resource/mcp and must resolve to host + /mcp,
	// not the bare origin (the bug in ACC-591).
	req := httptest.NewRequest("GET", "/.well-known/oauth-protected-resource/mcp", nil)
	req.Host = "mcp.example.com"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200", rec.Code)
	}
	var metadata ProtectedResourceMetadata
	if err := json.NewDecoder(rec.Body).Decode(&metadata); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	if metadata.Resource != "http://mcp.example.com/mcp" {
		t.Errorf("resource: got %q, want http://mcp.example.com/mcp", metadata.Resource)
	}
}

func TestAuthMetadataHandler_AuthorizationServer(t *testing.T) {
	// Mock upstream authorization server
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/oauth-authorization-server" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"issuer":                 "https://auth.example.com",
			"authorization_endpoint": "https://auth.example.com/authorize",
			"token_endpoint":         "https://auth.example.com/token",
		})
	}))
	defer upstream.Close()

	handler := AuthMetadataHandler(
		WithIssuer(upstream.URL),
	)

	req := httptest.NewRequest("GET", "/.well-known/oauth-authorization-server", nil)
	req.Host = "mcp.example.com"
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200", rec.Code)
	}

	var metadata map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&metadata); err != nil {
		t.Fatalf("decoding: %v", err)
	}

	// Verify authorization_endpoint is rewritten with resource param
	authEndpoint, ok := metadata["authorization_endpoint"].(string)
	if !ok {
		t.Fatal("missing authorization_endpoint")
	}
	if !strings.Contains(authEndpoint, "resource=") {
		t.Errorf("expected resource param in authorization_endpoint, got %q", authEndpoint)
	}
	if !strings.Contains(authEndpoint, "mcp.example.com") {
		t.Errorf("expected resource to contain host, got %q", authEndpoint)
	}
}

func TestAuthMetadataHandler_AuthorizationServer_UpstreamError(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintln(w, "internal error")
	}))
	defer upstream.Close()

	handler := AuthMetadataHandler(
		WithIssuer(upstream.URL),
	)

	req := httptest.NewRequest("GET", "/.well-known/oauth-authorization-server", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Errorf("status: got %d, want 502", rec.Code)
	}
}

func TestAuthMetadataHandler_CustomHTTPClient(t *testing.T) {
	var requestReceived bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestReceived = true
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"issuer":                 "https://auth.example.com",
			"authorization_endpoint": "https://auth.example.com/authorize",
		})
	}))
	defer upstream.Close()

	customClient := &http.Client{}
	handler := AuthMetadataHandler(
		WithIssuer(upstream.URL),
		WithMetadataHTTPClient(customClient),
	)

	req := httptest.NewRequest("GET", "/.well-known/oauth-authorization-server", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if !requestReceived {
		t.Error("upstream server was not contacted (custom HTTP client may not be used)")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status: got %d, want 200", rec.Code)
	}
}

func TestAuthMetadataHandler_CORSHeaders(t *testing.T) {
	handler := AuthMetadataHandler()

	req := httptest.NewRequest("GET", "/.well-known/oauth-protected-resource", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Error("missing CORS origin header")
	}
}
