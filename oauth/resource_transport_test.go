package oauth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

type stubResourceSource struct {
	token     string
	err       error
	resources []string
	scopes    [][]string
}

func (s *stubResourceSource) ResourceToken(_ context.Context, resource string, scopes ...string) (*TokenResponse, error) {
	s.resources = append(s.resources, resource)
	s.scopes = append(s.scopes, scopes)
	if s.err != nil {
		return nil, s.err
	}
	return &TokenResponse{AccessToken: s.token, TokenType: "Bearer"}, nil
}

func TestResourceTransport_AttachesBearer(t *testing.T) {
	var got string
	rs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("Authorization")
	}))
	defer rs.Close()

	src := &stubResourceSource{token: "tok-123"}
	client := NewResourceClient(src, "https://mcp.example.com", "mcp:tools")

	resp, err := client.Get(rs.URL)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if want := "Bearer tok-123"; got != want {
		t.Errorf("Authorization: got %q, want %q", got, want)
	}

	// The transport is bound to one resource rather than deriving it from the
	// request URL, so what it asks for must not follow where it is sending.
	if len(src.resources) != 1 || src.resources[0] != "https://mcp.example.com" {
		t.Errorf("resource requested: got %v, want the bound resource, not the request host", src.resources)
	}
	if len(src.scopes) != 1 || len(src.scopes[0]) != 1 || src.scopes[0][0] != "mcp:tools" {
		t.Errorf("scopes requested: got %v", src.scopes)
	}
}

func TestResourceTransport_DoesNotMutateTheCallersRequest(t *testing.T) {
	// http.RoundTripper forbids modifying the request it is handed: a caller
	// may retry it, and a retry carrying a stale Authorization header would be
	// authorized with a token that has since expired.
	rs := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer rs.Close()

	req, err := http.NewRequest(http.MethodGet, rs.URL, nil)
	if err != nil {
		t.Fatal(err)
	}

	tr := &ResourceTransport{Source: &stubResourceSource{token: "tok-123"}, Resource: "https://mcp.example.com"}
	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if h := req.Header.Get("Authorization"); h != "" {
		t.Errorf("caller's request was mutated: Authorization = %q", h)
	}
}

func TestResourceTransport_SurfacesSourceErrors(t *testing.T) {
	// A refusal has to reach the caller as itself. Wrapping it into a transport
	// error would cost the Connect code, which is the only thing saying whether
	// retrying could ever work.
	want := &AgentError{Code: "permission_denied", Message: "declined"}
	tr := &ResourceTransport{Source: &stubResourceSource{err: want}, Resource: "https://mcp.example.com"}

	req, err := http.NewRequest(http.MethodGet, "http://example.invalid", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tr.RoundTrip(req); !IsDeclined(err) {
		t.Errorf("error: got %v, want one IsDeclined matches", err)
	}
}

func TestResourceTransport_RequiresSourceAndResource(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "http://example.invalid", nil)
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name string
		tr   *ResourceTransport
	}{
		{name: "no source", tr: &ResourceTransport{Resource: "https://mcp.example.com"}},
		{name: "no resource", tr: &ResourceTransport{Source: &stubResourceSource{token: "t"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.tr.RoundTrip(req)
			var cfgErr *ConfigurationError
			if !errors.As(err, &cfgErr) {
				t.Errorf("error: got %T (%v), want *ConfigurationError", err, err)
			}
		})
	}
}
