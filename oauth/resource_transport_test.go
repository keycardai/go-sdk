package oauth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// stubResourceTokenSource returns tok, or err, and records the arguments of the
// last call.
type stubResourceTokenSource struct {
	tok *TokenResponse
	err error

	resource string
	scopes   []string
}

func (s *stubResourceTokenSource) ResourceToken(_ context.Context, resource string, scopes ...string) (*TokenResponse, error) {
	s.resource, s.scopes = resource, scopes
	if s.err != nil {
		return nil, s.err
	}
	return s.tok, nil
}

// resourceServer records the Authorization header of each request it serves.
func resourceServer(t *testing.T) (*httptest.Server, *atomic.Int32, *atomic.Value) {
	t.Helper()
	var hits atomic.Int32
	var auth atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		auth.Store(r.Header.Get("Authorization"))
	}))
	t.Cleanup(srv.Close)
	return srv, &hits, &auth
}

func TestResourceTransport_Row35_SetsBearer(t *testing.T) {
	srv, _, auth := resourceServer(t)
	src := &stubResourceTokenSource{tok: &TokenResponse{AccessToken: "tok-35"}}
	client, err := NewResourceClient(src, "https://api.example.com", "read")
	if err != nil {
		t.Fatalf("NewResourceClient: %v", err)
	}
	if client.Timeout != 0 {
		t.Errorf("client Timeout: got %v, want none", client.Timeout)
	}

	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	_ = resp.Body.Close()

	if got := auth.Load(); got != "Bearer tok-35" {
		t.Errorf("Authorization: got %v", got)
	}
	if src.resource != "https://api.example.com" || fmt.Sprint(src.scopes) != "[read]" {
		t.Errorf("source called with %q %v", src.resource, src.scopes)
	}
}

func TestResourceTransport_Row36_SourceErrorPropagates(t *testing.T) {
	srv, hits, _ := resourceServer(t)
	src := &stubResourceTokenSource{err: &AgentError{Code: AgentCodePermissionDenied, Message: "declined"}}
	client, err := NewResourceClient(src, "https://api.example.com")
	if err != nil {
		t.Fatalf("NewResourceClient: %v", err)
	}

	_, err = client.Get(srv.URL)
	if !IsDeclined(err) {
		t.Errorf("IsDeclined: got false for %v", err)
	}
	if n := hits.Load(); n != 0 {
		t.Errorf("resource requests: got %d, want 0", n)
	}

	transport := &ResourceTransport{Source: src, Resource: "https://api.example.com"}
	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	if _, err := transport.RoundTrip(req); err != src.err {
		t.Errorf("RoundTrip: got %v, want the source's error unwrapped", err)
	}
}

func TestResourceTransport_Row37_MissingSourceOrResource(t *testing.T) {
	src := &stubResourceTokenSource{tok: &TokenResponse{AccessToken: "tok"}}
	tests := []struct {
		name     string
		source   ResourceTokenSource
		resource string
	}{
		{"without a source", nil, "https://api.example.com"},
		{"without a resource", src, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cfgErr *ConfigurationError
			if _, err := NewResourceTransport(tt.source, tt.resource); !errors.As(err, &cfgErr) {
				t.Errorf("NewResourceTransport: got %v, want *ConfigurationError", err)
			}
			if _, err := NewResourceClient(tt.source, tt.resource); !errors.As(err, &cfgErr) {
				t.Errorf("NewResourceClient: got %v, want *ConfigurationError", err)
			}

			srv, hits, _ := resourceServer(t)
			req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
			transport := &ResourceTransport{Source: tt.source, Resource: tt.resource}
			if _, err := transport.RoundTrip(req); !errors.As(err, &cfgErr) {
				t.Errorf("RoundTrip: got %v, want *ConfigurationError", err)
			}
			if n := hits.Load(); n != 0 {
				t.Errorf("resource requests: got %d, want 0", n)
			}
		})
	}
}

func TestResourceTransport_Row38_CallerRequestUnchanged(t *testing.T) {
	srv, _, auth := resourceServer(t)
	transport, err := NewResourceTransport(&stubResourceTokenSource{tok: &TokenResponse{AccessToken: "fresh"}}, "https://api.example.com")
	if err != nil {
		t.Fatalf("NewResourceTransport: %v", err)
	}

	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	req.Header.Set("Authorization", "Bearer stale")
	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	_ = resp.Body.Close()

	if got := req.Header.Get("Authorization"); got != "Bearer stale" {
		t.Errorf("caller's Authorization: got %q, want it unchanged", got)
	}
	if got := auth.Load(); got != "Bearer fresh" {
		t.Errorf("sent Authorization: got %v, want the replaced value", got)
	}
}

// closeTracker records whether the transport closed the request body.
type closeTracker struct {
	*strings.Reader
	closed bool
}

func (c *closeTracker) Close() error { c.closed = true; return nil }

func TestResourceTransport_SourceWithoutTokenIsAnError(t *testing.T) {
	srv, hits, _ := resourceServer(t)
	for name, tok := range map[string]*TokenResponse{
		"nil token":          nil,
		"empty access token": {TokenType: "Bearer"},
	} {
		t.Run(name, func(t *testing.T) {
			transport := &ResourceTransport{Source: &stubResourceTokenSource{tok: tok}, Resource: "https://api.example.com"}
			req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
			resp, err := transport.RoundTrip(req)
			if err == nil {
				_ = resp.Body.Close()
				t.Fatal("RoundTrip succeeded")
			}
			if !strings.Contains(err.Error(), "no token") {
				t.Errorf("error does not say the source returned no token: %v", err)
			}
		})
	}
	if n := hits.Load(); n != 0 {
		t.Errorf("resource requests: got %d, want 0", n)
	}
}

func TestResourceTransport_ClosesBodyOnError(t *testing.T) {
	tests := []struct {
		name      string
		transport *ResourceTransport
	}{
		{"source error", &ResourceTransport{Source: &stubResourceTokenSource{err: errors.New("no token")}, Resource: "https://api.example.com"}},
		{"invalid transport", &ResourceTransport{Resource: "https://api.example.com"}},
		{"nil token", &ResourceTransport{Source: &stubResourceTokenSource{}, Resource: "https://api.example.com"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := &closeTracker{Reader: strings.NewReader("payload")}
			req, _ := http.NewRequest(http.MethodPost, "http://resource.invalid", body)
			if _, err := tt.transport.RoundTrip(req); err == nil {
				t.Fatal("RoundTrip succeeded")
			}
			if !body.closed {
				t.Error("request body not closed")
			}
		})
	}
}

type recordingRoundTripper struct{ req *http.Request }

func (r *recordingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	r.req = req
	return &http.Response{StatusCode: http.StatusNoContent, Body: http.NoBody, Request: req}, nil
}

func TestResourceTransport_SendsThroughBase(t *testing.T) {
	base := &recordingRoundTripper{}
	transport := &ResourceTransport{
		Source:   &stubResourceTokenSource{tok: &TokenResponse{AccessToken: "tok-base"}},
		Resource: "https://api.example.com",
		Base:     base,
	}
	req, _ := http.NewRequest(http.MethodGet, "http://resource.invalid/", nil)
	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	_ = resp.Body.Close()
	if base.req == nil {
		t.Fatal("Base was not used")
	}
	if got := base.req.Header.Get("Authorization"); got != "Bearer tok-base" {
		t.Errorf("Authorization at Base: got %q", got)
	}
}

func TestResourceClient_CrossOriginRedirectIsRefused(t *testing.T) {
	other, otherHits, _ := resourceServer(t)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/landing", http.StatusFound)
	}))
	t.Cleanup(origin.Close)

	src := &stubResourceTokenSource{tok: &TokenResponse{AccessToken: "tok-redirect"}}
	client, err := NewResourceClient(src, "https://api.example.com")
	if err != nil {
		t.Fatalf("NewResourceClient: %v", err)
	}
	resp, err := client.Get(origin.URL)
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("cross-origin redirect followed, want an error")
	}
	if n := otherHits.Load(); n != 0 {
		t.Errorf("redirect target received %d request(s) carrying the token", n)
	}
}

func TestResourceClient_SameOriginRedirectIsFollowed(t *testing.T) {
	var auth atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/landing" {
			http.Redirect(w, r, "/landing", http.StatusFound)
			return
		}
		auth.Store(r.Header.Get("Authorization"))
	}))
	t.Cleanup(srv.Close)

	src := &stubResourceTokenSource{tok: &TokenResponse{AccessToken: "tok-same"}}
	client, err := NewResourceClient(src, "https://api.example.com")
	if err != nil {
		t.Fatalf("NewResourceClient: %v", err)
	}
	resp, err := client.Get(srv.URL + "/start")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	_ = resp.Body.Close()
	if got, _ := auth.Load().(string); got != "Bearer tok-same" {
		t.Errorf("Authorization after same-origin redirect: got %q", got)
	}
}
