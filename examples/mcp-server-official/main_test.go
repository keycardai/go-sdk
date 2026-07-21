package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	keycard "github.com/keycardai/go-sdk/mcp"
	"github.com/keycardai/go-sdk/oauth"
)

// stubVerifier resolves tokens from a fixed map, standing in for JWT
// verification so the test exercises only the transport plumbing.
type stubVerifier struct {
	tokens map[string]*keycard.AuthInfo
}

func (s *stubVerifier) VerifyAccessToken(_ context.Context, token string) (*keycard.AuthInfo, error) {
	info, ok := s.tokens[token]
	if !ok {
		return nil, &oauth.InvalidTokenError{Message: "unknown token"}
	}
	copied := *info
	copied.Token = token
	return &copied, nil
}

// tokenRoundTripper injects the current bearer token into every request, so
// the test can rotate tokens mid-session like a client refreshing its token.
type tokenRoundTripper struct {
	mu    sync.Mutex
	token string
}

func (t *tokenRoundTripper) setToken(token string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.token = token
}

func (t *tokenRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	t.mu.Lock()
	token := t.token
	t.mu.Unlock()
	clone := req.Clone(req.Context())
	clone.Header.Set("Authorization", "Bearer "+token)
	return http.DefaultTransport.RoundTrip(clone)
}

func callWhoami(t *testing.T, session *mcp.ClientSession) whoamiOutput {
	t.Helper()
	res, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: "whoami"})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if res.IsError {
		t.Fatalf("whoami returned a tool error: %+v", res.Content)
	}
	raw, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatalf("marshal structured content: %v", err)
	}
	var out whoamiOutput
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal whoami output: %v", err)
	}
	return out
}

// TestAuthInfoFreshnessAcrossSession asserts that when the client rotates its
// token mid-session (e.g. a refresh), tool calls see the new token's auth, not
// the auth captured when the session was initialized. This is the property the
// per-call auth.TokenVerifier seam provides; auth stored on the initialize
// request's context would go stale.
func TestAuthInfoFreshnessAcrossSession(t *testing.T) {
	expiry := time.Now().Add(time.Hour).Unix()
	verifier := &stubVerifier{tokens: map[string]*keycard.AuthInfo{
		"token-a":       {Subject: "alice", ClientID: "client-1", Scopes: []string{"mcp:tools", "phase:a"}, ExpiresAt: expiry},
		"token-b":       {Subject: "alice", ClientID: "client-1", Scopes: []string{"mcp:tools", "phase:b"}, ExpiresAt: expiry},
		"token-mallory": {Subject: "mallory", ClientID: "client-2", Scopes: []string{"mcp:tools"}, ExpiresAt: expiry},
	}}

	httpServer := httptest.NewServer(newHandler(verifier, "https://mcp.example.com/.well-known/oauth-protected-resource/mcp", "mcp:tools"))
	defer httpServer.Close()

	rt := &tokenRoundTripper{token: "token-a"}
	transport := &mcp.StreamableClientTransport{
		Endpoint:   httpServer.URL,
		HTTPClient: &http.Client{Transport: rt},
		MaxRetries: -1,
	}

	client := mcp.NewClient(&mcp.Implementation{Name: "freshness-test", Version: "0.1.0"}, nil)
	session, err := client.Connect(context.Background(), transport, nil)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer session.Close()

	// First call carries token-a.
	out := callWhoami(t, session)
	if out.Subject != "alice" {
		t.Errorf("subject: got %q, want %q", out.Subject, "alice")
	}
	if !strings.Contains(strings.Join(out.Scopes, " "), "phase:a") {
		t.Errorf("scopes: got %v, want phase:a (token-a)", out.Scopes)
	}

	// Rotate to token-b on the same session. The tool must see token-b's
	// auth: same user, new scopes.
	rt.setToken("token-b")
	out = callWhoami(t, session)
	if out.Subject != "alice" {
		t.Errorf("subject after rotation: got %q, want %q", out.Subject, "alice")
	}
	if !strings.Contains(strings.Join(out.Scopes, " "), "phase:b") {
		t.Errorf("scopes after rotation: got %v, want phase:b (token-b); stale auth from session start", out.Scopes)
	}

	// A valid token for a different user must be rejected: the UserID set by
	// the adapter binds the session to alice (session-hijack prevention).
	// The transport rejects with 403 "session user mismatch"; the client
	// surfaces only the status text, so assert Forbidden to distinguish the
	// binding rejection from an invalid-token 401 (Unauthorized).
	rt.setToken("token-mallory")
	_, err = session.CallTool(context.Background(), &mcp.CallToolParams{Name: "whoami"})
	if err == nil {
		t.Fatal("expected session user mismatch error for a different user's token, got nil")
	}
	if !strings.Contains(err.Error(), "Forbidden") {
		t.Errorf("rejection: got %q, want 403 Forbidden (session user mismatch)", err)
	}
}

// TestUnauthenticatedChallengeAdvertisesResourceMetadata asserts the 401
// challenge carries resource_metadata (RFC 9728 section 5.1), which is how an
// MCP client discovers the authorization server. The official SDK only emits
// it when ResourceMetadataURL is set on RequireBearerTokenOptions.
func TestUnauthenticatedChallengeAdvertisesResourceMetadata(t *testing.T) {
	verifier := &stubVerifier{tokens: map[string]*keycard.AuthInfo{}}
	prmURL := "https://mcp.example.com/.well-known/oauth-protected-resource/mcp"

	httpServer := httptest.NewServer(newHandler(verifier, prmURL, "mcp:tools"))
	defer httpServer.Close()

	res, err := http.Post(httpServer.URL, "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("POST without token: %v", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status: got %d, want 401", res.StatusCode)
	}
	challenge := res.Header.Get("WWW-Authenticate")
	if challenge == "" {
		t.Fatal("missing WWW-Authenticate challenge on 401")
	}
	if !strings.Contains(challenge, `resource_metadata="`+prmURL+`"`) {
		t.Errorf("challenge %q missing resource_metadata=%q", challenge, prmURL)
	}
}
