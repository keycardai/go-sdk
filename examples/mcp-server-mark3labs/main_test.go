package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/client/transport"
	"github.com/mark3labs/mcp-go/mcp"

	keycard "github.com/keycardai/go-sdk/mcp"
	"github.com/keycardai/go-sdk/oauth"
)

// stubVerifier resolves tokens from a fixed map, standing in for JWT
// verification so the test exercises only the middleware and context plumbing.
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

// tokenSource holds the current bearer token, so the test can rotate tokens
// mid-session like a client refreshing its token.
type tokenSource struct {
	mu    sync.Mutex
	token string
}

func (t *tokenSource) setToken(token string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.token = token
}

func (t *tokenSource) headers(context.Context) map[string]string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return map[string]string{"Authorization": "Bearer " + t.token}
}

func callWhoami(t *testing.T, c *client.Client) string {
	t.Helper()
	req := mcp.CallToolRequest{}
	req.Params.Name = "whoami"
	res, err := c.CallTool(context.Background(), req)
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if res.IsError {
		t.Fatalf("whoami returned a tool error: %+v", res.Content)
	}
	text, ok := res.Content[0].(mcp.TextContent)
	if !ok {
		t.Fatalf("expected text content, got %T", res.Content[0])
	}
	return text.Text
}

// TestAuthInfoFreshnessAcrossSession asserts that when the client rotates its
// token mid-session, tool handlers see the new token's auth through
// keycard.AuthInfoFromContext: mark3labs derives each handler's context from
// the HTTP request that carried the call.
func TestAuthInfoFreshnessAcrossSession(t *testing.T) {
	expiry := time.Now().Add(time.Hour).Unix()
	verifier := &stubVerifier{tokens: map[string]*keycard.AuthInfo{
		"token-a": {Subject: "alice", ClientID: "client-1", Scopes: []string{"mcp:tools", "phase:a"}, ExpiresAt: expiry},
		"token-b": {Subject: "alice", ClientID: "client-1", Scopes: []string{"mcp:tools", "phase:b"}, ExpiresAt: expiry},
	}}

	httpServer := httptest.NewServer(newHandler(verifier, "mcp:tools"))
	defer httpServer.Close()

	source := &tokenSource{token: "token-a"}
	c, err := client.NewStreamableHttpClient(httpServer.URL, transport.WithHTTPHeaderFunc(source.headers))
	if err != nil {
		t.Fatalf("NewStreamableHttpClient: %v", err)
	}
	if err := c.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer c.Close()

	initReq := mcp.InitializeRequest{}
	initReq.Params.ProtocolVersion = mcp.LATEST_PROTOCOL_VERSION
	initReq.Params.ClientInfo = mcp.Implementation{Name: "freshness-test", Version: "0.1.0"}
	if _, err := c.Initialize(context.Background(), initReq); err != nil {
		t.Fatalf("Initialize: %v", err)
	}

	// First call carries token-a.
	text := callWhoami(t, c)
	if !strings.Contains(text, "subject=alice") || !strings.Contains(text, "phase:a") {
		t.Errorf("got %q, want subject=alice with phase:a (token-a)", text)
	}

	// Rotate to token-b on the same session. The handler's context must carry
	// token-b's auth.
	source.setToken("token-b")
	text = callWhoami(t, c)
	if !strings.Contains(text, "phase:b") {
		t.Errorf("got %q, want phase:b (token-b); stale auth from session start", text)
	}

	// A token the verifier rejects must not reach the handler.
	source.setToken("token-unknown")
	req := mcp.CallToolRequest{}
	req.Params.Name = "whoami"
	if _, err := c.CallTool(context.Background(), req); err == nil {
		t.Error("expected error for a rejected token, got nil")
	}
}

// TestUnauthenticatedChallengeAdvertisesResourceMetadata asserts Keycard's
// middleware advertises the path-inserted protected-resource metadata in the
// 401 challenge with no configuration, derived from the request host and
// path. This is the discovery pointer the official-SDK example must set
// explicitly; here it comes for free.
func TestUnauthenticatedChallengeAdvertisesResourceMetadata(t *testing.T) {
	verifier := &stubVerifier{tokens: map[string]*keycard.AuthInfo{}}

	httpServer := httptest.NewServer(newHandler(verifier, "mcp:tools"))
	defer httpServer.Close()

	res, err := http.Post(httpServer.URL+"/mcp", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("POST without token: %v", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status: got %d, want 401", res.StatusCode)
	}
	challenge := res.Header.Get("WWW-Authenticate")
	want := `resource_metadata="` + httpServer.URL + `/.well-known/oauth-protected-resource/mcp"`
	if !strings.Contains(challenge, want) {
		t.Errorf("challenge %q missing %s", challenge, want)
	}
}
