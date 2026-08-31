package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	keycard "github.com/keycardai/go-sdk/mcp"
)

// The SEP-2243 standard headers only become mandatory on sessions negotiated
// at 2026-07-28 or later, and the official SDK's streamable transport serves
// that version only when the handler is stateless
// (StreamableServerTransport.SupportsProtocolVersion). The stateful handler
// newHandler builds therefore never arms the validation: its server/discover
// response advertises 2025-11-25 at best and the client falls back to the
// legacy initialize handshake.
const (
	protocolVersion20260728 = "2026-07-28"
	protocolVersion20251125 = "2025-11-25"
	metaKeyProtocolVersion  = "io.modelcontextprotocol/protocolVersion"
	metaKeyClientInfo       = "io.modelcontextprotocol/clientInfo"
	// Sessionless requests carry the client identity and capabilities in
	// _meta rather than in an initialize handshake.
	metaKeyClientCapabilities = "io.modelcontextprotocol/clientCapabilities"
)

// newStatelessHandler is newHandler with the streamable handler in stateless
// mode, the configuration under which the server negotiates 2026-07-28.
func newStatelessHandler(verifier keycard.TokenVerifier, resourceMetadataURL string, requiredScopes ...string) http.Handler {
	server := mcp.NewServer(&mcp.Implementation{Name: "keycard-official-example", Version: "0.1.0"}, nil)
	mcp.AddTool(server, &mcp.Tool{
		Name:        "whoami",
		Description: "Report the authenticated caller for this call",
	}, whoami)

	streamable := mcp.NewStreamableHTTPHandler(
		func(*http.Request) *mcp.Server { return server },
		&mcp.StreamableHTTPOptions{Stateless: true},
	)

	return auth.RequireBearerToken(KeycardTokenVerifier(verifier), &auth.RequireBearerTokenOptions{
		Scopes:              requiredScopes,
		ResourceMetadataURL: resourceMetadataURL,
	})(streamable)
}

const testPRMURL = "https://mcp.example.com/.well-known/oauth-protected-resource/mcp"

func testVerifier() *stubVerifier {
	return &stubVerifier{tokens: map[string]*keycard.AuthInfo{
		"token-a": {
			Subject:   "alice",
			ClientID:  "client-1",
			Scopes:    []string{"mcp:tools"},
			ExpiresAt: time.Now().Add(time.Hour).Unix(),
		},
	}}
}

// TestStatelessSessionNegotiates20260728 asserts the SEP-2575 server/discover
// path is reachable through the Keycard middleware chain: the session lands on
// 2026-07-28, which is what makes the Mcp-Method / Mcp-Name validation
// mandatory for every subsequent tools/call. The call itself succeeds because
// the SDK client sets those headers from the request it is sending.
func TestStatelessSessionNegotiates20260728(t *testing.T) {
	httpServer := httptest.NewServer(newStatelessHandler(testVerifier(), testPRMURL, "mcp:tools"))
	defer httpServer.Close()

	transport := &mcp.StreamableClientTransport{
		Endpoint:   httpServer.URL,
		HTTPClient: &http.Client{Transport: &tokenRoundTripper{token: "token-a"}},
		MaxRetries: -1,
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "headers-test", Version: "0.1.0"}, nil)
	session, err := client.Connect(context.Background(), transport, nil)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer session.Close()

	if got := session.InitializeResult().ProtocolVersion; got != protocolVersion20260728 {
		t.Fatalf("negotiated protocol version: got %q, want %q", got, protocolVersion20260728)
	}

	if out := callWhoami(t, session); out.Subject != "alice" {
		t.Errorf("subject: got %q, want %q", out.Subject, "alice")
	}
}

// TestStatefulSessionStaysBelow20260728 pins the gate the example itself sits
// behind: with the default (stateful) streamable handler the transport does
// not serve 2026-07-28, so header validation stays dormant. If a later SDK
// release lifts that restriction this test fails, which is the signal that the
// proxy guidance in the README now applies to the default configuration too.
func TestStatefulSessionStaysBelow20260728(t *testing.T) {
	httpServer := httptest.NewServer(newHandler(testVerifier(), testPRMURL, "mcp:tools"))
	defer httpServer.Close()

	transport := &mcp.StreamableClientTransport{
		Endpoint:   httpServer.URL,
		HTTPClient: &http.Client{Transport: &tokenRoundTripper{token: "token-a"}},
		MaxRetries: -1,
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "headers-test", Version: "0.1.0"}, nil)
	session, err := client.Connect(context.Background(), transport, nil)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer session.Close()

	if got := session.InitializeResult().ProtocolVersion; got != protocolVersion20251125 {
		t.Fatalf("negotiated protocol version: got %q, want %q", got, protocolVersion20251125)
	}
}

// rawToolCall issues a hand-built tools/call exactly as the SDK client would
// on a 2026-07-28 session, minus any header named in strip.
func rawToolCall(t *testing.T, endpoint string, strip ...string) *http.Response {
	t.Helper()

	body := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"_meta":{%q:%q,%q:{"name":"headers-test","version":"0.1.0"},%q:{}},"name":"whoami","arguments":{}}}`,
		metaKeyProtocolVersion, protocolVersion20260728, metaKeyClientInfo, metaKeyClientCapabilities)
	req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Authorization", "Bearer token-a")
	req.Header.Set("MCP-Protocol-Version", protocolVersion20260728)
	req.Header.Set("Mcp-Method", "tools/call")
	req.Header.Set("Mcp-Name", "whoami")
	for _, h := range strip {
		req.Header.Del(h)
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST tools/call: %v", err)
	}
	return res
}

// TestToolCallRejectedWhenMcpHeadersStripped is the proxy failure mode: an
// intermediary that drops Mcp-Method / Mcp-Name turns every tools/call on a
// 2026-07-28 session into a 400. The same request with the headers intact
// succeeds, so the rejection is attributable to the stripping alone.
func TestToolCallRejectedWhenMcpHeadersStripped(t *testing.T) {
	httpServer := httptest.NewServer(newStatelessHandler(testVerifier(), testPRMURL, "mcp:tools"))
	defer httpServer.Close()

	res := rawToolCall(t, httpServer.URL)
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		payload, _ := io.ReadAll(res.Body)
		t.Fatalf("control request with headers intact: got %d, want 200 (body %s)", res.StatusCode, payload)
	}

	for _, stripped := range []string{"Mcp-Method", "Mcp-Name"} {
		t.Run(stripped, func(t *testing.T) {
			res := rawToolCall(t, httpServer.URL, stripped)
			defer res.Body.Close()
			payload, err := io.ReadAll(res.Body)
			if err != nil {
				t.Fatalf("read body: %v", err)
			}

			if res.StatusCode != http.StatusBadRequest {
				t.Fatalf("status: got %d, want 400 (body %s)", res.StatusCode, payload)
			}
			// The failure must be legible as a transport-level header
			// complaint, not as a Keycard auth failure: no 401, and no
			// WWW-Authenticate challenge to send clients back through
			// discovery and token acquisition.
			if challenge := res.Header.Get("WWW-Authenticate"); challenge != "" {
				t.Errorf("unexpected WWW-Authenticate challenge on header rejection: %q", challenge)
			}
			if !strings.Contains(string(payload), stripped) {
				t.Errorf("body %s does not name the missing %s header", payload, stripped)
			}
		})
	}
}

// TestMiddlewareChainPreservesMcpHeaders asserts the Keycard auth layer is not
// itself the intermediary that breaks the contract: the headers reach the MCP
// transport byte-for-byte.
func TestMiddlewareChainPreservesMcpHeaders(t *testing.T) {
	var got http.Header
	spy := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
	})
	handler := auth.RequireBearerToken(KeycardTokenVerifier(testVerifier()), &auth.RequireBearerTokenOptions{
		Scopes:              []string{"mcp:tools"},
		ResourceMetadataURL: testPRMURL,
	})(spy)

	httpServer := httptest.NewServer(handler)
	defer httpServer.Close()

	res := rawToolCall(t, httpServer.URL)
	defer res.Body.Close()

	want := map[string]string{
		"Mcp-Method":           "tools/call",
		"Mcp-Name":             "whoami",
		"MCP-Protocol-Version": protocolVersion20260728,
	}
	for header, value := range want {
		if got.Get(header) != value {
			t.Errorf("%s reaching the transport: got %q, want %q", header, got.Get(header), value)
		}
	}
}
