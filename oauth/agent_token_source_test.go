package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// agentServer runs handler on a Unix socket, which is the only transport the
// local Keycard server offers. Testing over TCP would leave the dialer — the
// part most likely to be wrong — unexercised.
func agentServer(t *testing.T, handler http.HandlerFunc) string {
	t.Helper()

	// Short path: macOS caps sun_path at ~104 bytes and t.TempDir() names are
	// long enough to overflow it once a filename is appended.
	dir, err := os.MkdirTemp("", "kcagent")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "agent.sock")

	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	srv := &httptest.Server{Listener: ln, Config: &http.Server{Handler: handler}}
	srv.Start()
	t.Cleanup(srv.Close)
	return socket
}

func writeIssueJWT(w http.ResponseWriter, token string, expiresAt time.Time) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"token":     token,
		"expiresAt": expiresAt.Format(time.RFC3339),
	})
}

func TestAgentTokenSource_RequestShape(t *testing.T) {
	var gotPath, gotBody, gotOrg, gotZone, gotProto string
	socket := agentServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotOrg = r.Header.Get("Keycard-Org")
		gotZone = r.Header.Get("Keycard-Zone")
		gotProto = r.Header.Get("Connect-Protocol-Version")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		writeIssueJWT(w, "h.p.s", time.Now().Add(time.Hour))
	})

	src := NewAgentTokenSource(
		WithAgentSocket(socket),
		WithAgentWorkload("unit-test"),
		WithAgentTenant("org-1", "zone-a"),
	)

	tok, err := src.ResourceToken(context.Background(), "https://mcp.example.com", "mcp:tools")
	if err != nil {
		t.Fatalf("ResourceToken: %v", err)
	}
	if tok.AccessToken != "h.p.s" {
		t.Errorf("access token: got %q, want %q", tok.AccessToken, "h.p.s")
	}
	if tok.TokenType != "Bearer" {
		t.Errorf("token type: got %q, want Bearer", tok.TokenType)
	}
	if tok.ExpiresIn <= 0 {
		t.Errorf("expires_in: got %d, want a positive lifetime derived from expiresAt", tok.ExpiresIn)
	}

	// The procedure path is the wire contract this package implements by hand
	// rather than through the generated client, so nothing else pins it.
	if want := "/keycard.agent.v1.AgentService/IssueJWT"; gotPath != want {
		t.Errorf("path: got %q, want %q", gotPath, want)
	}
	if gotProto != "1" {
		t.Errorf("Connect-Protocol-Version: got %q, want 1", gotProto)
	}
	if gotOrg != "org-1" || gotZone != "zone-a" {
		t.Errorf("tenant headers: got org=%q zone=%q, want org-1/zone-a", gotOrg, gotZone)
	}

	var body map[string]any
	if err := json.Unmarshal([]byte(gotBody), &body); err != nil {
		t.Fatalf("request body is not JSON: %v (%s)", err, gotBody)
	}
	if body["resource"] != "https://mcp.example.com" {
		t.Errorf("resource: got %v", body["resource"])
	}
	if body["workload"] != "unit-test" {
		t.Errorf("workload: got %v", body["workload"])
	}
	scopes, _ := body["scopes"].([]any)
	if len(scopes) != 1 || scopes[0] != "mcp:tools" {
		t.Errorf("scopes: got %v, want [mcp:tools]", body["scopes"])
	}
}

func TestAgentTokenSource_ResourceIsSentUnchanged(t *testing.T) {
	// The authorization server resolves the indicator the caller chose.
	// Normalizing it here would be a second opinion about what was requested,
	// and the one the server does not hold.
	const messy = "https://MCP.example.com:443/api/../api/"

	var got string
	socket := agentServer(t, func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		got, _ = body["resource"].(string)
		writeIssueJWT(w, "h.p.s", time.Now().Add(time.Hour))
	})

	src := NewAgentTokenSource(WithAgentSocket(socket))
	if _, err := src.ResourceToken(context.Background(), messy); err != nil {
		t.Fatalf("ResourceToken: %v", err)
	}
	if got != messy {
		t.Errorf("resource: got %q, want it sent verbatim as %q", got, messy)
	}
}

func TestAgentTokenSource_CachesUntilExpiry(t *testing.T) {
	var calls atomic.Int32
	socket := agentServer(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		writeIssueJWT(w, "h.p.s", time.Now().Add(time.Hour))
	})

	src := NewAgentTokenSource(WithAgentSocket(socket))
	for range 3 {
		if _, err := src.ResourceToken(context.Background(), "https://mcp.example.com"); err != nil {
			t.Fatalf("ResourceToken: %v", err)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("agent calls: got %d, want 1 — without caching every outbound request costs a round trip", got)
	}

	// A different scope set is a different grant and must not be served from
	// the entry minted for another one.
	if _, err := src.ResourceToken(context.Background(), "https://mcp.example.com", "extra"); err != nil {
		t.Fatalf("ResourceToken: %v", err)
	}
	if got := calls.Load(); got != 2 {
		t.Errorf("agent calls after a scope change: got %d, want 2", got)
	}
}

func TestAgentTokenSource_RemintsInsideTheLeeway(t *testing.T) {
	var calls atomic.Int32
	socket := agentServer(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		// Inside agentExpiryLeeway: still valid, but not for long enough to
		// hand to a caller about to make a request with it.
		writeIssueJWT(w, "h.p.s", time.Now().Add(agentExpiryLeeway/2))
	})

	src := NewAgentTokenSource(WithAgentSocket(socket))
	for range 2 {
		if _, err := src.ResourceToken(context.Background(), "https://mcp.example.com"); err != nil {
			t.Fatalf("ResourceToken: %v", err)
		}
	}
	if got := calls.Load(); got != 2 {
		t.Errorf("agent calls: got %d, want 2 — a token expiring inside the leeway must not be reused", got)
	}
}

func TestAgentTokenSource_MapsConnectCodes(t *testing.T) {
	for _, tc := range []struct {
		code      string
		status    int
		predicate func(error) bool
		name      string
	}{
		{code: AgentCodeDeclined, status: http.StatusForbidden, predicate: IsDeclined, name: "declined"},
		{code: AgentCodeRateLimited, status: http.StatusTooManyRequests, predicate: IsRateLimited, name: "rate limited"},
		{code: AgentCodePrompterUnavailable, status: http.StatusPreconditionFailed, predicate: IsPrompterUnavailable, name: "no prompter"},
		{code: AgentCodeAuthorizationRequired, status: http.StatusUnauthorized, predicate: IsAuthorizationRequired, name: "needs authorization"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			socket := agentServer(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.status)
				_ = json.NewEncoder(w).Encode(map[string]string{"code": tc.code, "message": "nope"})
			})

			src := NewAgentTokenSource(WithAgentSocket(socket))
			_, err := src.ResourceToken(context.Background(), "https://mcp.example.com")

			var agentErr *AgentError
			if !errors.As(err, &agentErr) {
				t.Fatalf("error: got %T (%v), want *AgentError", err, err)
			}
			if agentErr.Code != tc.code {
				t.Errorf("code: got %q, want %q", agentErr.Code, tc.code)
			}
			if !tc.predicate(err) {
				t.Errorf("predicate did not match %q — a caller cannot tell this outcome from the others", tc.code)
			}
			// The predicates must not all fire for one code, or branching on
			// them is meaningless.
			if tc.code != AgentCodeDeclined && IsDeclined(err) {
				t.Errorf("IsDeclined matched %q", tc.code)
			}
		})
	}
}

func TestAgentTokenSource_NoSocketIsAConfigurationError(t *testing.T) {
	t.Setenv(AgentSocketEnv, "")

	src := NewAgentTokenSource()
	_, err := src.ResourceToken(context.Background(), "https://mcp.example.com")

	var cfgErr *ConfigurationError
	if !errors.As(err, &cfgErr) {
		t.Fatalf("error: got %T (%v), want *ConfigurationError", err, err)
	}
}

func TestAgentTokenSource_EmptyResourceIsRejectedLocally(t *testing.T) {
	var calls atomic.Int32
	socket := agentServer(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		writeIssueJWT(w, "h.p.s", time.Now().Add(time.Hour))
	})

	src := NewAgentTokenSource(WithAgentSocket(socket))
	if _, err := src.ResourceToken(context.Background(), ""); err == nil {
		t.Fatal("empty resource was accepted")
	}
	if got := calls.Load(); got != 0 {
		t.Errorf("agent calls: got %d, want 0 — an empty resource must not reach the server, which would default it", got)
	}
}
