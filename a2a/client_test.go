package a2a

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/keycardai/go-sdk/oauth"
)

// fakeZone is a fake Keycard authorization server: it advertises a token endpoint and
// performs (or rejects) the RFC 8693 exchange, recording the basic-auth client id it
// received so a test can assert the calling agent's credential was used.
type fakeZone struct {
	*httptest.Server
	mu           sync.Mutex
	exchanges    int
	lastClientID string
	reject       bool
}

func newFakeZone(t *testing.T) *fakeZone {
	t.Helper()
	z := &fakeZone{}
	mux := http.NewServeMux()
	z.Server = httptest.NewServer(mux)
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":         z.URL,
			"token_endpoint": z.URL + "/token",
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		id, _, _ := r.BasicAuth()
		z.mu.Lock()
		z.exchanges++
		z.lastClientID = id
		reject := z.reject
		z.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		if reject {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error":             "invalid_grant",
				"error_description": "user token not accepted for target",
			})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "exchanged-token",
			"token_type":   "bearer",
			"expires_in":   3600,
		})
	})
	t.Cleanup(z.Close)
	return z
}

func (z *fakeZone) exchangeCount() int {
	z.mu.Lock()
	defer z.mu.Unlock()
	return z.exchanges
}

func (z *fakeZone) clientID() string {
	z.mu.Lock()
	defer z.mu.Unlock()
	return z.lastClientID
}

// fakeAgent is a fake target agent: it serves its card and a JSON-RPC endpoint that
// records the bearer token it was invoked with and returns either a response message
// or a JSON-RPC error.
type fakeAgent struct {
	*httptest.Server
	mu          sync.Mutex
	invocations int
	lastBearer  string
	lastHeaders http.Header
	lastBody    map[string]any
	failCode    int
	failMessage string
	hang        bool
	emptyResult bool
	result      map[string]any
}

func newFakeAgent(t *testing.T) *fakeAgent {
	t.Helper()
	a := &fakeAgent{}
	mux := http.NewServeMux()
	a.Server = httptest.NewServer(mux)
	mux.HandleFunc(agentCardPath, func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"name": "Target Agent",
			"url":  a.URL + "/a2a/jsonrpc",
		})
	})
	mux.HandleFunc("/a2a/jsonrpc", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		a.mu.Lock()
		a.invocations++
		a.lastBearer = r.Header.Get("Authorization")
		a.lastHeaders = r.Header.Clone()
		a.lastBody = body
		failMessage := a.failMessage
		failCode := a.failCode
		hang := a.hang
		emptyResult := a.emptyResult
		result := a.result
		a.mu.Unlock()

		if hang {
			// Return when the client cancels, but cap it so the test server's Close()
			// never blocks waiting on this handler.
			select {
			case <-r.Context().Done():
			case <-time.After(time.Second):
			}
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if failMessage != "" {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0",
				"error":   map[string]any{"code": failCode, "message": failMessage},
			})
			return
		}
		if emptyResult {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0",
				"result":  map[string]any{},
			})
			return
		}
		if result == nil {
			// Recorded from a keycardai-a2a (a2a-sdk 1.x) agent answering SendMessage.
			result = map[string]any{
				"message": map[string]any{
					"messageId": "resp-1",
					"contextId": "ctx-1",
					"role":      "ROLE_AGENT",
					"parts":     []map[string]any{{"text": "handled"}},
				},
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0",
			"id":      body["id"],
			"result":  result,
		})
	})
	t.Cleanup(a.Close)
	return a
}

func (a *fakeAgent) request() (http.Header, map[string]any) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.lastHeaders, a.lastBody
}

func (a *fakeAgent) invocationCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.invocations
}

func (a *fakeAgent) bearer() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.lastBearer
}

func TestDelegationClient_Invoke_Redirects(t *testing.T) {
	for _, tc := range []struct {
		row                string
		status             int
		same, trusted, tls bool
	}{
		// Spec row 16: disallowed 307 and 302 redirects receive no request.
		{row: "16/307", status: http.StatusTemporaryRedirect},
		{row: "16/302", status: http.StatusFound},
		// Spec row 17: follow a relative same-origin redirect with the token.
		{row: "17", status: http.StatusTemporaryRedirect, same: true},
		{row: "17/308", status: http.StatusPermanentRedirect, same: true},
		// Spec row 18: follow an allowlisted redirect with the token.
		{row: "18", status: http.StatusTemporaryRedirect, trusted: true},
		// Spec row 19: a scheme downgrade is a disallowed origin change.
		{row: "19", status: http.StatusTemporaryRedirect, tls: true},
	} {
		t.Run(tc.row, func(t *testing.T) {
			zone := newFakeZone(t)
			var redirected atomic.Int32
			redirectHandler := func(w http.ResponseWriter, r *http.Request) {
				redirected.Add(1)
				if r.Method != http.MethodPost || r.Header.Get("Authorization") != "Bearer exchanged-token" {
					t.Errorf("redirect request method = %q, Authorization = %q", r.Method, r.Header.Get("Authorization"))
				}
				var request jsonRPCRequest
				if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
					t.Errorf("redirect request body: %v", err)
				}
				_, _ = w.Write([]byte(`{"jsonrpc":"2.0","result":{"message":{"messageId":"redirected","parts":[{"text":"handled"}]}}}`))
			}
			other := httptest.NewServer(http.HandlerFunc(redirectHandler))
			defer other.Close()

			mux := http.NewServeMux()
			agent := httptest.NewUnstartedServer(mux)
			if tc.tls {
				agent.StartTLS()
			} else {
				agent.Start()
			}
			defer agent.Close()
			destination := other.URL + "/next"
			if tc.same {
				destination = "/next"
			} else if tc.tls {
				destination = "http://" + strings.TrimPrefix(agent.URL, "https://") + "/next"
			}
			mux.HandleFunc(agentCardPath, func(w http.ResponseWriter, _ *http.Request) {
				_ = json.NewEncoder(w).Encode(map[string]string{"name": "Redirecting Agent"})
			})
			mux.HandleFunc("/next", redirectHandler)
			mux.HandleFunc("/a2a/jsonrpc", func(w http.ResponseWriter, r *http.Request) {
				if got := r.Header.Get("Authorization"); got != "Bearer exchanged-token" {
					t.Errorf("invocation Authorization = %q", got)
				}
				w.Header().Set("Location", destination)
				w.WriteHeader(tc.status)
			})

			var options []DelegationOption
			if tc.trusted {
				options = append(options, WithTrustedEndpointOrigins(other.URL))
			}
			if tc.tls {
				options = append(options, WithHTTPClient(agent.Client()))
			}
			client, err := NewDelegationClient(zone.URL, "agent-client", "agent-secret", options...)
			if err != nil {
				t.Fatal(err)
			}
			result, err := client.Invoke(context.Background(), agent.URL, "user-token", NewTextMessage("ping"))
			var wantRequests int32
			if tc.same || tc.trusted {
				wantRequests = 1
				if err != nil || result.Message.MessageID != "redirected" {
					t.Fatalf("wanted the redirect result; got %v, %v", result, err)
				}
			} else {
				origin, _ := endpointOrigin(destination, false)
				originError, ok := err.(*ConfigurationError)
				if !ok || originError.Retryable() ||
					!strings.Contains(originError.Error(), origin) || !strings.Contains(originError.Error(), agent.URL) {
					t.Fatalf("wanted non-retryable refusal for %q on %q; got %v", origin, agent.URL, err)
				}
			}
			if redirected.Load() != wantRequests || zone.exchangeCount() != 1 {
				t.Fatalf("redirect requests = %d, exchanges = %d", redirected.Load(), zone.exchangeCount())
			}
		})
	}
}

// Spec test 3: a valid user token is exchanged for a target-scoped token and the agent
// is invoked with it.
func TestDelegationClient_Invoke_ExchangesThenInvokes(t *testing.T) {
	zone := newFakeZone(t)
	agent := newFakeAgent(t)

	client, err := NewDelegationClient(zone.URL, "agent-client", "agent-secret")
	if err != nil {
		t.Fatalf("NewDelegationClient: %v", err)
	}

	res, err := client.Invoke(context.Background(), agent.URL, "user-token", NewTextMessage("do the thing"))
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}

	if zone.exchangeCount() != 1 {
		t.Errorf("exchanges: got %d, want 1", zone.exchangeCount())
	}
	if zone.clientID() != "agent-client" {
		t.Errorf("exchange authenticated as %q, want agent-client", zone.clientID())
	}
	if agent.invocationCount() != 1 {
		t.Errorf("agent invocations: got %d, want 1", agent.invocationCount())
	}
	if got := agent.bearer(); got != "Bearer exchanged-token" {
		t.Errorf("agent bearer: got %q, want the exchanged token", got)
	}
	if len(res.Message.Parts) != 1 || res.Message.Parts[0].Text != "handled" {
		t.Errorf("response message: got %+v", res.Message)
	}
	if res.Message.Role != RoleAgent || res.Message.ContextID != "ctx-1" {
		t.Errorf("response message role/context: got %q/%q", res.Message.Role, res.Message.ContextID)
	}
	if res.Task != nil {
		t.Errorf("task: got %+v, want nil for an inline message answer", res.Task)
	}
	if res.AgentCard.Name != "Target Agent" {
		t.Errorf("resolved card name: got %q", res.AgentCard.Name)
	}
}

// ECO-161: the wire shape per protocol generation. The default speaks A2A 1.0
// (SendMessage, A2A-Version: 1.0, ROLE_USER, untagged text parts), which is what
// keycardai-a2a serves; WithProtocolVersion(ProtocolVersion03) sends a real 0.3
// envelope, not a 1.0 envelope under a 0.3 header.
func TestDelegationClient_Invoke_WireShape(t *testing.T) {
	cases := []struct {
		name          string
		opts          []DelegationOption
		wantMethod    string
		wantHeader    string
		wantVersion   string
		absentHeader  string
		wantRole      string
		wantPart      map[string]any
		wantMessageID string
	}{
		{
			name:         "default is protocol 1.0",
			wantMethod:   "SendMessage",
			wantHeader:   "A2A-Version",
			wantVersion:  "1.0",
			absentHeader: "x-a2a-protocol-version",
			wantRole:     "ROLE_USER",
			wantPart:     map[string]any{"text": "do the thing"},
		},
		{
			name:         "explicit 1.0",
			opts:         []DelegationOption{WithProtocolVersion(ProtocolVersion10)},
			wantMethod:   "SendMessage",
			wantHeader:   "A2A-Version",
			wantVersion:  "1.0",
			absentHeader: "x-a2a-protocol-version",
			wantRole:     "ROLE_USER",
			wantPart:     map[string]any{"text": "do the thing"},
		},
		{
			name:         "0.3 sends a 0.3 envelope",
			opts:         []DelegationOption{WithProtocolVersion(ProtocolVersion03)},
			wantMethod:   "message/send",
			wantHeader:   "x-a2a-protocol-version",
			wantVersion:  "0.3",
			absentHeader: "A2A-Version",
			wantRole:     "user",
			wantPart:     map[string]any{"kind": "text", "text": "do the thing"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			zone := newFakeZone(t)
			agent := newFakeAgent(t)

			client, err := NewDelegationClient(zone.URL, "agent-client", "agent-secret", tc.opts...)
			if err != nil {
				t.Fatalf("NewDelegationClient: %v", err)
			}
			msg := NewTextMessage("do the thing")
			msg.Metadata = map[string]any{"traceId": "abc"}
			if _, err := client.Invoke(context.Background(), agent.URL, "user-token", msg); err != nil {
				t.Fatalf("Invoke: %v", err)
			}

			headers, body := agent.request()
			if got := headers.Get(tc.wantHeader); got != tc.wantVersion {
				t.Errorf("%s header: got %q, want %q", tc.wantHeader, got, tc.wantVersion)
			}
			if got := headers.Get(tc.absentHeader); got != "" {
				t.Errorf("%s header: got %q, want absent", tc.absentHeader, got)
			}
			if body["jsonrpc"] != "2.0" {
				t.Errorf("jsonrpc: got %v", body["jsonrpc"])
			}
			if body["method"] != tc.wantMethod {
				t.Errorf("method: got %v, want %s", body["method"], tc.wantMethod)
			}
			params, _ := body["params"].(map[string]any)
			wireMsg, _ := params["message"].(map[string]any)
			if wireMsg["messageId"] != msg.MessageID {
				t.Errorf("messageId: got %v, want %s", wireMsg["messageId"], msg.MessageID)
			}
			if wireMsg["role"] != tc.wantRole {
				t.Errorf("role: got %v, want %s", wireMsg["role"], tc.wantRole)
			}
			parts, _ := wireMsg["parts"].([]any)
			if len(parts) != 1 {
				t.Fatalf("parts: got %v, want one part", wireMsg["parts"])
			}
			gotPart, _ := json.Marshal(parts[0])
			wantPart, _ := json.Marshal(tc.wantPart)
			if string(gotPart) != string(wantPart) {
				t.Errorf("part: got %s, want %s", gotPart, wantPart)
			}
			meta, _ := wireMsg["metadata"].(map[string]any)
			if meta["traceId"] != "abc" {
				t.Errorf("metadata: got %v", wireMsg["metadata"])
			}
			for _, key := range []string{"kind", "contextId", "taskId"} {
				if _, present := wireMsg[key]; present {
					t.Errorf("message carried %q, want it omitted when unset", key)
				}
			}
		})
	}
}

// ECO-161 regression guard: the 0.3 method name is never sent unless 0.3 is asked for.
func TestDelegationClient_Invoke_DefaultDoesNotSendLegacyMethod(t *testing.T) {
	zone := newFakeZone(t)
	agent := newFakeAgent(t)

	client, err := NewDelegationClient(zone.URL, "agent-client", "agent-secret")
	if err != nil {
		t.Fatalf("NewDelegationClient: %v", err)
	}
	for i := 0; i < 3; i++ {
		if _, err := client.Invoke(context.Background(), agent.URL, "user-token", NewTextMessage("hi")); err != nil {
			t.Fatalf("Invoke: %v", err)
		}
		_, body := agent.request()
		if body["method"] == "message/send" {
			t.Fatalf("invocation %d sent the 0.3 method message/send", i+1)
		}
	}
}

// A 0.3-configured client translates the 0.3 response (plain role, kind-tagged parts,
// the message as the bare result) back to the 1.0 model callers see.
func TestDelegationClient_Invoke_LegacyResponseDecoded(t *testing.T) {
	zone := newFakeZone(t)
	agent := newFakeAgent(t)
	agent.result = map[string]any{
		"kind":      "message",
		"messageId": "resp-03",
		"role":      "agent",
		"parts":     []map[string]any{{"kind": "text", "text": "handled-03"}},
	}

	client, err := NewDelegationClient(zone.URL, "agent-client", "agent-secret", WithProtocolVersion(ProtocolVersion03))
	if err != nil {
		t.Fatalf("NewDelegationClient: %v", err)
	}
	res, err := client.Invoke(context.Background(), agent.URL, "user-token", NewTextMessage("hi"))
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if res.Message.Role != RoleAgent || res.Message.MessageID != "resp-03" || res.Message.Parts[0].Text != "handled-03" {
		t.Errorf("decoded message: got %+v", res.Message)
	}
}

// A 1.0 agent may answer SendMessage with a task; it surfaces on Result.Task rather
// than being reported as an empty message.
func TestDelegationClient_Invoke_TaskResponse(t *testing.T) {
	zone := newFakeZone(t)
	agent := newFakeAgent(t)
	agent.result = map[string]any{
		"task": map[string]any{
			"id":        "task-1",
			"contextId": "ctx-1",
			"status": map[string]any{
				"state":   "TASK_STATE_COMPLETED",
				"message": map[string]any{"messageId": "resp-2", "role": "ROLE_AGENT", "parts": []map[string]any{{"text": "done"}}},
			},
			"artifacts": []any{},
			"history":   []any{},
		},
	}

	client, err := NewDelegationClient(zone.URL, "agent-client", "agent-secret")
	if err != nil {
		t.Fatalf("NewDelegationClient: %v", err)
	}
	res, err := client.Invoke(context.Background(), agent.URL, "user-token", NewTextMessage("hi"))
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if res.Task == nil || res.Task.ID != "task-1" || res.Task.Status.State != "TASK_STATE_COMPLETED" {
		t.Fatalf("task: got %+v", res.Task)
	}
	if res.Task.Status.Message == nil || res.Task.Status.Message.Parts[0].Text != "done" {
		t.Errorf("task status message: got %+v", res.Task.Status.Message)
	}
	if res.Message.MessageID != "" {
		t.Errorf("message: got %+v, want zero value alongside a task", res.Message)
	}
}

// Spec row 12: a same-origin endpoint is invoked.
// Spec row 13: a different host is refused before exchange or invocation.
// Spec row 14: an explicitly trusted origin is invoked.
// Spec row 15: different ports and schemes are refused; explicit default ports match.
// Spec row 15a: an untrusted 0.3 card URL is refused.
// Spec row 15b: host and scheme are matched case-insensitively.
func TestDelegationClient_EndpointOrigin(t *testing.T) {
	const targetURL = "https://agent.example"
	for _, tc := range []struct {
		name, endpoint, refusal string
		trusted                 []string
		legacy                  bool
		target                  string
	}{
		{name: "same origin", endpoint: targetURL + "/rpc"},
		{name: "different host", endpoint: "https://other.example/rpc", refusal: "https://other.example:443"},
		{name: "trusted origin", endpoint: "https://gateway.example/rpc", trusted: []string{"HTTPS://GATEWAY.example:443/"}},
		{name: "different port", endpoint: "https://agent.example:8443/rpc", refusal: "https://agent.example:8443"},
		{name: "different scheme", endpoint: "http://agent.example/rpc", refusal: "http://agent.example:80"},
		{name: "explicit default port", endpoint: "https://agent.example:443/rpc"},
		{name: "legacy card", endpoint: "https://other.example/rpc", refusal: "https://other.example:443", legacy: true},
		{name: "mixed case", endpoint: "HTTPS://Agent.Example/rpc"},
		{name: "equivalent IPv6 spellings", target: "https://[2001:db8::1]", endpoint: "https://[2001:0DB8:0:0:0:0:0:1]/rpc"},
		{name: "equivalent scoped IPv6 spellings", target: "https://[fe80::1%25Eth0]", endpoint: "https://[FE80:0:0:0:0:0:0:1%25Eth0]/rpc"},
		{name: "case-sensitive IPv6 zone", target: "https://[fe80::1%25Eth0]", endpoint: "https://[fe80::1%25eth0]/rpc", refusal: "https://[fe80::1%eth0]:443"},
		{name: "non-ASCII host", target: "https://billing.example", endpoint: "https://bİlling.example/rpc", refusal: "invalid invocation endpoint"},
		{name: "escaped non-ASCII host", target: "https://billing.example", endpoint: "https://b%C4%B0lling.example/rpc", refusal: "invalid invocation endpoint"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			target := tc.target
			if target == "" {
				target = targetURL
			}
			zone := newFakeZone(t)
			card := AgentCard{Name: "Target"}
			opts := []DelegationOption{WithTrustedEndpointOrigins(tc.trusted...)}
			if tc.legacy {
				card.URL = tc.endpoint
				opts = append(opts, WithProtocolVersion(ProtocolVersion03))
			} else {
				card.SupportedInterfaces = []AgentInterface{{URL: tc.endpoint, ProtocolBinding: "JSONRPC", ProtocolVersion: ProtocolVersion10}}
			}
			var posted []string
			transport := originTestTransport(func(req *http.Request) (*http.Response, error) {
				rec := httptest.NewRecorder()
				switch req.URL.Path {
				case agentCardPath:
					_ = json.NewEncoder(rec).Encode(card)
				case "/rpc":
					posted = append(posted, req.URL.String())
					if req.Header.Get("Authorization") != "Bearer exchanged-token" {
						t.Error("invocation did not receive the exchanged token")
					}
					_, _ = io.WriteString(rec, `{"result":{"message":{"role":"ROLE_AGENT","parts":[{"text":"ok"}]}}}`)
				default:
					return http.DefaultTransport.RoundTrip(req)
				}
				return rec.Result(), nil
			})
			client, err := NewDelegationClient(zone.URL, "agent-client", "agent-secret",
				append(opts, WithHTTPClient(&http.Client{Transport: transport}))...)
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.Invoke(context.Background(), target, "user-token", NewTextMessage("hi"))
			if tc.refusal != "" {
				var configErr *ConfigurationError
				if !errors.As(err, &configErr) || configErr.Retryable() ||
					!strings.Contains(err.Error(), tc.refusal) || !strings.Contains(err.Error(), target) {
					t.Fatalf("want non-retryable origin refusal, got %v", err)
				}
				if zone.exchangeCount() != 0 || len(posted) != 0 {
					t.Fatal("refused endpoint caused a token exchange or invocation")
				}
				return
			}
			if err != nil || zone.exchangeCount() != 1 || len(posted) != 1 || !strings.EqualFold(posted[0], tc.endpoint) {
				t.Fatalf("want successful exchange and invocation of %q, got %v and %v", tc.endpoint, err, posted)
			}
		})
	}
}

type originTestTransport func(*http.Request) (*http.Response, error)

func (f originTestTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

// A 1.0 card's JSONRPC interface is the endpoint, preferring the one matching the
// client's protocol version.
func TestDelegationClient_JSONRPCEndpoint(t *testing.T) {
	cases := []struct {
		name    string
		version string
		card    AgentCard
		want    string
	}{
		{
			name:    "1.0 card, matching interface",
			version: ProtocolVersion10,
			card: AgentCard{SupportedInterfaces: []AgentInterface{
				{URL: "https://t/grpc", ProtocolBinding: "GRPC", ProtocolVersion: "1.0"},
				{URL: "https://t/rpc03", ProtocolBinding: "JSONRPC", ProtocolVersion: "0.3"},
				{URL: "https://t/rpc10", ProtocolBinding: "JSONRPC", ProtocolVersion: "1.0"},
			}},
			want: "https://t/rpc10",
		},
		{
			name:    "1.0 card, 0.3 client picks the 0.3 interface",
			version: ProtocolVersion03,
			card: AgentCard{SupportedInterfaces: []AgentInterface{
				{URL: "https://t/rpc10", ProtocolBinding: "JSONRPC", ProtocolVersion: "1.0"},
				{URL: "https://t/rpc03", ProtocolBinding: "JSONRPC", ProtocolVersion: "0.3"},
			}},
			want: "https://t/rpc03",
		},
		{
			name:    "1.0 card, no version match falls back to any JSONRPC interface",
			version: ProtocolVersion10,
			card: AgentCard{SupportedInterfaces: []AgentInterface{
				{URL: "https://t/rpc03", ProtocolBinding: "JSONRPC", ProtocolVersion: "0.3"},
			}},
			want: "https://t/rpc03",
		},
		{
			name:    "0.3 card url",
			version: ProtocolVersion10,
			card:    AgentCard{URL: "https://t/legacy"},
			want:    "https://t/legacy",
		},
		{
			name:    "no endpoint on the card",
			version: ProtocolVersion10,
			card:    AgentCard{Name: "x"},
			want:    "https://target.example.com/a2a/jsonrpc",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client, err := NewDelegationClient("https://zone.example.com", "id", "secret", WithProtocolVersion(tc.version))
			if err != nil {
				t.Fatalf("NewDelegationClient: %v", err)
			}
			if got := client.jsonRPCEndpoint("https://target.example.com/", tc.card); got != tc.want {
				t.Errorf("endpoint: got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestNewDelegationClient_RejectsInvalidTrustedEndpointOrigins(t *testing.T) {
	for _, tc := range []struct{ name, origin string }{
		{"path", "https://gateway.example/rpc"},
		{"escaped path", "https://gateway.example/%2f"},
		{"query", "https://gateway.example/?key=value"},
		{"empty query", "https://gateway.example/?"},
		{"fragment", "https://gateway.example/#part"},
		{"empty fragment", "https://gateway.example/#"},
		{"userinfo", "https://user@gateway.example"},
		{"empty userinfo", "https://@gateway.example"},
		{"non-ASCII host", "https://bİlling.example"},
		{"escaped non-ASCII host", "https://b%C4%B0lling.example"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewDelegationClient("https://zone.example.com", "id", "secret", WithTrustedEndpointOrigins(tc.origin))
			var cfgErr *ConfigurationError
			if !errors.As(err, &cfgErr) {
				t.Fatalf("error: got %v, want ConfigurationError", err)
			}
		})
	}
}

func TestNewDelegationClient_RejectsUnknownProtocolVersion(t *testing.T) {
	_, err := NewDelegationClient("https://zone.example.com", "id", "secret", WithProtocolVersion("2.0"))
	var cfgErr *ConfigurationError
	if !errors.As(err, &cfgErr) {
		t.Fatalf("error: got %v, want ConfigurationError", err)
	}
}

// Spec test 4: the exchange is rejected by the zone; the token-exchange OAuth error
// surfaces and the agent is not invoked.
func TestDelegationClient_Invoke_ExchangeRejected(t *testing.T) {
	zone := newFakeZone(t)
	zone.reject = true
	agent := newFakeAgent(t)

	client, err := NewDelegationClient(zone.URL, "agent-client", "agent-secret")
	if err != nil {
		t.Fatalf("NewDelegationClient: %v", err)
	}

	_, err = client.Invoke(context.Background(), agent.URL, "user-token", NewTextMessage("do the thing"))

	var oauthErr *oauth.OAuthError
	if !errors.As(err, &oauthErr) {
		t.Fatalf("error: got %v, want oauth.OAuthError", err)
	}
	if oauthErr.ErrorCode != "invalid_grant" {
		t.Errorf("oauth error code: got %q, want invalid_grant", oauthErr.ErrorCode)
	}
	if agent.invocationCount() != 0 {
		t.Errorf("agent invocations: got %d, want 0 (must not invoke on exchange failure)", agent.invocationCount())
	}
}

// Spec test 5: the target returns a JSON-RPC error; an invocation error surfaces.
func TestDelegationClient_Invoke_JSONRPCError(t *testing.T) {
	zone := newFakeZone(t)
	agent := newFakeAgent(t)
	agent.failCode = -32000
	agent.failMessage = "task failed"

	client, err := NewDelegationClient(zone.URL, "agent-client", "agent-secret")
	if err != nil {
		t.Fatalf("NewDelegationClient: %v", err)
	}

	_, err = client.Invoke(context.Background(), agent.URL, "user-token", NewTextMessage("do the thing"))

	var invErr *InvocationError
	if !errors.As(err, &invErr) {
		t.Fatalf("error: got %v, want InvocationError", err)
	}
	if invErr.Code != -32000 {
		t.Errorf("invocation error code: got %d, want -32000", invErr.Code)
	}
}

// Review #1: the per-call timeout bounds Invoke even when the caller supplies an
// http.Client with no Timeout, and surfaces the deadline as an InvocationError.
func TestDelegationClient_Invoke_TimesOutIndependentOfClient(t *testing.T) {
	zone := newFakeZone(t)
	agent := newFakeAgent(t)
	agent.hang = true

	client, err := NewDelegationClient(zone.URL, "agent-client", "agent-secret",
		WithHTTPClient(&http.Client{}), // no Timeout of its own
		WithInvokeTimeout(150*time.Millisecond),
	)
	if err != nil {
		t.Fatalf("NewDelegationClient: %v", err)
	}

	start := time.Now()
	_, err = client.Invoke(context.Background(), agent.URL, "user-token", NewTextMessage("hi"))
	if err == nil {
		t.Fatal("expected a timeout error")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("Invoke ignored the invoke timeout (took %s)", elapsed)
	}
	var invErr *InvocationError
	if !errors.As(err, &invErr) {
		t.Errorf("errors.As(*InvocationError): got %v", err)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("errors.Is(context.DeadlineExceeded): got %v", err)
	}
}

// Review #4: a result object present but carrying no message is an invocation error,
// not a silent empty success.
func TestDelegationClient_Invoke_EmptyResultMessage(t *testing.T) {
	zone := newFakeZone(t)
	agent := newFakeAgent(t)
	agent.emptyResult = true

	client, err := NewDelegationClient(zone.URL, "agent-client", "agent-secret")
	if err != nil {
		t.Fatalf("NewDelegationClient: %v", err)
	}

	_, err = client.Invoke(context.Background(), agent.URL, "user-token", NewTextMessage("hi"))
	var invErr *InvocationError
	if !errors.As(err, &invErr) {
		t.Fatalf("errors.As(*InvocationError): got %v", err)
	}
}

// Review #2: a caller-supplied HTTP client governs agent-card discovery too.
func TestDelegationClient_HTTPClientGovernsDiscovery(t *testing.T) {
	zone := newFakeZone(t)
	agent := newFakeAgent(t)

	rt := &recordingTransport{base: http.DefaultTransport}
	client, err := NewDelegationClient(zone.URL, "agent-client", "agent-secret",
		WithHTTPClient(&http.Client{Transport: rt}),
	)
	if err != nil {
		t.Fatalf("NewDelegationClient: %v", err)
	}

	if _, err := client.Invoke(context.Background(), agent.URL, "user-token", NewTextMessage("hi")); err != nil {
		t.Fatalf("Invoke: %v", err)
	}

	if !rt.sawPath(agentCardPath) {
		t.Errorf("agent-card discovery did not use the supplied HTTP client; paths=%v", rt.seenPaths())
	}
}

// recordingTransport records the request paths it forwards, for asserting which client
// served a given request.
type recordingTransport struct {
	base  http.RoundTripper
	mu    sync.Mutex
	paths []string
}

func (rt *recordingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	rt.mu.Lock()
	rt.paths = append(rt.paths, req.URL.Path)
	rt.mu.Unlock()
	return rt.base.RoundTrip(req)
}

func (rt *recordingTransport) sawPath(p string) bool {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	for _, x := range rt.paths {
		if x == p {
			return true
		}
	}
	return false
}

func (rt *recordingTransport) seenPaths() []string {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return append([]string(nil), rt.paths...)
}

func TestNewDelegationClient_RejectsEmpty(t *testing.T) {
	cases := []struct {
		name, issuer, clientID, clientSecret string
	}{
		{name: "empty issuer", issuer: "", clientID: "id", clientSecret: "secret"},
		{name: "empty client_id", issuer: "https://zone.example.com", clientID: "", clientSecret: "secret"},
		{name: "empty client_secret", issuer: "https://zone.example.com", clientID: "id", clientSecret: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewDelegationClient(tc.issuer, tc.clientID, tc.clientSecret)
			var cfgErr *ConfigurationError
			if !errors.As(err, &cfgErr) {
				t.Fatalf("error: got %v, want ConfigurationError", err)
			}
		})
	}
}

func TestDelegationClient_Invoke_RejectsEmptySubjectToken(t *testing.T) {
	client, err := NewDelegationClient("https://zone.example.com", "id", "secret")
	if err != nil {
		t.Fatalf("NewDelegationClient: %v", err)
	}
	_, err = client.Invoke(context.Background(), "https://agent.example.com", "", NewTextMessage("hi"))
	var cfgErr *ConfigurationError
	if !errors.As(err, &cfgErr) {
		t.Fatalf("error: got %v, want ConfigurationError", err)
	}
}
