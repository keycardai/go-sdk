package oauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// AgentSocketEnv names the Unix socket of the Keycard server running alongside
// the application. `keycard run` sets it on the process it starts; in proxy
// mode it still names the per-session socket and the session server forwards
// to the agent daemon, so a caller needs no other discovery.
const AgentSocketEnv = "KEYCARD_SOCKET"

const (
	// agentIssueJWTProcedure is the Connect unary procedure that mints a token.
	//
	// Spoken as plain HTTP rather than through the generated client. Those stubs
	// live in github.com/keycardai/cli, which already depends on this module, so
	// importing them would close a module cycle — and they are published nowhere
	// else. Connect's unary JSON encoding is a stable wire contract that needs
	// only net/http, which is what makes this implementable here at all.
	agentIssueJWTProcedure = "/keycard.agent.v1.AgentService/IssueJWT"

	// agentExpiryLeeway is how far before expiry a cached token is discarded.
	// Sized for the round trip the caller is about to make, not for clock skew:
	// the token comes from a local socket, so re-minting is cheap and handing
	// out one that dies mid-request is the expensive outcome.
	agentExpiryLeeway = 30 * time.Second
)

// ResourceTokenSource supplies an access token for a named third-party
// resource, obtained without the caller holding a client secret.
//
// This is the client-side counterpart to [AccessContext], which holds tokens
// per resource but is populated server-side by a resource provider. An
// application that needs to *call* a resource rather than serve one has no
// other way to obtain a credential for it.
//
// resource is an RFC 8707 resource indicator: the absolute URI of the service
// the token is for. It is passed through unchanged, because the authorization
// server resolves it and any normalization applied here would be a second,
// disagreeing opinion about what the caller asked for.
type ResourceTokenSource interface {
	ResourceToken(ctx context.Context, resource string, scopes ...string) (*TokenResponse, error)
}

// AgentError is a refusal from the local Keycard server.
//
// Code is the Connect error code, which is the whole reason this type exists:
// the reasons differ in what a caller should do about them, and collapsing them
// into one opaque failure throws that away. Use the Is* predicates rather than
// comparing strings.
type AgentError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *AgentError) Error() string {
	return "keycard agent: " + e.Code + ": " + e.Message
}

func (*AgentError) keycardError() {}

// The Connect error codes the local Keycard server answers with, in the
// snake_case spelling Connect puts on the wire.
//
// Declared rather than inlined because they are a wire contract with a server
// released separately from this module: the strings are matched, not derived,
// so a spelling that drifts turns every predicate below silently false. The
// Is* helpers are the intended way to read them; they are exported so a caller
// can branch on a code that has no helper yet.
const (
	AgentCodeDeclined              = "permission_denied"
	AgentCodeRateLimited           = "resource_exhausted"
	AgentCodePrompterUnavailable   = "failed_precondition"
	AgentCodeAuthorizationRequired = "unauthenticated"
)

// IsDeclined reports whether the request was refused by the human at the
// approval prompt, or the prompt expired. Retrying without a change in what is
// being asked for will be refused again.
func IsDeclined(err error) bool { return agentCode(err) == AgentCodeDeclined }

// IsRateLimited reports whether the local server is bounding how often it will
// interrupt the developer. Back off; the budget refills.
func IsRateLimited(err error) bool { return agentCode(err) == AgentCodeRateLimited }

// IsPrompterUnavailable reports whether the host has no way to ask a human.
// This is the headless case: it will not resolve by retrying, and an
// application that has another credential should fall back to it.
func IsPrompterUnavailable(err error) bool { return agentCode(err) == AgentCodePrompterUnavailable }

// IsAuthorizationRequired reports whether the resource needs a one-time
// interactive grant the server will not initiate on its own. The remedy is
// `keycard auth resource <uri>`, run by the developer.
func IsAuthorizationRequired(err error) bool { return agentCode(err) == AgentCodeAuthorizationRequired }

func agentCode(err error) string {
	var e *AgentError
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

// AgentTokenSource obtains resource tokens from the Keycard server on the local
// machine, which brokers them using the developer's own session. The
// application holds no client credentials of its own.
//
// Issuance is gated by a human approval on first use of a given resource and
// scope set, so the first call may block for as long as it takes someone to
// answer. Approvals are remembered by the server for its lifetime, not by this
// type.
type AgentTokenSource struct {
	socket     string
	workload   string
	org, zone  string
	httpClient *http.Client

	mu     sync.Mutex
	cached map[string]cachedResourceToken
}

type cachedResourceToken struct {
	token   *TokenResponse
	expires time.Time
}

// AgentTokenSourceOption configures an AgentTokenSource.
type AgentTokenSourceOption func(*AgentTokenSource)

// WithAgentSocket overrides the socket path, which otherwise comes from
// KEYCARD_SOCKET.
func WithAgentSocket(path string) AgentTokenSourceOption {
	return func(a *AgentTokenSource) { a.socket = path }
}

// WithAgentWorkload sets the name shown to the human in the approval prompt.
//
// It is self-declared and unauthenticated — the server renders it as such and
// never treats it as an authorization input — so choose something that helps
// the developer recognise this application, not something that claims trust.
func WithAgentWorkload(name string) AgentTokenSourceOption {
	return func(a *AgentTokenSource) { a.workload = name }
}

// WithAgentTenant selects the organization and zone. Required when the request
// reaches the multi-zone agent daemon, which resolves a session per request and
// refuses one it cannot place. The per-session server started by `keycard run`
// ignores both.
func WithAgentTenant(org, zone string) AgentTokenSourceOption {
	return func(a *AgentTokenSource) { a.org, a.zone = org, zone }
}

// WithAgentHTTPClient replaces the client used to reach the socket. The
// default dials the Unix socket; a replacement is responsible for doing so
// itself, and exists mainly for tests.
func WithAgentHTTPClient(c *http.Client) AgentTokenSourceOption {
	return func(a *AgentTokenSource) { a.httpClient = c }
}

// NewAgentTokenSource creates an AgentTokenSource. The socket is not probed at
// construction; its absence surfaces at the first call, matching the other
// sources in this package.
func NewAgentTokenSource(opts ...AgentTokenSourceOption) *AgentTokenSource {
	a := &AgentTokenSource{cached: make(map[string]cachedResourceToken)}
	for _, opt := range opts {
		opt(a)
	}
	if a.httpClient == nil {
		a.httpClient = &http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					socket, err := a.socketPath()
					if err != nil {
						return nil, err
					}
					var d net.Dialer
					return d.DialContext(ctx, "unix", socket)
				},
			},
		}
	}
	return a
}

func (a *AgentTokenSource) socketPath() (string, error) {
	if a.socket != "" {
		return a.socket, nil
	}
	if s := os.Getenv(AgentSocketEnv); s != "" {
		return s, nil
	}
	return "", &ConfigurationError{
		Message: AgentSocketEnv + " is not set; run this application under `keycard run`",
	}
}

// ResourceToken implements [ResourceTokenSource].
//
// A cached token is reused until it is within agentExpiryLeeway of expiry.
// Caching here rather than in the caller is deliberate: without it every
// outbound request becomes an authorization server round trip, and the server
// remembers the *approval*, not the token.
func (a *AgentTokenSource) ResourceToken(ctx context.Context, resource string, scopes ...string) (*TokenResponse, error) {
	if resource == "" {
		return nil, &ConfigurationError{Message: "resource is required"}
	}

	key := resource + "\x00" + strings.Join(scopes, " ")
	if tok := a.lookup(key); tok != nil {
		return tok, nil
	}

	tok, expires, err := a.mint(ctx, resource, scopes)
	if err != nil {
		return nil, err
	}

	a.mu.Lock()
	a.cached[key] = cachedResourceToken{token: tok, expires: expires}
	a.mu.Unlock()
	return tok, nil
}

func (a *AgentTokenSource) lookup(key string) *TokenResponse {
	a.mu.Lock()
	defer a.mu.Unlock()
	entry, ok := a.cached[key]
	if !ok || time.Now().Add(agentExpiryLeeway).After(entry.expires) {
		return nil
	}
	return entry.token
}

func (a *AgentTokenSource) mint(ctx context.Context, resource string, scopes []string) (*TokenResponse, time.Time, error) {
	if _, err := a.socketPath(); err != nil {
		return nil, time.Time{}, err
	}

	body, err := json.Marshal(map[string]any{
		"resource": resource,
		"scopes":   scopes,
		"workload": a.workload,
	})
	if err != nil {
		return nil, time.Time{}, err
	}

	// The host is ignored by the dialer, but net/http requires one.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"http://keycard-agent"+agentIssueJWTProcedure, bytes.NewReader(body))
	if err != nil {
		return nil, time.Time{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Connect-Protocol-Version", "1")
	if a.org != "" {
		req.Header.Set("Keycard-Org", a.org)
	}
	if a.zone != "" {
		req.Header.Set("Keycard-Zone", a.zone)
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("keycard agent: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		agentErr := &AgentError{}
		if err := json.NewDecoder(resp.Body).Decode(agentErr); err != nil || agentErr.Code == "" {
			return nil, time.Time{}, &HTTPError{
				Message: fmt.Sprintf("keycard agent returned HTTP %d", resp.StatusCode),
				Status:  resp.StatusCode,
			}
		}
		return nil, time.Time{}, agentErr
	}

	// Connect renders protobuf field names in lowerCamelCase and a Timestamp as
	// RFC 3339.
	var out struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expiresAt"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, time.Time{}, fmt.Errorf("keycard agent: decoding response: %w", err)
	}
	if out.Token == "" {
		return nil, time.Time{}, errors.New("keycard agent: empty token in response")
	}

	// ExpiresIn rather than the absolute time, to match every other token this
	// package returns. The absolute value is kept for the cache, where a
	// relative one would drift.
	expiresIn := 0
	if !out.ExpiresAt.IsZero() {
		if d := time.Until(out.ExpiresAt); d > 0 {
			expiresIn = int(d.Seconds())
		}
	}
	return &TokenResponse{
		AccessToken: out.Token,
		TokenType:   "Bearer",
		ExpiresIn:   expiresIn,
		Scope:       scopes,
	}, out.ExpiresAt, nil
}
