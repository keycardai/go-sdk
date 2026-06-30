// Package a2a implements Keycard's agent-to-agent (A2A) delegation contract: one
// agent service calling another on the user's behalf, carrying the user's identity
// through every hop.
//
// A delegated call is three steps. It discovers the target agent's card from
// <target>/.well-known/agent-card.json, performs an RFC 8693 token exchange (the
// inbound user token is the subject and the calling agent's own credential
// authenticates the exchange) to obtain a token scoped to the target, and invokes the
// target's A2A JSON-RPC endpoint with that token as the bearer credential. The user
// remains the subject at each hop; the authorization server records the calling agent
// in the token's act chain for audit.
//
// This package implements the delegation contract only. Hosting an agent inside a
// specific agent framework (its server, request-handler, and agent-card wiring) is
// framework-specific glue and out of scope.
package a2a

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/keycardai/credentials-go/oauth"
)

const (
	defaultProtocolVersion = "0.3"
	defaultInvokeTimeout   = 30 * time.Second
	defaultJSONRPCPath     = "/a2a/jsonrpc"
	jsonRPCMethodSend      = "message/send"
	subjectTokenTypeAccess = "urn:ietf:params:oauth:token-type:access_token"
)

// DelegationClient delegates calls from one agent to another, carrying the user's
// identity through an RFC 8693 token exchange. Construct it once per calling agent.
type DelegationClient struct {
	exchange        *oauth.TokenExchangeClient
	discovery       *ServiceDiscovery
	httpClient      *http.Client
	protocolVersion string
	invokeTimeout   time.Duration
}

// DelegationOption configures a DelegationClient.
type DelegationOption func(*delegationConfig)

type delegationConfig struct {
	httpClient      *http.Client
	discovery       *ServiceDiscovery
	protocolVersion string
	invokeTimeout   time.Duration
}

// WithHTTPClient sets the HTTP client used for the token exchange and the agent
// invocation. Unless a ServiceDiscovery is supplied via WithServiceDiscovery, this
// client also governs agent-card discovery. The default client has a 30 second timeout.
func WithHTTPClient(c *http.Client) DelegationOption {
	return func(cfg *delegationConfig) { cfg.httpClient = c }
}

// WithInvokeTimeout bounds the total time for a single Invoke call (discovery, token
// exchange, and invocation combined). It is enforced via the context, independent of any
// HTTP client timeout, so it still applies when a caller supplies an http.Client with no
// Timeout of its own. Defaults to 30 seconds; a value <= 0 disables it.
func WithInvokeTimeout(d time.Duration) DelegationOption {
	return func(cfg *delegationConfig) { cfg.invokeTimeout = d }
}

// WithServiceDiscovery supplies a shared ServiceDiscovery (for a shared agent-card
// cache). When unset, the client uses its own ServiceDiscovery with default settings.
func WithServiceDiscovery(d *ServiceDiscovery) DelegationOption {
	return func(cfg *delegationConfig) { cfg.discovery = d }
}

// WithProtocolVersion sets the A2A protocol version advertised on invocation requests
// via the x-a2a-protocol-version header. Defaults to "0.3".
func WithProtocolVersion(v string) DelegationOption {
	return func(cfg *delegationConfig) { cfg.protocolVersion = v }
}

// NewDelegationClient builds a delegation client for one calling agent. issuer is the
// Keycard zone authorization server where each token exchange is performed; clientID
// and clientSecret are the calling agent's own credential, used to authenticate the
// exchange and to identify the agent in the act chain. It returns a ConfigurationError
// if the issuer, client ID, or client secret is empty.
func NewDelegationClient(issuer, clientID, clientSecret string, opts ...DelegationOption) (*DelegationClient, error) {
	if strings.TrimSpace(issuer) == "" {
		return nil, &ConfigurationError{Message: "issuer must not be empty"}
	}
	if strings.TrimSpace(clientID) == "" || strings.TrimSpace(clientSecret) == "" {
		return nil, &ConfigurationError{Message: "client_id and client_secret must not be empty"}
	}

	cfg := delegationConfig{
		protocolVersion: defaultProtocolVersion,
		invokeTimeout:   defaultInvokeTimeout,
	}
	for _, opt := range opts {
		opt(&cfg)
	}

	httpClient := cfg.httpClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: defaultInvokeTimeout}
	}

	discovery := cfg.discovery
	if discovery == nil {
		var dopts []DiscoveryOption
		if cfg.httpClient != nil {
			// A caller-supplied client governs discovery too (e.g. a shared proxy).
			dopts = append(dopts, WithDiscoveryHTTPClient(cfg.httpClient))
		}
		discovery = NewServiceDiscovery(dopts...)
	}

	exchange := oauth.NewTokenExchangeClient(issuer,
		oauth.WithClientCredentials(clientID, clientSecret),
		oauth.WithTokenExchangeHTTPClient(httpClient),
	)

	return &DelegationClient{
		exchange:        exchange,
		discovery:       discovery,
		httpClient:      httpClient,
		protocolVersion: cfg.protocolVersion,
		invokeTimeout:   cfg.invokeTimeout,
	}, nil
}

// Invoke delegates a call to the target agent on the user's behalf. It discovers the
// target's card, exchanges subjectToken (the inbound user token) for a token scoped to
// the target, and invokes the target's JSON-RPC endpoint with that token, sending msg.
//
// A discovery, exchange, or invocation failure is returned as a *DiscoveryError, an
// OAuth error from the exchange (wrapped), or an *InvocationError respectively. On an
// exchange failure the target agent is not invoked.
func (c *DelegationClient) Invoke(ctx context.Context, target, subjectToken string, msg Message) (*Result, error) {
	if strings.TrimSpace(subjectToken) == "" {
		return nil, &ConfigurationError{Message: "subject_token must not be empty"}
	}

	if c.invokeTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.invokeTimeout)
		defer cancel()
	}

	card, err := c.discovery.GetCard(ctx, target)
	if err != nil {
		return nil, err
	}

	audience := strings.TrimRight(target, "/")
	tokenResp, err := c.exchange.ExchangeToken(ctx, oauth.TokenExchangeRequest{
		SubjectToken:     subjectToken,
		SubjectTokenType: subjectTokenTypeAccess,
		Resource:         audience,
		Audience:         audience,
	})
	if err != nil {
		return nil, fmt.Errorf("a2a delegation: token exchange for %s: %w", audience, err)
	}

	respMsg, err := c.invoke(ctx, c.jsonRPCEndpoint(target, card), tokenResp.AccessToken, msg)
	if err != nil {
		return nil, err
	}

	return &Result{Message: respMsg, AgentCard: card}, nil
}

// jsonRPCEndpoint resolves the target's JSON-RPC endpoint: the card's url when set,
// otherwise the target base URL with the conventional /a2a/jsonrpc path.
func (c *DelegationClient) jsonRPCEndpoint(target string, card AgentCard) string {
	if strings.TrimSpace(card.URL) != "" {
		return card.URL
	}
	return strings.TrimRight(target, "/") + defaultJSONRPCPath
}

type jsonRPCRequest struct {
	JSONRPC string        `json:"jsonrpc"`
	ID      string        `json:"id"`
	Method  string        `json:"method"`
	Params  messageParams `json:"params"`
}

type messageParams struct {
	Message Message `json:"message"`
}

type jsonRPCResponse struct {
	Result *struct {
		Message Message `json:"message"`
	} `json:"result"`
	Error *jsonRPCError `json:"error"`
}

type jsonRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (c *DelegationClient) invoke(ctx context.Context, endpoint, bearer string, msg Message) (Message, error) {
	body, err := json.Marshal(jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      newUUID(),
		Method:  jsonRPCMethodSend,
		Params:  messageParams{Message: msg},
	})
	if err != nil {
		return Message{}, &InvocationError{Message: "encoding request", Err: err}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return Message{}, &InvocationError{Message: "building request", Err: err}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+bearer)
	if c.protocolVersion != "" {
		req.Header.Set("x-a2a-protocol-version", c.protocolVersion)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return Message{}, &InvocationError{Message: fmt.Sprintf("invoking %s", endpoint), Err: err}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return Message{}, &InvocationError{Message: fmt.Sprintf("agent %s returned HTTP %d", endpoint, resp.StatusCode)}
	}

	var rpcResp jsonRPCResponse
	if err := json.NewDecoder(resp.Body).Decode(&rpcResp); err != nil {
		return Message{}, &InvocationError{Message: "decoding response", Err: err}
	}
	if rpcResp.Error != nil {
		return Message{}, &InvocationError{Message: rpcResp.Error.Message, Code: rpcResp.Error.Code}
	}
	if rpcResp.Result == nil {
		return Message{}, &InvocationError{Message: "agent response carried neither result nor error"}
	}
	if rpcResp.Result.Message.MessageID == "" && len(rpcResp.Result.Message.Parts) == 0 {
		return Message{}, &InvocationError{Message: "agent response carried an empty result message"}
	}

	return rpcResp.Result.Message, nil
}
