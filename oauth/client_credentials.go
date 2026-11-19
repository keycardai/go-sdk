package oauth

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/keycardai/go-sdk/internal/printed"
)

// ClientCredentialsRequest represents an RFC 6749 Section 4.4 client credentials request.
type ClientCredentialsRequest struct {
	Resource            string
	Scope               string
	ClientAssertion     string
	ClientAssertionType string
	// ClientID names the application credential the client authenticates as,
	// sent as the client_id form parameter beside ClientAssertion. It is never
	// sent when the client uses HTTP Basic.
	ClientID string
}

// ClientCredentialsClientOption configures a ClientCredentialsClient.
type ClientCredentialsClientOption func(*clientCredentialsConfig)

type clientCredentialsConfig struct {
	clientID       string
	clientSecret   string
	httpClient     *http.Client
	discoveryTTL   time.Duration
	negativeTTL    time.Duration
	requestTimeout time.Duration
}

// WithCCBasicAuth sets the client ID and secret for HTTP basic auth.
func WithCCBasicAuth(clientID, clientSecret string) ClientCredentialsClientOption {
	return func(cfg *clientCredentialsConfig) {
		cfg.clientID = clientID
		cfg.clientSecret = clientSecret
	}
}

// WithCCHTTPClient sets the HTTP client for client credentials requests.
func WithCCHTTPClient(c *http.Client) ClientCredentialsClientOption {
	return func(cfg *clientCredentialsConfig) {
		cfg.httpClient = c
	}
}

// WithCCRequestTimeout bounds each request this call makes to the authorization server when the
// caller's context has no deadline of its own. Default: 10 seconds.
func WithCCRequestTimeout(d time.Duration) ClientCredentialsClientOption {
	return func(cfg *clientCredentialsConfig) { cfg.requestTimeout = d }
}

// WithCCDiscoveryTTL sets how long a discovered token endpoint is cached. Default: 1 hour.
func WithCCDiscoveryTTL(d time.Duration) ClientCredentialsClientOption {
	return func(cfg *clientCredentialsConfig) { cfg.discoveryTTL = d }
}

// WithCCNegativeTTL bounds how long a deterministic discovery failure (a 4xx other than
// 429, an issuer mismatch, or metadata without a token_endpoint) is remembered. It never
// exceeds the discovery TTL; a value <= 0 disables negative caching. Transient failures
// are never cached. Default: 1 minute.
func WithCCNegativeTTL(d time.Duration) ClientCredentialsClientOption {
	return func(cfg *clientCredentialsConfig) { cfg.negativeTTL = d }
}

// ClientCredentialsClient performs RFC 6749 Section 4.4 client credentials grants
// against an OAuth authorization server. It lazily discovers the token endpoint via
// OAuth metadata and caches it for the discovery TTL; concurrent callers share one
// discovery fetch.
//
// String, GoString, and LogValue show the issuer and client ID only.
type ClientCredentialsClient struct {
	issuerURL string
	cfg       clientCredentialsConfig
	endpoint  tokenEndpointResolver
}

func (c *ClientCredentialsClient) printed() printed.Struct {
	return printed.Struct{Type: "oauth.ClientCredentialsClient", Fields: []printed.Field{
		{Name: "Issuer", Key: "issuer", Value: c.issuerURL},
		{Name: "ClientID", Key: "client_id", Value: c.cfg.clientID},
	}}
}

// String implements [fmt.Stringer].
func (c *ClientCredentialsClient) String() string { return c.printed().String() }

// GoString implements [fmt.GoStringer].
func (c *ClientCredentialsClient) GoString() string { return c.printed().GoString() }

// LogValue implements [slog.LogValuer].
func (c *ClientCredentialsClient) LogValue() slog.Value {
	if c == nil {
		return slog.AnyValue(nil)
	}
	return c.printed().LogValue()
}

// NewClientCredentialsClient creates a new ClientCredentialsClient for the given issuer.
func NewClientCredentialsClient(issuerURL string, opts ...ClientCredentialsClientOption) *ClientCredentialsClient {
	cfg := clientCredentialsConfig{
		httpClient:     http.DefaultClient,
		discoveryTTL:   defaultDiscoveryTTL,
		negativeTTL:    defaultNegativeTTL,
		requestTimeout: defaultFetchTimeout,
	}
	for _, opt := range opts {
		opt(&cfg)
	}

	return &ClientCredentialsClient{
		issuerURL: issuerURL,
		cfg:       cfg,
		endpoint:  newTokenEndpointResolver(issuerURL, cfg.httpClient, cfg.discoveryTTL, cfg.negativeTTL, cfg.requestTimeout),
	}
}

// TokenEndpoint returns the discovered token endpoint URL, fetching metadata when the
// cached value is missing or expired.
func (c *ClientCredentialsClient) TokenEndpoint(ctx context.Context) (string, error) {
	return c.endpoint.Endpoint(ctx)
}

// RequestToken performs a client credentials grant request.
func (c *ClientCredentialsClient) RequestToken(ctx context.Context, req ClientCredentialsRequest) (*TokenResponse, error) {
	tokenEndpoint, err := c.endpoint.Endpoint(ctx)
	if err != nil {
		return nil, err
	}

	basicAuth := c.cfg.clientID != "" && c.cfg.clientSecret != ""
	if basicAuth {
		req.ClientID = ""
	}
	body := serializeClientCredentialsRequest(req)

	ctx, cancel := withDefaultTimeout(ctx, c.cfg.requestTimeout)
	defer cancel()

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, strings.NewReader(body.Encode()))
	if err != nil {
		return nil, fmt.Errorf("creating client credentials request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if basicAuth {
		setBasicAuth(httpReq.Header, c.cfg.clientID, c.cfg.clientSecret)
	}

	resp, err := c.cfg.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("client credentials request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if oauthErr := parseOAuthErrorResponse(resp); oauthErr != nil {
			return nil, oauthErr
		}
		return nil, fmt.Errorf("client credentials request failed (HTTP %d)", resp.StatusCode)
	}

	return deserializeTokenResponse(resp)
}

func serializeClientCredentialsRequest(req ClientCredentialsRequest) url.Values {
	params := url.Values{}
	params.Set("grant_type", "client_credentials")

	if req.Resource != "" {
		params.Set("resource", req.Resource)
	}
	if req.Scope != "" {
		params.Set("scope", req.Scope)
	}
	if req.ClientAssertion != "" {
		params.Set("client_assertion", req.ClientAssertion)
	}
	if req.ClientAssertionType != "" {
		params.Set("client_assertion_type", req.ClientAssertionType)
	}
	if req.ClientID != "" {
		params.Set("client_id", req.ClientID)
	}

	return params
}
