package oauth

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ClientCredentialsRequest represents an RFC 6749 Section 4.4 client credentials request.
type ClientCredentialsRequest struct {
	Resource            string
	Scope               string
	ClientAssertion     string
	ClientAssertionType string
}

// ClientCredentialsClientOption configures a ClientCredentialsClient.
type ClientCredentialsClientOption func(*clientCredentialsConfig)

type clientCredentialsConfig struct {
	clientID     string
	clientSecret string
	httpClient   *http.Client
	discoveryTTL time.Duration
	negativeTTL  time.Duration
	fetchTimeout time.Duration
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

// WithCCFetchTimeout sets the timeout for the discovery fetch. Default: 10 seconds.
func WithCCFetchTimeout(d time.Duration) ClientCredentialsClientOption {
	return func(cfg *clientCredentialsConfig) { cfg.fetchTimeout = d }
}

// ClientCredentialsClient performs RFC 6749 Section 4.4 client credentials grants
// against an OAuth authorization server. It lazily discovers the token endpoint via
// OAuth metadata and caches it for the discovery TTL; concurrent callers share one
// discovery fetch.
type ClientCredentialsClient struct {
	issuerURL string
	cfg       clientCredentialsConfig
	endpoint  tokenEndpointResolver
}

// NewClientCredentialsClient creates a new ClientCredentialsClient for the given issuer.
func NewClientCredentialsClient(issuerURL string, opts ...ClientCredentialsClientOption) *ClientCredentialsClient {
	cfg := clientCredentialsConfig{
		httpClient:   http.DefaultClient,
		discoveryTTL: defaultDiscoveryTTL,
		negativeTTL:  defaultNegativeTTL,
		fetchTimeout: defaultFetchTimeout,
	}
	for _, opt := range opts {
		opt(&cfg)
	}

	return &ClientCredentialsClient{
		issuerURL: issuerURL,
		cfg:       cfg,
		endpoint:  newTokenEndpointResolver(issuerURL, cfg.httpClient, cfg.discoveryTTL, cfg.negativeTTL, cfg.fetchTimeout),
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

	body := serializeClientCredentialsRequest(req)

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, strings.NewReader(body.Encode()))
	if err != nil {
		return nil, fmt.Errorf("creating client credentials request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if c.cfg.clientID != "" && c.cfg.clientSecret != "" {
		httpReq.SetBasicAuth(c.cfg.clientID, c.cfg.clientSecret)
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

	return params
}
