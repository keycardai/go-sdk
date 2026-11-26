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
	// ClientID names the application credential the client authenticates as,
	// sent as the client_id form parameter beside ClientAssertion. It is never
	// sent when the client uses HTTP Basic. With a client configured through
	// [WithCCCredential], set it only beside ClientAssertion; the credential
	// supplies its own client_id otherwise.
	ClientID string
}

// ClientCredentialsClientOption configures a ClientCredentialsClient.
type ClientCredentialsClientOption func(*clientCredentialsConfig)

type clientCredentialsConfig struct {
	clientID       string
	clientSecret   string
	basicAuthSet   bool
	credential     ApplicationCredential
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
		cfg.basicAuthSet = true
	}
}

// WithCCCredential authenticates token requests with the credential's client
// authentication unless the request supplies its own client assertion.
// The credential must implement [ClientAuthenticator].
func WithCCCredential(credential ApplicationCredential) ClientCredentialsClientOption {
	return func(cfg *clientCredentialsConfig) { cfg.credential = credential }
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
type ClientCredentialsClient struct {
	issuerURL string
	cfg       clientCredentialsConfig
	endpoint  tokenEndpointResolver
	configErr error
}

// NewClientCredentialsClient creates a new ClientCredentialsClient for the given issuer.
// Combining [WithCCCredential] and [WithCCBasicAuth] causes RequestToken to
// return a ConfigurationError before making any HTTP request.
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

	var configErr error
	if cfg.credential != nil && cfg.basicAuthSet {
		configErr = &ConfigurationError{Message: "use either WithCCCredential or WithCCBasicAuth, not both"}
	}
	return &ClientCredentialsClient{
		issuerURL: issuerURL,
		cfg:       cfg,
		endpoint:  newTokenEndpointResolver(issuerURL, cfg.httpClient, cfg.discoveryTTL, cfg.negativeTTL, cfg.requestTimeout),
		configErr: configErr,
	}
}

// TokenEndpoint returns the discovered token endpoint URL, fetching metadata when the
// cached value is missing or expired.
func (c *ClientCredentialsClient) TokenEndpoint(ctx context.Context) (string, error) {
	return c.endpoint.Endpoint(ctx)
}

// RequestToken performs a client credentials grant request.
func (c *ClientCredentialsClient) RequestToken(ctx context.Context, req ClientCredentialsRequest) (*TokenResponse, error) {
	if c.configErr != nil {
		return nil, c.configErr
	}
	var authenticator ClientAuthenticator
	if req.ClientAssertion == "" && c.cfg.credential != nil {
		if req.ClientID != "" {
			return nil, &ConfigurationError{Message: "ClientID without ClientAssertion conflicts with WithCCCredential; the credential supplies its own client_id"}
		}
		var ok bool
		authenticator, ok = c.cfg.credential.(ClientAuthenticator)
		if !ok {
			return nil, &ConfigurationError{Message: fmt.Sprintf("credential %T does not provide client authentication", c.cfg.credential)}
		}
	}
	tokenEndpoint, err := c.endpoint.Endpoint(ctx)
	if err != nil {
		return nil, err
	}

	basicAuth := req.ClientAssertion == "" && c.cfg.clientID != "" && c.cfg.clientSecret != ""
	if basicAuth || authenticator != nil {
		req.ClientID = ""
	}
	if authenticator != nil {
		req.ClientAssertionType = ""
	}
	body := serializeClientCredentialsRequest(req)

	ctx, cancel := withDefaultTimeout(ctx, c.cfg.requestTimeout)
	defer cancel()

	header := http.Header{"Content-Type": {"application/x-www-form-urlencoded"}}
	if authenticator != nil {
		if err := addClientAuthentication(ctx, authenticator, c.issuerURL, tokenEndpoint, header, body); err != nil {
			return nil, err
		}
	}
	if basicAuth {
		setBasicAuth(header, c.cfg.clientID, c.cfg.clientSecret)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, strings.NewReader(body.Encode()))
	if err != nil {
		return nil, fmt.Errorf("creating client credentials request: %w", err)
	}
	httpReq.Header = header

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
