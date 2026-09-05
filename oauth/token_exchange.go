package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// TokenExchangeRequest represents an RFC 8693 token exchange request.
type TokenExchangeRequest struct {
	GrantType           string
	Resource            string
	Audience            string
	Scope               string
	RequestedTokenType  string
	SubjectToken        string
	SubjectTokenType    string
	ActorToken          string
	ActorTokenType      string
	ClientAssertion     string
	ClientAssertionType string
	// ClientID names the application credential the client authenticates as,
	// sent as the client_id form parameter. Used with assertion-based
	// credentials that are resolved by ID rather than by the assertion's
	// subject.
	ClientID string
}

// TokenResponse represents an OAuth token endpoint response.
type TokenResponse struct {
	AccessToken     string   `json:"access_token"`
	TokenType       string   `json:"token_type"`
	ExpiresIn       int      `json:"expires_in,omitempty"`
	RefreshToken    string   `json:"refresh_token,omitempty"`
	IDToken         string   `json:"id_token,omitempty"`
	Scope           []string `json:"scope,omitempty"`
	IssuedTokenType string   `json:"issued_token_type,omitempty"`
	UserID          string   `json:"user_id,omitempty"`
}

// TokenExchangeClientOption configures a TokenExchangeClient.
type TokenExchangeClientOption func(*tokenExchangeConfig)

type tokenExchangeConfig struct {
	clientID     string
	clientSecret string
	httpClient   *http.Client
	discoveryTTL time.Duration
	negativeTTL  time.Duration
}

// WithClientCredentials sets the client ID and secret for HTTP basic auth.
func WithClientCredentials(clientID, clientSecret string) TokenExchangeClientOption {
	return func(cfg *tokenExchangeConfig) {
		cfg.clientID = clientID
		cfg.clientSecret = clientSecret
	}
}

// WithTokenExchangeHTTPClient sets the HTTP client for token exchange requests.
func WithTokenExchangeHTTPClient(c *http.Client) TokenExchangeClientOption {
	return func(cfg *tokenExchangeConfig) {
		cfg.httpClient = c
	}
}

// WithTokenExchangeDiscoveryTTL sets how long a discovered token endpoint is cached. Default: 1 hour.
func WithTokenExchangeDiscoveryTTL(d time.Duration) TokenExchangeClientOption {
	return func(cfg *tokenExchangeConfig) { cfg.discoveryTTL = d }
}

// WithTokenExchangeNegativeTTL bounds how long a deterministic discovery failure (a 4xx
// other than 429, an issuer mismatch, or metadata without a token_endpoint) is remembered.
// It never exceeds the discovery TTL; a value <= 0 disables negative caching. Transient
// failures are never cached. Default: 1 minute.
func WithTokenExchangeNegativeTTL(d time.Duration) TokenExchangeClientOption {
	return func(cfg *tokenExchangeConfig) { cfg.negativeTTL = d }
}

// TokenExchangeClient performs RFC 8693 token exchange against an OAuth authorization server.
// It lazily discovers the token endpoint via OAuth metadata and caches it for the
// discovery TTL; concurrent callers share one discovery fetch.
type TokenExchangeClient struct {
	issuerURL string
	cfg       tokenExchangeConfig
	endpoint  tokenEndpointResolver
}

// NewTokenExchangeClient creates a new TokenExchangeClient for the given issuer.
func NewTokenExchangeClient(issuerURL string, opts ...TokenExchangeClientOption) *TokenExchangeClient {
	cfg := tokenExchangeConfig{
		httpClient:   http.DefaultClient,
		discoveryTTL: defaultDiscoveryTTL,
		negativeTTL:  defaultNegativeTTL,
	}
	for _, opt := range opts {
		opt(&cfg)
	}

	return &TokenExchangeClient{
		issuerURL: issuerURL,
		cfg:       cfg,
		endpoint:  newTokenEndpointResolver(issuerURL, cfg.httpClient, cfg.discoveryTTL, cfg.negativeTTL, defaultFetchTimeout),
	}
}

// TokenEndpoint returns the discovered token endpoint URL, fetching metadata when the
// cached value is missing or expired.
func (c *TokenExchangeClient) TokenEndpoint(ctx context.Context) (string, error) {
	return c.endpoint.Endpoint(ctx)
}

// ExchangeToken performs a token exchange request.
func (c *TokenExchangeClient) ExchangeToken(ctx context.Context, req TokenExchangeRequest) (*TokenResponse, error) {
	tokenEndpoint, err := c.endpoint.Endpoint(ctx)
	if err != nil {
		return nil, err
	}

	body := serializeTokenExchangeRequest(req)

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, strings.NewReader(body.Encode()))
	if err != nil {
		return nil, fmt.Errorf("creating token exchange request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if c.cfg.clientID != "" && c.cfg.clientSecret != "" {
		httpReq.SetBasicAuth(c.cfg.clientID, c.cfg.clientSecret)
	}

	resp, err := c.cfg.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("token exchange request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if oauthErr := parseOAuthErrorResponse(resp); oauthErr != nil {
			return nil, oauthErr
		}
		return nil, fmt.Errorf("token exchange failed (HTTP %d)", resp.StatusCode)
	}

	return deserializeTokenResponse(resp)
}

func serializeTokenExchangeRequest(req TokenExchangeRequest) url.Values {
	params := url.Values{}

	grantType := req.GrantType
	if grantType == "" {
		grantType = "urn:ietf:params:oauth:grant-type:token-exchange"
	}
	params.Set("grant_type", grantType)

	params.Set("subject_token", req.SubjectToken)

	subjectTokenType := req.SubjectTokenType
	if subjectTokenType == "" {
		subjectTokenType = "urn:ietf:params:oauth:token-type:access_token"
	}
	params.Set("subject_token_type", subjectTokenType)

	if req.Resource != "" {
		params.Set("resource", req.Resource)
	}
	if req.Audience != "" {
		params.Set("audience", req.Audience)
	}
	if req.Scope != "" {
		params.Set("scope", req.Scope)
	}
	if req.RequestedTokenType != "" {
		params.Set("requested_token_type", req.RequestedTokenType)
	}
	if req.ActorToken != "" {
		params.Set("actor_token", req.ActorToken)
	}
	if req.ActorTokenType != "" {
		params.Set("actor_token_type", req.ActorTokenType)
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

func deserializeTokenResponse(resp *http.Response) (*TokenResponse, error) {
	var raw map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, fmt.Errorf("decoding token response: %w", err)
	}

	accessToken, _ := raw["access_token"].(string)
	if accessToken == "" {
		return nil, fmt.Errorf("token exchange response missing access_token")
	}

	tokenType, _ := raw["token_type"].(string)
	if tokenType == "" {
		tokenType = "Bearer"
	}

	result := &TokenResponse{
		AccessToken: accessToken,
		TokenType:   tokenType,
	}

	if v, ok := raw["expires_in"].(float64); ok {
		result.ExpiresIn = int(v)
	}
	if v, ok := raw["refresh_token"].(string); ok {
		result.RefreshToken = v
	}
	if v, ok := raw["id_token"].(string); ok {
		result.IDToken = v
	}
	if v, ok := raw["issued_token_type"].(string); ok {
		result.IssuedTokenType = v
	}
	if v, ok := raw["scope"].(string); ok {
		result.Scope = strings.Fields(v)
	}
	if v, ok := raw["user_id"].(string); ok {
		result.UserID = string(v)
	}

	return result, nil
}
