package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"time"

	"github.com/keycardai/go-sdk/internal/printed"
)

// TokenExchangeRequest represents an RFC 8693 token exchange request.
//
// String, GoString, and LogValue leave out SubjectToken, ActorToken, and
// ClientAssertion.
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

func (r TokenExchangeRequest) printed() printed.Struct {
	return printed.Struct{Type: "oauth.TokenExchangeRequest", Fields: []printed.Field{
		{Name: "GrantType", Key: "grant_type", Value: r.GrantType},
		{Name: "Resource", Key: "resource", Value: r.Resource},
		{Name: "Audience", Key: "audience", Value: r.Audience},
		{Name: "Scope", Key: "scope", Value: r.Scope},
		{Name: "RequestedTokenType", Key: "requested_token_type", Value: r.RequestedTokenType},
		{Name: "SubjectTokenType", Key: "subject_token_type", Value: r.SubjectTokenType},
		{Name: "ActorTokenType", Key: "actor_token_type", Value: r.ActorTokenType},
		{Name: "ClientAssertionType", Key: "client_assertion_type", Value: r.ClientAssertionType},
		{Name: "ClientID", Key: "client_id", Value: r.ClientID},
	}}
}

// String implements [fmt.Stringer].
func (r TokenExchangeRequest) String() string { return r.printed().String() }

// GoString implements [fmt.GoStringer].
func (r TokenExchangeRequest) GoString() string { return r.printed().GoString() }

// LogValue implements [slog.LogValuer].
func (r TokenExchangeRequest) LogValue() slog.Value { return r.printed().LogValue() }

// TokenResponse represents an OAuth token endpoint response.
//
// String, GoString, and LogValue leave out AccessToken, RefreshToken, and IDToken.
// encoding/json writes them.
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

func (t TokenResponse) printed() printed.Struct {
	return printed.Struct{Type: "oauth.TokenResponse", Fields: []printed.Field{
		{Name: "TokenType", Key: "token_type", Value: t.TokenType},
		{Name: "ExpiresIn", Key: "expires_in", Value: t.ExpiresIn},
		{Name: "Scope", Key: "scope", Value: t.Scope},
		{Name: "IssuedTokenType", Key: "issued_token_type", Value: t.IssuedTokenType},
		{Name: "UserID", Key: "user_id", Value: t.UserID},
	}}
}

// String implements [fmt.Stringer].
func (t TokenResponse) String() string { return t.printed().String() }

// GoString implements [fmt.GoStringer].
func (t TokenResponse) GoString() string { return t.printed().GoString() }

// LogValue implements [slog.LogValuer].
func (t TokenResponse) LogValue() slog.Value { return t.printed().LogValue() }

// TokenExchangeClientOption configures a TokenExchangeClient.
type TokenExchangeClientOption func(*tokenExchangeConfig)

type tokenExchangeConfig struct {
	clientID       string
	clientSecret   string
	credential     ApplicationCredential
	actor          IdentityTokenSource
	httpClient     *http.Client
	discoveryTTL   time.Duration
	negativeTTL    time.Duration
	requestTimeout time.Duration
}

// WithClientCredentials sets the client ID and secret for HTTP basic auth.
func WithClientCredentials(clientID, clientSecret string) TokenExchangeClientOption {
	return func(cfg *tokenExchangeConfig) {
		cfg.clientID = clientID
		cfg.clientSecret = clientSecret
	}
}

// WithTokenExchangeCredential uses credential instead of static Basic credentials.
func WithTokenExchangeCredential(credential ApplicationCredential) TokenExchangeClientOption {
	return func(cfg *tokenExchangeConfig) {
		cfg.credential = credential
	}
}

// WithTokenExchangeActor sets the source of the actor JWT for token exchanges.
// The client fetches a token for each exchange that does not supply its own
// actor token and skips the source for impersonation. A nil source, including
// a typed nil function or pointer, disables it.
func WithTokenExchangeActor(source IdentityTokenSource) TokenExchangeClientOption {
	switch value := reflect.ValueOf(source); value.Kind() {
	case reflect.Func, reflect.Pointer:
		if value.IsNil() {
			source = nil
		}
	}
	return func(cfg *tokenExchangeConfig) { cfg.actor = source }
}

// WithTokenExchangeHTTPClient sets the HTTP client for token exchange requests.
func WithTokenExchangeHTTPClient(c *http.Client) TokenExchangeClientOption {
	return func(cfg *tokenExchangeConfig) {
		cfg.httpClient = c
	}
}

// WithTokenExchangeRequestTimeout bounds actor token lookup and each request to
// the authorization server when the caller's context has no deadline of its own.
// Default: 10 seconds.
func WithTokenExchangeRequestTimeout(d time.Duration) TokenExchangeClientOption {
	return func(cfg *tokenExchangeConfig) { cfg.requestTimeout = d }
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
//
// String, GoString, and LogValue show the issuer and client ID only.
type TokenExchangeClient struct {
	issuerURL string
	cfg       tokenExchangeConfig
	endpoint  tokenEndpointResolver
}

func (c *TokenExchangeClient) printed() printed.Struct {
	return printed.Struct{Type: "oauth.TokenExchangeClient", Fields: []printed.Field{
		{Name: "Issuer", Key: "issuer", Value: c.issuerURL},
		{Name: "ClientID", Key: "client_id", Value: c.cfg.clientID},
	}}
}

// String implements [fmt.Stringer].
func (c *TokenExchangeClient) String() string { return c.printed().String() }

// GoString implements [fmt.GoStringer].
func (c *TokenExchangeClient) GoString() string { return c.printed().GoString() }

// LogValue implements [slog.LogValuer].
func (c *TokenExchangeClient) LogValue() slog.Value {
	if c == nil {
		return slog.AnyValue(nil)
	}
	return c.printed().LogValue()
}

// NewTokenExchangeClient creates a new TokenExchangeClient for the given issuer.
func NewTokenExchangeClient(issuerURL string, opts ...TokenExchangeClientOption) *TokenExchangeClient {
	cfg := tokenExchangeConfig{
		httpClient:     http.DefaultClient,
		discoveryTTL:   defaultDiscoveryTTL,
		negativeTTL:    defaultNegativeTTL,
		requestTimeout: defaultFetchTimeout,
	}
	for _, opt := range opts {
		opt(&cfg)
	}

	return &TokenExchangeClient{
		issuerURL: issuerURL,
		cfg:       cfg,
		endpoint:  newTokenEndpointResolver(issuerURL, cfg.httpClient, cfg.discoveryTTL, cfg.negativeTTL, cfg.requestTimeout),
	}
}

// TokenEndpoint returns the discovered token endpoint URL, fetching metadata when the
// cached value is missing or expired.
func (c *TokenExchangeClient) TokenEndpoint(ctx context.Context) (string, error) {
	return c.endpoint.Endpoint(ctx)
}

// ExchangeToken performs a token exchange request. A request assertion takes
// precedence over configured HTTP Basic credentials. A request ClientID with
// HTTP Basic returns a ConfigurationError before discovery.
// A configured [WithTokenExchangeActor] source provides an actor JWT unless the
// request supplies one or uses the substitute-user token type. A source failure
// returns a WorkloadIdentityConfigurationError or WorkloadIdentityRuntimeError
// before any request to the authorization server.
func (c *TokenExchangeClient) ExchangeToken(ctx context.Context, req TokenExchangeRequest) (*TokenResponse, error) {
	auth := &ClientAuth{ClientID: c.cfg.clientID, ClientSecret: c.cfg.clientSecret}
	if c.cfg.credential != nil {
		auth = c.cfg.credential.Auth(c.issuerURL)
	}
	useBasic := req.ClientAssertion == "" && auth != nil && auth.ClientID != "" && auth.ClientSecret != ""
	if useBasic && req.ClientID != "" {
		return nil, &ConfigurationError{Message: "token exchange client_id cannot be sent with HTTP Basic"}
	}

	if c.cfg.actor != nil && req.ActorToken == "" && req.SubjectTokenType != SubstituteUserTokenType {
		actorCtx, cancel := withDefaultTimeout(ctx, c.cfg.requestTimeout)
		token, err := fetchIdentityToken(actorCtx, c.cfg.actor)
		cancel()
		if err != nil {
			return nil, err
		}
		req.ActorToken = token
		req.ActorTokenType = "urn:ietf:params:oauth:token-type:jwt"
	}

	tokenEndpoint, err := c.endpoint.Endpoint(ctx)
	if err != nil {
		return nil, err
	}

	ctx, cancel := withDefaultTimeout(ctx, c.cfg.requestTimeout)
	defer cancel()

	if credential := c.cfg.credential; credential != nil && auth == nil && req.ClientAssertion == "" {
		prepared, err := credential.PrepareTokenExchangeRequest(ctx, req.SubjectToken, req.Resource, &PrepareOptions{
			Issuer: c.issuerURL, TokenEndpoint: tokenEndpoint,
		})
		if err != nil {
			return nil, err
		}
		if prepared == nil || prepared.ClientAssertion == "" {
			return nil, &ClientSecretConfigurationError{Message: fmt.Sprintf("no client credentials configured for zone %q", c.issuerURL)}
		}
		req.ClientAssertion = prepared.ClientAssertion
		req.ClientAssertionType = prepared.ClientAssertionType
		req.ClientID = prepared.ClientID
	}

	body := serializeTokenExchangeRequest(req)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, strings.NewReader(body.Encode()))
	if err != nil {
		return nil, fmt.Errorf("creating token exchange request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if useBasic {
		setBasicAuth(httpReq.Header, auth.ClientID, auth.ClientSecret)
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
	data, err := readBoundedBody(resp.Body)
	if err != nil {
		if errors.Is(err, ErrResponseBodyTooLarge) {
			return nil, oversizedOAuthError(resp.StatusCode)
		}
		return nil, fmt.Errorf("reading token response: %w", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("decoding token response: %w", err)
	}

	accessToken, _ := raw["access_token"].(string)
	if accessToken == "" {
		return nil, fmt.Errorf("token response missing access_token")
	}
	if strings.IndexFunc(accessToken, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
		return nil, fmt.Errorf("token response access_token contains a control character")
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
