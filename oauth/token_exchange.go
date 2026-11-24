package oauth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
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
//
// AccessToken, RefreshToken, IDToken, UserID and Username are secrets. The
// printed form of a TokenResponse, through any fmt verb, shows which of them
// are set and never their values. JSON encoding includes them. A token
// response stored as JSON is placed the same way as a fresh one.
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	// TokenType names the kind of credential: Bearer, Basic, Keycard-API-Key
	// or Keycard-Password. It is kept as received. A response without
	// token_type gives Bearer. PlaceCredential refuses any other value.
	TokenType       string   `json:"token_type"`
	ExpiresIn       int      `json:"expires_in,omitempty"`
	RefreshToken    string   `json:"refresh_token,omitempty"`
	IDToken         string   `json:"id_token,omitempty"`
	Scope           []string `json:"scope,omitempty"`
	IssuedTokenType string   `json:"issued_token_type,omitempty"`
	// UserID is the user ID of a Basic credential.
	UserID string `json:"user_id,omitempty"`
	// Username is the username of a Keycard-Password credential.
	Username string `json:"username,omitempty"`
	// Method says where to send a Keycard-API-Key or Keycard-Password
	// credential. It holds the response's method member as received.
	// PlaceCredential checks it.
	Method json.RawMessage `json:"method,omitempty"`
}

// Format prints t with its secrets redacted, for every verb.
func (t TokenResponse) Format(f fmt.State, _ rune) {
	fields := []string{"TokenType:" + strconv.Quote(t.TokenType)}
	secret := func(name, value string) {
		if value != "" {
			fields = append(fields, name+":[redacted]")
		}
	}
	secret("AccessToken", t.AccessToken)
	if t.ExpiresIn != 0 {
		fields = append(fields, "ExpiresIn:"+strconv.Itoa(t.ExpiresIn))
	}
	secret("RefreshToken", t.RefreshToken)
	secret("IDToken", t.IDToken)
	if len(t.Scope) > 0 {
		fields = append(fields, fmt.Sprintf("Scope:%q", t.Scope))
	}
	if t.IssuedTokenType != "" {
		fields = append(fields, "IssuedTokenType:"+strconv.Quote(t.IssuedTokenType))
	}
	secret("UserID", t.UserID)
	secret("Username", t.Username)
	if len(t.Method) > 0 {
		var method bytes.Buffer
		if json.Compact(&method, t.Method) != nil {
			method.Reset()
			method.Write(t.Method)
		}
		fields = append(fields, "Method:"+method.String())
	}
	io.WriteString(f, "oauth.TokenResponse{"+strings.Join(fields, " ")+"}")
}

// TokenExchangeClientOption configures a TokenExchangeClient.
type TokenExchangeClientOption func(*tokenExchangeConfig)

type tokenExchangeConfig struct {
	clientID       string
	clientSecret   string
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

// WithTokenExchangeHTTPClient sets the HTTP client for token exchange requests.
func WithTokenExchangeHTTPClient(c *http.Client) TokenExchangeClientOption {
	return func(cfg *tokenExchangeConfig) {
		cfg.httpClient = c
	}
}

// WithTokenExchangeRequestTimeout bounds each request this call makes to the authorization server when the
// caller's context has no deadline of its own. Default: 10 seconds.
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
type TokenExchangeClient struct {
	issuerURL string
	cfg       tokenExchangeConfig
	endpoint  tokenEndpointResolver
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

// ExchangeToken performs a token exchange request.
func (c *TokenExchangeClient) ExchangeToken(ctx context.Context, req TokenExchangeRequest) (*TokenResponse, error) {
	tokenEndpoint, err := c.endpoint.Endpoint(ctx)
	if err != nil {
		return nil, err
	}

	body := serializeTokenExchangeRequest(req)

	ctx, cancel := withDefaultTimeout(ctx, c.cfg.requestTimeout)
	defer cancel()

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, strings.NewReader(body.Encode()))
	if err != nil {
		return nil, fmt.Errorf("creating token exchange request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if c.cfg.clientID != "" && c.cfg.clientSecret != "" {
		setBasicAuth(httpReq.Header, c.cfg.clientID, c.cfg.clientSecret)
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

// deserializeTokenResponse parses a token endpoint response. A member with the
// wrong JSON type is ignored. token_type, user_id, username and method are kept
// as received; PlaceCredential checks them.
func deserializeTokenResponse(resp *http.Response) (*TokenResponse, error) {
	var raw map[string]json.RawMessage
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, fmt.Errorf("decoding token response: %w", err)
	}
	str := func(key string) string {
		var s string
		_ = json.Unmarshal(raw[key], &s)
		return s
	}

	accessToken := str("access_token")
	if accessToken == "" {
		return nil, fmt.Errorf("token response missing access_token")
	}
	if strings.IndexFunc(accessToken, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
		return nil, fmt.Errorf("token response access_token contains a control character")
	}

	tokenType := str("token_type")
	if tokenType == "" {
		tokenType = TokenTypeBearer
	}

	result := &TokenResponse{
		AccessToken:     accessToken,
		TokenType:       tokenType,
		RefreshToken:    str("refresh_token"),
		IDToken:         str("id_token"),
		IssuedTokenType: str("issued_token_type"),
		UserID:          str("user_id"),
		Username:        str("username"),
	}

	var expiresIn float64
	if json.Unmarshal(raw["expires_in"], &expiresIn) == nil {
		result.ExpiresIn = int(expiresIn)
	}
	if scope := str("scope"); scope != "" {
		result.Scope = strings.Fields(scope)
	}
	if method, ok := raw["method"]; ok && string(method) != "null" {
		result.Method = method
	}

	return result, nil
}
