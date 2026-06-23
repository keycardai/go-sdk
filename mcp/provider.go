package mcp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sync"

	"github.com/keycardai/credentials-go/oauth"
)

// AccessContextStatus represents the status of token exchanges.
type AccessContextStatus string

const (
	StatusSuccess      AccessContextStatus = "success"
	StatusPartialError AccessContextStatus = "partial_error"
	StatusError        AccessContextStatus = "error"
)

// ErrorDetail describes an error during token exchange.
type ErrorDetail struct {
	Message     string `json:"message"`
	Code        string `json:"code,omitempty"`
	Description string `json:"description,omitempty"`
	RawError    string `json:"raw_error,omitempty"`
}

// AccessContext holds the results of token exchanges for multiple resources.
// It is a non-throwing result container: callers check status before accessing tokens.
type AccessContext struct {
	tokens         map[string]*oauth.TokenResponse
	resourceErrors map[string]ErrorDetail
	globalError    *ErrorDetail
}

// NewAccessContext creates a new empty AccessContext.
func NewAccessContext() *AccessContext {
	return &AccessContext{
		tokens:         make(map[string]*oauth.TokenResponse),
		resourceErrors: make(map[string]ErrorDetail),
	}
}

// SetToken sets a successful token for a resource (clears any error for that resource).
func (ac *AccessContext) SetToken(resource string, token *oauth.TokenResponse) {
	ac.tokens[resource] = token
	delete(ac.resourceErrors, resource)
}

// SetBulkTokens sets multiple tokens at once.
func (ac *AccessContext) SetBulkTokens(tokens map[string]*oauth.TokenResponse) {
	for resource, token := range tokens {
		ac.tokens[resource] = token
	}
}

// SetResourceError sets an error for a specific resource (clears any token for that resource).
func (ac *AccessContext) SetResourceError(resource string, detail ErrorDetail) {
	ac.resourceErrors[resource] = detail
	delete(ac.tokens, resource)
}

// SetError sets a global error.
func (ac *AccessContext) SetError(detail ErrorDetail) {
	ac.globalError = &detail
}

// Access returns the token for the given resource.
// Returns ResourceAccessError if the resource has an error or no token.
func (ac *AccessContext) Access(resource string) (*oauth.TokenResponse, error) {
	if ac.globalError != nil {
		return nil, &ResourceAccessError{Message: ac.globalError.Message}
	}
	if _, hasErr := ac.resourceErrors[resource]; hasErr {
		return nil, &ResourceAccessError{Message: ac.resourceErrors[resource].Message}
	}
	token, ok := ac.tokens[resource]
	if !ok {
		return nil, &ResourceAccessError{Message: fmt.Sprintf("no token for resource %q", resource)}
	}
	return token, nil
}

// Status returns the overall status of the context.
func (ac *AccessContext) Status() AccessContextStatus {
	if ac.globalError != nil {
		return StatusError
	}
	if len(ac.resourceErrors) > 0 {
		return StatusPartialError
	}
	return StatusSuccess
}

// HasErrors returns true if any errors occurred (global or per-resource).
func (ac *AccessContext) HasErrors() bool {
	return ac.globalError != nil || len(ac.resourceErrors) > 0
}

// HasError returns true if a global error is set.
func (ac *AccessContext) HasError() bool {
	return ac.globalError != nil
}

// HasResourceError returns true if the specific resource had an error.
func (ac *AccessContext) HasResourceError(resource string) bool {
	_, ok := ac.resourceErrors[resource]
	return ok
}

// GetError returns the global error, or nil.
func (ac *AccessContext) GetError() *ErrorDetail {
	return ac.globalError
}

// GetResourceError returns the error for a specific resource, or nil.
func (ac *AccessContext) GetResourceError(resource string) *ErrorDetail {
	if detail, ok := ac.resourceErrors[resource]; ok {
		return &detail
	}
	return nil
}

// GetErrors returns all errors (global + per-resource).
func (ac *AccessContext) GetErrors() (resources map[string]ErrorDetail, globalError *ErrorDetail) {
	result := make(map[string]ErrorDetail, len(ac.resourceErrors))
	for k, v := range ac.resourceErrors {
		result[k] = v
	}
	return result, ac.globalError
}

// SuccessfulResources returns the list of resources with successful token exchanges.
func (ac *AccessContext) SuccessfulResources() []string {
	resources := make([]string, 0, len(ac.tokens))
	for r := range ac.tokens {
		resources = append(resources, r)
	}
	return resources
}

// FailedResources returns the list of resources with failed token exchanges.
func (ac *AccessContext) FailedResources() []string {
	resources := make([]string, 0, len(ac.resourceErrors))
	for r := range ac.resourceErrors {
		resources = append(resources, r)
	}
	return resources
}

// AuthProviderOption configures an AuthProvider.
type AuthProviderOption func(*authProviderConfig)

type authProviderConfig struct {
	zoneURL               string
	zoneID                string
	baseURL               string
	applicationCredential ApplicationCredential
	httpClient            *http.Client
}

// WithZoneURL sets the Keycard zone URL directly.
func WithZoneURL(zoneURL string) AuthProviderOption {
	return func(cfg *authProviderConfig) { cfg.zoneURL = zoneURL }
}

// WithZoneID sets the Keycard zone ID (used with base URL to construct zone URL).
func WithZoneID(zoneID string) AuthProviderOption {
	return func(cfg *authProviderConfig) { cfg.zoneID = zoneID }
}

// WithBaseURL sets the base URL for zone URL construction. Default: "https://keycard.cloud".
func WithBaseURL(baseURL string) AuthProviderOption {
	return func(cfg *authProviderConfig) { cfg.baseURL = baseURL }
}

// WithApplicationCredential sets the application credential for token exchange.
func WithApplicationCredential(cred ApplicationCredential) AuthProviderOption {
	return func(cfg *authProviderConfig) { cfg.applicationCredential = cred }
}

// WithProviderHTTPClient sets the HTTP client used by the auth provider.
func WithProviderHTTPClient(c *http.Client) AuthProviderOption {
	return func(cfg *authProviderConfig) { cfg.httpClient = c }
}

// AuthProvider orchestrates token exchange for MCP servers. It is single-zone unless
// constructed with a multi-zone credential (NewMultiZoneClientSecret), in which case it
// routes each exchange to the zone that minted the request's token.
type AuthProvider struct {
	multiZone   bool
	defaultZone string          // single-zone issuer URL ("" when multi-zone)
	zones       map[string]bool // configured zone issuer URLs
	credential  ApplicationCredential
	httpClient  *http.Client

	mu      sync.Mutex
	clients map[string]*oauth.TokenExchangeClient // per-zone, lazily created
}

// NewAuthProvider creates a new AuthProvider with the given options. With a multi-zone
// credential the zones are taken from the credential and zoneURL/zoneID are not required;
// otherwise exactly one zone is configured from zoneURL or zoneID.
func NewAuthProvider(opts ...AuthProviderOption) (*AuthProvider, error) {
	cfg := authProviderConfig{
		baseURL:    "https://keycard.cloud",
		httpClient: http.DefaultClient,
	}
	for _, opt := range opts {
		opt(&cfg)
	}

	p := &AuthProvider{
		credential: cfg.applicationCredential,
		httpClient: cfg.httpClient,
		zones:      make(map[string]bool),
		clients:    make(map[string]*oauth.TokenExchangeClient),
	}

	// A multi-zone credential is self-describing: it carries the zone set.
	if mz, ok := cfg.applicationCredential.(MultiZoneCredential); ok && len(mz.Zones()) > 0 {
		p.multiZone = true
		for _, zone := range mz.Zones() {
			p.zones[zone] = true
		}
		return p, nil
	}

	zoneURL := cfg.zoneURL
	if zoneURL == "" {
		zoneURL = buildZoneURL(cfg.zoneID, cfg.baseURL)
	}
	if zoneURL == "" {
		return nil, &AuthProviderConfigurationError{
			Message: "either zoneURL or zoneID must be provided (or a multi-zone credential)",
		}
	}
	p.defaultZone = zoneURL
	p.zones[zoneURL] = true
	return p, nil
}

// Grant returns middleware that performs token exchange for the specified resources.
// The AccessContext is stored in the request context (retrieve with AccessContextFromRequest).
func (p *AuthProvider) Grant(resources ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authInfo := AuthInfoFromRequest(r)

			if authInfo == nil || authInfo.Token == "" {
				ac := NewAccessContext()
				ac.SetError(ErrorDetail{
					Message: "No authentication token available. Ensure RequireBearerAuth() middleware runs before Grant().",
				})
				ctx := context.WithValue(r.Context(), accessContextKey, ac)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			ac := p.exchange(r.Context(), authInfo.Issuer, authInfo.Token, resources...)
			ctx := context.WithValue(r.Context(), accessContextKey, ac)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// ExchangeTokens performs token exchange for a single-zone provider and returns an
// AccessContext. For a multi-zone provider use ExchangeTokensForZone, or Grant (which
// routes by the verified token's issuer).
func (p *AuthProvider) ExchangeTokens(ctx context.Context, subjectToken string, resources ...string) *AccessContext {
	return p.exchange(ctx, "", subjectToken, resources...)
}

// ExchangeTokensForZone performs token exchange against the given zone (issuer URL),
// selecting that zone's credential. It fails closed if the zone is not configured.
func (p *AuthProvider) ExchangeTokensForZone(ctx context.Context, issuer, subjectToken string, resources ...string) *AccessContext {
	return p.exchange(ctx, issuer, subjectToken, resources...)
}

func (p *AuthProvider) exchange(ctx context.Context, issuer, subjectToken string, resources ...string) *AccessContext {
	ac := NewAccessContext()

	zone, err := p.resolveZone(issuer)
	if err != nil {
		ac.SetError(ErrorDetail{
			Message:  "Could not resolve the request's zone.",
			RawError: err.Error(),
		})
		return ac
	}

	client := p.clientForZone(zone)
	tokens := make(map[string]*oauth.TokenResponse)

	// Resolve the token endpoint for credential assertion audience.
	tokenEndpoint, _ := client.TokenEndpoint(ctx)

	for _, resource := range resources {
		var req *oauth.TokenExchangeRequest

		if p.credential != nil {
			opts := &PrepareOptions{TokenEndpoint: tokenEndpoint}
			req, err = p.credential.PrepareTokenExchangeRequest(ctx, subjectToken, resource, opts)
			if err != nil {
				ac.SetResourceError(resource, ErrorDetail{
					Message:  fmt.Sprintf("Token exchange failed for %s", resource),
					RawError: err.Error(),
				})
				continue
			}
		} else {
			req = &oauth.TokenExchangeRequest{
				SubjectToken:     subjectToken,
				Resource:         resource,
				SubjectTokenType: "urn:ietf:params:oauth:token-type:access_token",
			}
		}

		resp, err := client.ExchangeToken(ctx, *req)
		if err != nil {
			detail := ErrorDetail{
				Message: fmt.Sprintf("Token exchange failed for %s", resource),
			}
			var oauthErr *oauth.OAuthError
			if errors.As(err, &oauthErr) {
				detail.Code = oauthErr.ErrorCode
				if oauthErr.Message != "" {
					detail.Description = oauthErr.Message
				}
			} else {
				detail.RawError = err.Error()
			}
			ac.SetResourceError(resource, detail)
			continue
		}

		tokens[resource] = resp
	}

	ac.SetBulkTokens(tokens)
	return ac
}

// resolveZone picks the zone issuer URL for an exchange. A single-zone provider always
// uses its configured zone (the issuer is ignored). A multi-zone provider requires the
// issuer to be one of its configured zones and fails closed otherwise.
func (p *AuthProvider) resolveZone(issuer string) (string, error) {
	if !p.multiZone {
		return p.defaultZone, nil
	}
	if issuer == "" {
		return "", fmt.Errorf("multi-zone provider could not resolve a zone: the token has no issuer")
	}
	if !p.zones[issuer] {
		return "", fmt.Errorf("multi-zone provider has no credential configured for zone %q", issuer)
	}
	return issuer, nil
}

// clientForZone returns the token-exchange client for a zone, creating it on first use
// with that zone's issuer and credential. Clients are cached per zone.
func (p *AuthProvider) clientForZone(zone string) *oauth.TokenExchangeClient {
	p.mu.Lock()
	defer p.mu.Unlock()

	if c, ok := p.clients[zone]; ok {
		return c
	}

	var clientOpts []oauth.TokenExchangeClientOption
	if p.httpClient != nil {
		clientOpts = append(clientOpts, oauth.WithTokenExchangeHTTPClient(p.httpClient))
	}
	if p.credential != nil {
		if auth := p.credential.Auth(zone); auth != nil {
			clientOpts = append(clientOpts, oauth.WithClientCredentials(auth.ClientID, auth.ClientSecret))
		}
	}

	c := oauth.NewTokenExchangeClient(zone, clientOpts...)
	p.clients[zone] = c
	return c
}

func buildZoneURL(zoneID, baseURL string) string {
	if zoneID == "" {
		return ""
	}
	u, err := url.Parse(baseURL)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%s://%s.%s", u.Scheme, zoneID, u.Host)
}
