package mcp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/keycardai/credentials-go/oauth"
)

// AccessContext, its status/error types, and ResourceAccessError now live in the oauth
// package, so the oauth client surface can return them without importing mcp. They are
// re-exported here as aliases for backward compatibility.
type (
	AccessContext       = oauth.AccessContext
	AccessContextStatus = oauth.AccessContextStatus
	ErrorDetail         = oauth.ErrorDetail
)

const (
	StatusSuccess      = oauth.StatusSuccess
	StatusPartialError = oauth.StatusPartialError
	StatusError        = oauth.StatusError
)

// NewAccessContext creates a new empty AccessContext.
func NewAccessContext() *AccessContext { return oauth.NewAccessContext() }

// NewAccessContextWithTokens creates an AccessContext pre-seeded with tokens, keyed by resource.
func NewAccessContextWithTokens(tokens map[string]*oauth.TokenResponse) *AccessContext {
	return oauth.NewAccessContextWithTokens(tokens)
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
	defaultZone string // single-zone issuer URL ("" when multi-zone)
	credential  ApplicationCredential
	httpClient  *http.Client

	mu sync.Mutex
	// clients is keyed by zone issuer URL. A key's presence marks a configured zone;
	// the value is that zone's token-exchange client, created lazily (nil until first use).
	clients map[string]*oauth.TokenExchangeClient
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

	// A WebIdentity credential needs a client id for its assertion, and the provider has
	// no way to supply one at request time (it never sets resource_client_id). Without it
	// every exchange would fail with a config error, so fail loudly at construction.
	if wi, ok := cfg.applicationCredential.(*WebIdentityCredential); ok && wi.clientID == "" {
		return nil, &AuthProviderConfigurationError{
			Message: "WebIdentity credential requires a client id: pass mcp.WithClientID to NewWebIdentity",
		}
	}

	p := &AuthProvider{
		credential: cfg.applicationCredential,
		httpClient: cfg.httpClient,
		clients:    make(map[string]*oauth.TokenExchangeClient),
	}

	// A multi-zone credential is self-describing: it carries the zone set. Register each
	// zone with a nil client; the client is created on first use in clientForZone.
	if mz, ok := cfg.applicationCredential.(MultiZoneCredential); ok && len(mz.Zones()) > 0 {
		p.multiZone = true
		for _, zone := range mz.Zones() {
			p.clients[zone] = nil
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
	p.clients[zoneURL] = nil
	return p, nil
}

// GrantOption configures the token exchange that Grant performs.
type GrantOption func(*grantConfig)

type grantConfig struct {
	userIdentifier          func(*http.Request) (string, error)
	requestScopes           []string
	requestScopesByResource map[string][]string
}

// WithUserIdentifier sets a resolver that maps the inbound request to a user identifier.
// When set, Grant impersonates that user (RFC 8693 substitute-user) for each resource
// rather than exchanging the caller's own token. The resolver runs once per request; if it
// returns an error the grant fails closed with a global error on the AccessContext.
//
// SECURITY: the resolved identifier becomes the subject of a real token minted with the
// agent's own credential. Derive it from the verified token, never from unverified request
// data such as a header, query parameter, or body field:
//
//	mcp.WithUserIdentifier(func(r *http.Request) (string, error) {
//		return mcp.AuthInfoFromRequest(r).Subject, nil
//	})
func WithUserIdentifier(fn func(*http.Request) (string, error)) GrantOption {
	return func(c *grantConfig) { c.userIdentifier = fn }
}

// WithRequestScopes sets the scopes requested for each resource's exchanged token. The
// same scopes apply to every resource in the grant and take precedence over any scope the
// application credential sets. Use WithRequestScopesByResource to vary scopes per resource.
func WithRequestScopes(scopes ...string) GrantOption {
	return func(c *grantConfig) { c.requestScopes = scopes }
}

// WithRequestScopesByResource sets the scopes requested per resource, keyed by resource
// URL. A resource present in the map uses its scopes; a resource absent from the map falls
// back to WithRequestScopes (if set). This mirrors the per-resource form of the TypeScript
// requestScopes option.
func WithRequestScopesByResource(scopes map[string][]string) GrantOption {
	return func(c *grantConfig) { c.requestScopesByResource = scopes }
}

// Grant returns middleware that performs token exchange for the specified resources and
// stores the result in the request context (retrieve with AccessContextFromRequest).
// Stacked Grant middlewares merge into a single AccessContext on the request. With
// WithUserIdentifier the grant impersonates the resolved user instead of exchanging the
// caller's token.
func (p *AuthProvider) Grant(resources []string, opts ...GrantOption) func(http.Handler) http.Handler {
	cfg := grantConfig{}
	for _, opt := range opts {
		opt(&cfg)
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authInfo := AuthInfoFromRequest(r)
			if authInfo == nil || authInfo.Token == "" {
				ac := oauth.NewAccessContext()
				ac.SetError(oauth.ErrorDetail{
					Message: "No authentication token available. Ensure RequireBearerAuth() middleware runs before Grant().",
				})
				next.ServeHTTP(w, r.WithContext(mergeAccessContext(r, ac)))
				return
			}

			userIdentifier := ""
			if cfg.userIdentifier != nil {
				id, err := cfg.userIdentifier(r)
				if err != nil {
					ac := oauth.NewAccessContext()
					ac.SetError(oauth.ErrorDetail{
						Message:  "Failed to resolve the user identifier for impersonation.",
						RawError: err.Error(),
					})
					next.ServeHTTP(w, r.WithContext(mergeAccessContext(r, ac)))
					return
				}
				userIdentifier = id
			}

			ac := p.exchange(r.Context(), authInfo.Issuer, authInfo.Token, userIdentifier, cfg.requestScopes, cfg.requestScopesByResource, resources)
			next.ServeHTTP(w, r.WithContext(mergeAccessContext(r, ac)))
		})
	}
}

// mergeAccessContext folds ac into the request's existing AccessContext when one is
// present (stacked grants), otherwise attaches ac to the request context.
func mergeAccessContext(r *http.Request, ac *oauth.AccessContext) context.Context {
	if existing := AccessContextFromRequest(r); existing != nil {
		existing.Merge(ac)
		return r.Context()
	}
	return context.WithValue(r.Context(), accessContextKey, ac)
}

// ExchangeTokens performs token exchange for a single-zone provider and returns an
// AccessContext. For a multi-zone provider use ExchangeTokensForZone, or Grant (which
// routes by the verified token's issuer).
func (p *AuthProvider) ExchangeTokens(ctx context.Context, subjectToken string, resources ...string) *AccessContext {
	return p.exchange(ctx, "", subjectToken, "", nil, nil, resources)
}

// ExchangeTokensForZone performs token exchange against the given zone (issuer URL),
// selecting that zone's credential. It fails closed if the zone is not configured.
func (p *AuthProvider) ExchangeTokensForZone(ctx context.Context, issuer, subjectToken string, resources ...string) *AccessContext {
	return p.exchange(ctx, issuer, subjectToken, "", nil, nil, resources)
}

func (p *AuthProvider) exchange(ctx context.Context, issuer, subjectToken, userIdentifier string, scopes []string, scopesByResource map[string][]string, resources []string) *AccessContext {
	ac := oauth.NewAccessContext()

	zone, err := p.resolveZone(issuer)
	if err != nil {
		ac.SetError(oauth.ErrorDetail{
			Message:  "Could not resolve the request's zone.",
			RawError: err.Error(),
		})
		return ac
	}

	client := p.clientForZone(zone)
	if client == nil {
		ac.SetError(oauth.ErrorDetail{
			Message:  "Could not resolve the request's zone.",
			RawError: fmt.Sprintf("no token-exchange client for zone %q", zone),
		})
		return ac
	}

	// Resolve the token endpoint for credential assertion audience.
	tokenEndpoint, _ := client.TokenEndpoint(ctx)

	tokens := make(map[string]*oauth.TokenResponse)
	for _, resource := range resources {
		resourceScopes := scopes
		if s, ok := scopesByResource[resource]; ok {
			resourceScopes = s
		}
		resp, err := p.exchangeResource(ctx, client, subjectToken, userIdentifier, resourceScopes, resource, tokenEndpoint)
		if err != nil {
			ac.SetResourceError(resource, exchangeErrorDetail(resource, err))
			continue
		}
		tokens[resource] = resp
	}

	ac.SetBulkTokens(tokens)
	return ac
}

// exchangeResource exchanges (or impersonates) a single resource token. With a
// userIdentifier it performs an RFC 8693 substitute-user impersonation; otherwise it
// exchanges the caller's subject token, building the request via the application
// credential when one is configured.
func (p *AuthProvider) exchangeResource(ctx context.Context, client *oauth.TokenExchangeClient, subjectToken, userIdentifier string, scopes []string, resource, tokenEndpoint string) (*oauth.TokenResponse, error) {
	if userIdentifier != "" {
		return client.Impersonate(ctx, oauth.ImpersonateRequest{
			UserIdentifier: userIdentifier,
			Resource:       resource,
			Scopes:         scopes,
		})
	}

	var req *oauth.TokenExchangeRequest
	if p.credential != nil {
		r, err := p.credential.PrepareTokenExchangeRequest(ctx, subjectToken, resource, &PrepareOptions{TokenEndpoint: tokenEndpoint})
		if err != nil {
			return nil, err
		}
		req = r
	} else {
		req = &oauth.TokenExchangeRequest{
			SubjectToken:     subjectToken,
			Resource:         resource,
			SubjectTokenType: "urn:ietf:params:oauth:token-type:access_token",
		}
	}
	if len(scopes) > 0 {
		req.Scope = strings.Join(scopes, " ")
	}

	return client.ExchangeToken(ctx, *req)
}

// exchangeErrorDetail builds an ErrorDetail from a failed exchange, surfacing an OAuth
// error's code/description when present and otherwise the raw error.
func exchangeErrorDetail(resource string, err error) oauth.ErrorDetail {
	detail := oauth.ErrorDetail{Message: fmt.Sprintf("Token exchange failed for %s", resource)}
	var oauthErr *oauth.OAuthError
	if errors.As(err, &oauthErr) {
		detail.Code = oauthErr.ErrorCode
		if oauthErr.Message != "" {
			detail.Description = oauthErr.Message
		}
	} else {
		detail.RawError = err.Error()
	}
	return detail
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
	// clients is guarded by mu (clientForZone mutates it), so take the lock for the
	// membership check even though we only read it here.
	p.mu.Lock()
	_, configured := p.clients[issuer]
	p.mu.Unlock()
	if !configured {
		return "", fmt.Errorf("multi-zone provider has no credential configured for zone %q", issuer)
	}
	return issuer, nil
}

// clientForZone returns the token-exchange client for a configured zone, creating it on
// first use with the zone's issuer and credential and caching it. It returns nil when the
// zone is not configured: a client is only minted for a zone the map already holds, so an
// unknown zone never gets one. Callers resolve the zone with resolveZone first.
func (p *AuthProvider) clientForZone(zone string) *oauth.TokenExchangeClient {
	p.mu.Lock()
	defer p.mu.Unlock()

	c, ok := p.clients[zone]
	if !ok {
		return nil
	}
	if c != nil {
		return c
	}

	// Configured but not yet created: build the client on first use and cache it.
	var clientOpts []oauth.TokenExchangeClientOption
	if p.httpClient != nil {
		clientOpts = append(clientOpts, oauth.WithTokenExchangeHTTPClient(p.httpClient))
	}
	if p.credential != nil {
		if auth := p.credential.Auth(zone); auth != nil {
			clientOpts = append(clientOpts, oauth.WithClientCredentials(auth.ClientID, auth.ClientSecret))
		}
	}

	c = oauth.NewTokenExchangeClient(zone, clientOpts...)
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
