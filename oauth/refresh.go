package oauth

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// RefreshAuthorizationRequest is the input to RefreshAuthorization. Authenticate the
// client the same way as the grant that issued the refresh token, with exactly one of:
//
//   - ClientID alone: a public client. ClientID goes in the body.
//   - ClientID and ClientSecret: a confidential client. It authenticates with HTTP
//     Basic, and ClientID does not go in the body.
//   - Credential: the credential's client authentication.
type RefreshAuthorizationRequest struct {
	// RefreshToken is the refresh_token from a previous token response.
	RefreshToken string
	// ClientID is the client the grant was issued to.
	ClientID string
	// ClientSecret is set for a confidential client only.
	ClientSecret string
	// Credential authenticates the request in place of ClientID and ClientSecret. It
	// must implement [ClientAuthenticator].
	Credential ApplicationCredential
	// Resources are RFC 8707 resource indicators, sent as one resource parameter each.
	// Set them to narrow the token to a subset of the granted resources.
	Resources []string
	// Scopes are sent as one space-joined scope parameter. Set them to narrow the token
	// to a subset of the granted scopes.
	Scopes []string
}

// RefreshOption configures RefreshAuthorization.
type RefreshOption func(*refreshConfig)

type refreshConfig struct {
	httpClient     *http.Client
	metadata       *AuthorizationServerMetadata
	requestTimeout time.Duration
}

// WithRefreshHTTPClient sets the HTTP client used for discovery and the refresh
// request.
func WithRefreshHTTPClient(c *http.Client) RefreshOption {
	return func(cfg *refreshConfig) { cfg.httpClient = c }
}

// WithRefreshMetadata uses pre-discovered authorization server metadata. The call then
// does not send a discovery request.
func WithRefreshMetadata(md *AuthorizationServerMetadata) RefreshOption {
	return func(cfg *refreshConfig) { cfg.metadata = md }
}

// WithRefreshRequestTimeout bounds discovery and the refresh request when the caller's
// context has no deadline of its own. The bound on the refresh request also covers the
// credential's client authentication. Default: 10 seconds.
func WithRefreshRequestTimeout(d time.Duration) RefreshOption {
	return func(cfg *refreshConfig) { cfg.requestTimeout = d }
}

// RefreshAuthorization redeems a refresh token at the token endpoint (RFC 6749
// section 6). The token endpoint comes from discovery for issuer, or from
// WithRefreshMetadata, in which case issuer may be empty. The call does not keep
// state.
//
// When the response has a RefreshToken, the authorization server rotated it. Store the
// new value in place of the old one. When it has none, the old value stays valid.
//
// It returns a ConfigurationError, without sending a request, when RefreshToken is
// empty, when the client authentication is not one of the forms listed on
// [RefreshAuthorizationRequest], when the Credential does not implement
// [ClientAuthenticator], or when there is no issuer. An error from the credential's
// client authentication is returned wrapped, and no request is sent. An OAuth error
// response is an *OAuthError. invalid_grant means the refresh token is expired,
// revoked, or was issued to another client, and the only recovery is to run the
// authorization flow again. Any other non-2xx response is an *HTTPError.
func RefreshAuthorization(ctx context.Context, issuer string, req RefreshAuthorizationRequest, opts ...RefreshOption) (*TokenResponse, error) {
	cfg := refreshConfig{httpClient: http.DefaultClient, requestTimeout: defaultFetchTimeout}
	for _, opt := range opts {
		opt(&cfg)
	}

	if req.RefreshToken == "" {
		return nil, &ConfigurationError{Message: "refresh requires a refresh token"}
	}
	var authenticator ClientAuthenticator
	switch {
	case req.Credential != nil && (req.ClientID != "" || req.ClientSecret != ""):
		return nil, &ConfigurationError{Message: "refresh takes a Credential or a ClientID and optional ClientSecret, not both"}
	case req.Credential != nil:
		var err error
		if authenticator, err = clientAuthenticator(req.Credential); err != nil {
			return nil, err
		}
	case req.ClientID == "":
		return nil, &ConfigurationError{Message: "refresh requires a Credential or a ClientID"}
	}
	issuer, err := issuerOrMetadata(issuer, cfg.metadata)
	if err != nil {
		return nil, err
	}

	md := cfg.metadata
	if md == nil {
		md, err = FetchAuthorizationServerMetadata(ctx, issuer,
			WithDiscoveryHTTPClient(cfg.httpClient), WithDiscoveryRequestTimeout(cfg.requestTimeout))
		if err != nil {
			return nil, &TokenEndpointDiscoveryError{Message: "discovering token endpoint", Err: err}
		}
	}
	if md.TokenEndpoint == "" {
		return nil, &TokenEndpointDiscoveryError{Message: fmt.Sprintf("authorization server %q does not advertise a token_endpoint", issuer)}
	}

	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", req.RefreshToken)
	if len(req.Scopes) > 0 {
		form.Set("scope", strings.Join(req.Scopes, " "))
	}
	for _, r := range req.Resources {
		form.Add("resource", r)
	}

	ctx, cancel := withDefaultTimeout(ctx, cfg.requestTimeout)
	defer cancel()

	header := http.Header{}
	switch {
	case authenticator != nil:
		if err := addClientAuthentication(ctx, authenticator, issuer, md.TokenEndpoint, header, form); err != nil {
			return nil, err
		}
	case req.ClientSecret != "":
		setBasicAuth(header, req.ClientID, req.ClientSecret)
	default:
		form.Set("client_id", req.ClientID)
	}

	httpReq, err := newFormRequest(ctx, md.TokenEndpoint, header, form)
	if err != nil {
		return nil, fmt.Errorf("creating refresh request: %w", err)
	}
	resp, err := cfg.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("refresh request failed: %w", err)
	}
	defer resp.Body.Close()

	if !isSuccess(resp.StatusCode) {
		return nil, errorFromResponse(resp, "token endpoint")
	}
	return deserializeTokenResponse(resp)
}
