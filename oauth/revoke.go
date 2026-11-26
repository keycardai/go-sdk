package oauth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/keycardai/go-sdk/internal/printed"
)

// RevokeTokenRequest is the input to RevokeToken. Supply either a Credential
// or a ClientID with an optional ClientSecret.
//
// String, GoString, and LogValue leave out Token and ClientSecret, and show
// Credential's type only.
type RevokeTokenRequest struct {
	// Token is the token to revoke.
	Token string
	// TokenTypeHint defaults to "refresh_token" when empty.
	TokenTypeHint string
	// ClientID identifies the public or confidential client.
	ClientID string
	// ClientSecret authenticates a confidential client with HTTP Basic.
	ClientSecret string
	// Credential authenticates in place of ClientID and ClientSecret and must
	// implement [ClientAuthenticator].
	Credential ApplicationCredential
}

func (r RevokeTokenRequest) printed() printed.Struct {
	return printed.Struct{Type: "oauth.RevokeTokenRequest", Fields: []printed.Field{
		{Name: "TokenTypeHint", Key: "token_type_hint", Value: r.TokenTypeHint},
		{Name: "ClientID", Key: "client_id", Value: r.ClientID},
		{Name: "Credential", Key: "credential", Value: printed.TypeName(r.Credential)},
	}}
}

// String implements [fmt.Stringer].
func (r RevokeTokenRequest) String() string { return r.printed().String() }

// GoString implements [fmt.GoStringer].
func (r RevokeTokenRequest) GoString() string { return r.printed().GoString() }

// LogValue implements [slog.LogValuer].
func (r RevokeTokenRequest) LogValue() slog.Value { return r.printed().LogValue() }

// RevocationOption configures RevokeToken.
type RevocationOption func(*revocationConfig)

type revocationConfig struct {
	httpClient     *http.Client
	metadata       *AuthorizationServerMetadata
	requestTimeout time.Duration
}

// WithRevocationHTTPClient sets the HTTP client for discovery and revocation.
func WithRevocationHTTPClient(c *http.Client) RevocationOption {
	return func(cfg *revocationConfig) { cfg.httpClient = c }
}

// WithRevocationMetadata supplies authorization server metadata and skips discovery.
func WithRevocationMetadata(md *AuthorizationServerMetadata) RevocationOption {
	return func(cfg *revocationConfig) { cfg.metadata = md }
}

// WithRevocationRequestTimeout sets the timeout for each request, including
// credential authentication, when the caller has not set a context deadline.
// The default is 10 seconds.
func WithRevocationRequestTimeout(d time.Duration) RevocationOption {
	return func(cfg *revocationConfig) { cfg.requestTimeout = d }
}

// RevokeToken sends an RFC 7009 request to the issuer's advertised revocation
// endpoint, which must use HTTPS. If WithRevocationMetadata supplies metadata,
// issuer may be empty.
// The operation does not cache discovery, retry requests, or follow revocation redirects.
//
// HTTP 200 succeeds without reading a body, including for unknown, expired,
// or already revoked tokens. Keycard revokes the session when the token
// identifies a revocable session. Invalid inputs or a missing endpoint return
// a [ConfigurationError]. OAuth errors are returned as [OAuthError].
func RevokeToken(ctx context.Context, issuer string, req RevokeTokenRequest, opts ...RevocationOption) error {
	cfg := revocationConfig{httpClient: http.DefaultClient, requestTimeout: defaultFetchTimeout}
	for _, opt := range opts {
		opt(&cfg)
	}

	if req.Token == "" {
		return &ConfigurationError{Message: "revocation requires a token"}
	}
	var authenticator ClientAuthenticator
	switch {
	case req.Credential != nil && (req.ClientID != "" || req.ClientSecret != ""):
		return &ConfigurationError{Message: "revocation takes a Credential or a ClientID and optional ClientSecret, not both"}
	case req.Credential != nil:
		var err error
		if authenticator, err = clientAuthenticator(req.Credential); err != nil {
			return err
		}
	case req.ClientID == "":
		return &ConfigurationError{Message: "revocation requires a Credential or a ClientID"}
	}

	issuer, err := issuerOrMetadata(issuer, cfg.metadata)
	if err != nil {
		return err
	}
	if err := checkEndpoint("issuer", issuer); err != nil {
		return err
	}
	md := cfg.metadata
	if md == nil {
		md, err = FetchAuthorizationServerMetadata(ctx, issuer,
			WithDiscoveryHTTPClient(cfg.httpClient), WithDiscoveryRequestTimeout(cfg.requestTimeout))
		if err != nil {
			var typed KeycardError
			if errors.As(err, &typed) {
				return err
			}
			return &NetworkError{Message: "discovering revocation endpoint", Err: err}
		}
	}
	if md.RevocationEndpoint == "" {
		return &ConfigurationError{Message: fmt.Sprintf("authorization server %q does not advertise a revocation_endpoint", issuer)}
	}
	endpoint, err := url.Parse(md.RevocationEndpoint)
	if err != nil || endpoint.Scheme != "https" || endpoint.Hostname() == "" {
		return &ConfigurationError{Message: "revocation_endpoint must be an absolute HTTPS URL"}
	}

	hint := req.TokenTypeHint
	if hint == "" {
		hint = "refresh_token"
	}
	form := url.Values{"token": {req.Token}, "token_type_hint": {hint}}
	header := http.Header{}
	ctx, cancel := withDefaultTimeout(ctx, cfg.requestTimeout)
	defer cancel()

	switch {
	case authenticator != nil:
		if err := addClientAuthentication(ctx, authenticator, issuer, md.Issuer, header, form); err != nil {
			return err
		}
	case req.ClientSecret != "":
		setBasicAuth(header, req.ClientID, req.ClientSecret)
	default:
		form.Set("client_id", req.ClientID)
	}

	httpReq, err := newFormRequest(ctx, md.RevocationEndpoint, header, form)
	if err != nil {
		return &ConfigurationError{Message: fmt.Sprintf("creating revocation request: %v", err)}
	}
	client := *cfg.httpClient
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	resp, err := client.Do(httpReq)
	if err != nil {
		return &NetworkError{Message: "revocation request failed", Err: err}
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		return nil
	}
	data, err := readBoundedBody(resp.Body)
	if errors.Is(err, ErrResponseBodyTooLarge) {
		return oversizedOAuthError(resp.StatusCode)
	}
	if err != nil {
		return &NetworkError{Message: "reading revocation response", Err: err}
	}
	if oauthErr := decodeOAuthError(data, resp.StatusCode); oauthErr != nil {
		return oauthErr
	}
	return &HTTPError{Message: "revocation endpoint returned an error", Status: resp.StatusCode}
}
