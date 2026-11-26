package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/keycardai/go-sdk/internal/printed"
)

// IntrospectTokenRequest is the input to [IntrospectToken]. String, GoString,
// and LogValue omit Token and show only the type of Credential.
type IntrospectTokenRequest struct {
	// Token is the access or refresh token to check.
	Token string
	// TokenTypeHint is sent unchanged when nonempty.
	TokenTypeHint string
	// Credential authenticates the confidential client and must implement
	// [ClientAuthenticator].
	Credential ApplicationCredential
}

func (r IntrospectTokenRequest) printed() printed.Struct {
	return printed.Struct{Type: "oauth.IntrospectTokenRequest", Fields: []printed.Field{
		{Name: "TokenTypeHint", Key: "token_type_hint", Value: r.TokenTypeHint},
		{Name: "Credential", Key: "credential", Value: printed.TypeName(r.Credential)},
	}}
}

// String implements [fmt.Stringer].
func (r IntrospectTokenRequest) String() string { return r.printed().String() }

// GoString implements [fmt.GoStringer].
func (r IntrospectTokenRequest) GoString() string { return r.printed().GoString() }

// LogValue implements [slog.LogValuer].
func (r IntrospectTokenRequest) LogValue() slog.Value { return r.printed().LogValue() }

// TokenIntrospection is the RFC 7662 result. Only Active is set for an
// inactive token. All other fields are optional for an active token.
type TokenIntrospection struct {
	Active    bool
	TokenType *string
	Issuer    *string
	Subject   *string
	ClientID  *string
	// Audience contains the aud claim, including when the wire value is a single string.
	Audience []string
	// Scope contains the space-separated scopes from the scope claim.
	Scope     []string
	SessionID *string
	JWTID     *string
	IssuedAt  *int64 // Unix seconds.
	Expiry    *int64 // Unix seconds.
	// Extra holds claims without a typed field, preserving their JSON values.
	Extra map[string]json.RawMessage
}

// IntrospectionOption configures [IntrospectToken].
type IntrospectionOption func(*introspectionConfig)

type introspectionConfig struct {
	httpClient     *http.Client
	metadata       *AuthorizationServerMetadata
	requestTimeout time.Duration
}

// WithIntrospectionHTTPClient sets the HTTP client for discovery and introspection.
func WithIntrospectionHTTPClient(c *http.Client) IntrospectionOption {
	return func(cfg *introspectionConfig) { cfg.httpClient = c }
}

// WithIntrospectionMetadata supplies authorization server metadata and skips discovery.
func WithIntrospectionMetadata(md *AuthorizationServerMetadata) IntrospectionOption {
	return func(cfg *introspectionConfig) { cfg.metadata = md }
}

// WithIntrospectionRequestTimeout sets the timeout for each request, including
// credential authentication, when the caller has not set a context deadline.
// The default is 10 seconds.
func WithIntrospectionRequestTimeout(d time.Duration) IntrospectionOption {
	return func(cfg *introspectionConfig) { cfg.requestTimeout = d }
}

// IntrospectToken checks a token at the issuer's advertised HTTPS introspection
// endpoint. If [WithIntrospectionMetadata] supplies metadata, issuer may be
// empty. The operation does not cache results or discovery, retry requests,
// or follow introspection redirects.
func IntrospectToken(ctx context.Context, issuer string, req IntrospectTokenRequest, opts ...IntrospectionOption) (*TokenIntrospection, error) {
	cfg := introspectionConfig{httpClient: http.DefaultClient, requestTimeout: defaultFetchTimeout}
	for _, opt := range opts {
		opt(&cfg)
	}

	if req.Token == "" {
		return nil, &ConfigurationError{Message: "introspection requires a token"}
	}
	authenticator, ok := req.Credential.(ClientAuthenticator)
	if !ok {
		return nil, &ConfigurationError{Message: fmt.Sprintf("credential %T does not provide client authentication", req.Credential)}
	}

	issuer, err := issuerOrMetadata(issuer, cfg.metadata)
	if err != nil {
		return nil, err
	}
	if err := checkEndpoint("issuer", issuer); err != nil {
		return nil, err
	}
	md := cfg.metadata
	if md == nil {
		md, err = FetchAuthorizationServerMetadata(ctx, issuer,
			WithDiscoveryHTTPClient(cfg.httpClient), WithDiscoveryRequestTimeout(cfg.requestTimeout))
		if err != nil {
			var typed KeycardError
			if errors.As(err, &typed) {
				return nil, err
			}
			return nil, &NetworkError{Message: "discovering introspection endpoint", Err: err}
		}
	}
	if md.IntrospectionEndpoint == "" {
		return nil, &ConfigurationError{Message: fmt.Sprintf("authorization server %q does not advertise an introspection_endpoint", issuer)}
	}
	endpoint, err := url.Parse(md.IntrospectionEndpoint)
	if err != nil || endpoint.Scheme != "https" || endpoint.Hostname() == "" {
		return nil, &ConfigurationError{Message: "introspection_endpoint must be an absolute HTTPS URL"}
	}

	form := url.Values{"token": {req.Token}}
	if req.TokenTypeHint != "" {
		form.Set("token_type_hint", req.TokenTypeHint)
	}
	header := http.Header{}
	ctx, cancel := withDefaultTimeout(ctx, cfg.requestTimeout)
	defer cancel()
	if err := addClientAuthentication(ctx, authenticator, issuer, md.Issuer, header, form); err != nil {
		return nil, err
	}
	httpReq, err := newFormRequest(ctx, md.IntrospectionEndpoint, header, form)
	if err != nil {
		return nil, &ConfigurationError{Message: fmt.Sprintf("creating introspection request: %v", err)}
	}
	client := *cfg.httpClient
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, &NetworkError{Message: "introspection request failed", Err: err}
	}
	defer resp.Body.Close()

	data, err := readBoundedBody(resp.Body)
	if errors.Is(err, ErrResponseBodyTooLarge) {
		return nil, oversizedOAuthError(resp.StatusCode)
	}
	if err != nil {
		return nil, &NetworkError{Message: "reading introspection response", Err: err}
	}
	if resp.StatusCode != http.StatusOK {
		if oauthErr := decodeOAuthError(data, resp.StatusCode); oauthErr != nil {
			return nil, oauthErr
		}
		return nil, &HTTPError{Message: "introspection endpoint returned an error", Status: resp.StatusCode}
	}

	result, err := parseTokenIntrospection(data)
	if err != nil {
		return nil, &OAuthError{
			ErrorCode: "invalid_response", Message: "decoding introspection response", Status: resp.StatusCode, Err: err,
		}
	}
	return result, nil
}

func parseTokenIntrospection(data []byte) (*TokenIntrospection, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return nil, err
	}
	var active *bool
	if raw, ok := fields["active"]; ok {
		if err := json.Unmarshal(raw, &active); err != nil {
			return nil, err
		}
	}
	if active == nil {
		return nil, errors.New("introspection response requires a boolean active field")
	}
	result := &TokenIntrospection{Active: *active}
	if !result.Active {
		return result, nil
	}
	delete(fields, "active")

	var aud jwt.ClaimStrings
	var scope *string
	for _, field := range []struct {
		name string
		dest any
	}{
		{"token_type", &result.TokenType},
		{"iss", &result.Issuer},
		{"sub", &result.Subject},
		{"client_id", &result.ClientID},
		{"aud", &aud},
		{"scope", &scope},
		{"sid", &result.SessionID},
		{"jti", &result.JWTID},
		{"iat", &result.IssuedAt},
		{"exp", &result.Expiry},
	} {
		if raw, ok := fields[field.name]; ok {
			if err := json.Unmarshal(raw, field.dest); err != nil {
				return nil, fmt.Errorf("decoding introspection field %q: %w", field.name, err)
			}
			delete(fields, field.name)
		}
	}
	result.Audience = []string(aud)
	if scope != nil {
		result.Scope = strings.Fields(*scope)
	}
	if len(fields) > 0 {
		result.Extra = fields
	}
	return result, nil
}
