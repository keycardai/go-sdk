package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	deviceCodeGrantType       = "urn:ietf:params:oauth:grant-type:device_code"
	defaultDevicePollInterval = 5 * time.Second
	deviceSlowDownIncrement   = 5 * time.Second
)

// Clock supplies the current time and timers. Inject a fake in tests so that
// expiry and polling waits do not depend on real time.
type Clock interface {
	Now() time.Time
	After(d time.Duration) <-chan time.Time
}

type systemClock struct{}

func (systemClock) Now() time.Time                         { return time.Now() }
func (systemClock) After(d time.Duration) <-chan time.Time { return time.After(d) }

// DeviceAuthorizationRequest is the input to RequestDeviceAuthorization.
type DeviceAuthorizationRequest struct {
	// Scopes are sent as one space-joined scope parameter.
	Scopes []string
	// Resources are RFC 8707 resource indicators, sent as one resource parameter each.
	Resources []string
}

// DeviceAuthorization is the device authorization response (RFC 8628 section 3.2).
// It is a plain value: a caller may persist it and poll from another process that
// authenticates as the same client.
type DeviceAuthorization struct {
	// DeviceCode is the code the device polls with. NEVER show it to the person.
	DeviceCode string `json:"device_code"`
	// UserCode is the code the person confirms. Always show it, so the person can
	// compare it with the confirmation page.
	UserCode string `json:"user_code"`
	// VerificationURI is where the person enters UserCode.
	VerificationURI string `json:"verification_uri"`
	// VerificationURIComplete is VerificationURI with UserCode filled in. Show it
	// instead of VerificationURI when it is set.
	VerificationURIComplete string `json:"verification_uri_complete,omitempty"`
	// ExpiresIn is the lifetime of DeviceCode and UserCode, in seconds.
	ExpiresIn int `json:"expires_in"`
	// Interval is the minimum wait between polls, in seconds. It is 5 when the
	// response omits it.
	Interval int `json:"interval"`
	// ExpiresAt is the time the response was received plus ExpiresIn, read from the
	// client's clock.
	ExpiresAt time.Time `json:"expires_at"`
}

// DeviceAuthorizationOption configures a DeviceAuthorizationClient.
type DeviceAuthorizationOption func(*deviceAuthorizationConfig)

type deviceAuthorizationConfig struct {
	credential   ClientAuthenticator
	clientID     string
	metadata     *AuthorizationServerMetadata
	httpClient   *http.Client
	clock        Clock
	discoveryTTL time.Duration
	negativeTTL  time.Duration
}

// WithDeviceCredential authenticates every request with the credential's client
// authentication. Set exactly one of WithDeviceCredential and WithDevicePublicClient.
func WithDeviceCredential(c ClientAuthenticator) DeviceAuthorizationOption {
	return func(cfg *deviceAuthorizationConfig) { cfg.credential = c }
}

// WithDevicePublicClient makes the client a public client: every request sends
// client_id in the body, with no other authentication. Set exactly one of
// WithDeviceCredential and WithDevicePublicClient.
func WithDevicePublicClient(clientID string) DeviceAuthorizationOption {
	return func(cfg *deviceAuthorizationConfig) { cfg.clientID = clientID }
}

// WithDeviceMetadata uses pre-discovered authorization server metadata. The client
// then makes no discovery request.
func WithDeviceMetadata(md *AuthorizationServerMetadata) DeviceAuthorizationOption {
	return func(cfg *deviceAuthorizationConfig) { cfg.metadata = md }
}

// WithDeviceHTTPClient sets the HTTP client for discovery and for requests to the
// authorization server.
func WithDeviceHTTPClient(c *http.Client) DeviceAuthorizationOption {
	return func(cfg *deviceAuthorizationConfig) { cfg.httpClient = c }
}

// WithDeviceClock sets the clock used for ExpiresAt, polling waits, and the discovery
// cache. Default: the system clock.
func WithDeviceClock(c Clock) DeviceAuthorizationOption {
	return func(cfg *deviceAuthorizationConfig) { cfg.clock = c }
}

// WithDeviceDiscoveryTTL sets how long discovered metadata is cached. Default: 1 hour.
func WithDeviceDiscoveryTTL(d time.Duration) DeviceAuthorizationOption {
	return func(cfg *deviceAuthorizationConfig) { cfg.discoveryTTL = d }
}

// WithDeviceNegativeTTL bounds how long a deterministic discovery failure (a 4xx other
// than 429, an issuer mismatch, or a malformed document) is remembered. It never
// exceeds the discovery TTL; a value <= 0 disables negative caching. Transient
// failures are never cached. Default: 1 minute.
func WithDeviceNegativeTTL(d time.Duration) DeviceAuthorizationOption {
	return func(cfg *deviceAuthorizationConfig) { cfg.negativeTTL = d }
}

// DeviceAuthorizationClient runs the OAuth 2.0 device authorization grant (RFC 8628)
// from the device's side. It reads device_authorization_endpoint and token_endpoint
// from discovery, or from metadata set with WithDeviceMetadata. It does not keep
// state between operations.
type DeviceAuthorizationClient struct {
	issuer   string
	cfg      deviceAuthorizationConfig
	metadata discoveryCache[*AuthorizationServerMetadata]
}

// NewDeviceAuthorizationClient creates a DeviceAuthorizationClient for issuer. With
// WithDeviceMetadata, issuer may be empty and defaults to the metadata's issuer. It
// returns a ConfigurationError when the client authentication is not exactly one of
// WithDeviceCredential and WithDevicePublicClient, when there is no issuer, or when
// issuer and the metadata's issuer differ.
func NewDeviceAuthorizationClient(issuer string, opts ...DeviceAuthorizationOption) (*DeviceAuthorizationClient, error) {
	cfg := deviceAuthorizationConfig{
		httpClient:   http.DefaultClient,
		clock:        systemClock{},
		discoveryTTL: defaultDiscoveryTTL,
		negativeTTL:  defaultNegativeTTL,
	}
	for _, opt := range opts {
		opt(&cfg)
	}

	hasCredential, hasClientID := cfg.credential != nil, cfg.clientID != ""
	if hasCredential == hasClientID {
		return nil, &ConfigurationError{Message: "device authorization requires exactly one of WithDeviceCredential and WithDevicePublicClient"}
	}
	if cfg.metadata != nil {
		if issuer == "" {
			issuer = cfg.metadata.Issuer
		} else if strings.TrimRight(issuer, "/") != strings.TrimRight(cfg.metadata.Issuer, "/") {
			return nil, &ConfigurationError{Message: fmt.Sprintf("issuer %q does not match the metadata issuer %q", issuer, cfg.metadata.Issuer)}
		}
	}
	if issuer == "" {
		return nil, &ConfigurationError{Message: "device authorization requires an issuer or metadata"}
	}

	c := &DeviceAuthorizationClient{
		issuer:   issuer,
		cfg:      cfg,
		metadata: newDiscoveryCache[*AuthorizationServerMetadata](cfg.discoveryTTL, cfg.negativeTTL, defaultFetchTimeout),
	}
	c.metadata.now = cfg.clock.Now
	return c, nil
}

// RequestDeviceAuthorization asks the zone for a device code and a user code. The
// caller shows the person VerificationURIComplete when it is set, and
// VerificationURI otherwise, together with UserCode.
//
// It returns a ConfigurationError, without sending a request, when the metadata has
// no device_authorization_endpoint, and an *OAuthError with code invalid_response
// when the response lacks device_code, user_code, verification_uri, or expires_in.
func (c *DeviceAuthorizationClient) RequestDeviceAuthorization(ctx context.Context, req DeviceAuthorizationRequest) (*DeviceAuthorization, error) {
	md, err := c.resolveMetadata(ctx)
	if err != nil {
		return nil, err
	}
	endpoint := md.DeviceAuthorizationEndpoint
	if endpoint == "" {
		return nil, &ConfigurationError{Message: fmt.Sprintf("authorization server %q does not advertise a device_authorization_endpoint", c.issuer)}
	}

	form := url.Values{}
	if len(req.Scopes) > 0 {
		form.Set("scope", strings.Join(req.Scopes, " "))
	}
	for _, r := range req.Resources {
		form.Add("resource", r)
	}

	resp, err := c.post(ctx, endpoint, form)
	if err != nil {
		return nil, fmt.Errorf("device authorization request failed: %w", err)
	}
	defer resp.Body.Close()

	if !isSuccess(resp.StatusCode) {
		return nil, errorFromResponse(resp, "device authorization endpoint")
	}
	return c.parseDeviceAuthorization(resp)
}

func (c *DeviceAuthorizationClient) parseDeviceAuthorization(resp *http.Response) (*DeviceAuthorization, error) {
	var da DeviceAuthorization
	if err := json.NewDecoder(resp.Body).Decode(&da); err != nil {
		return nil, &OAuthError{ErrorCode: "invalid_response", Message: "decoding device authorization response", Err: err}
	}
	var missing []string
	if da.DeviceCode == "" {
		missing = append(missing, "device_code")
	}
	if da.UserCode == "" {
		missing = append(missing, "user_code")
	}
	if da.VerificationURI == "" {
		missing = append(missing, "verification_uri")
	}
	if da.ExpiresIn <= 0 {
		missing = append(missing, "expires_in")
	}
	if len(missing) > 0 {
		return nil, &OAuthError{ErrorCode: "invalid_response", Message: "device authorization response is missing " + strings.Join(missing, ", ")}
	}
	if da.Interval <= 0 {
		da.Interval = int(defaultDevicePollInterval / time.Second)
	}
	da.ExpiresAt = c.cfg.clock.Now().Add(time.Duration(da.ExpiresIn) * time.Second)
	return &da, nil
}

// PollToken polls the token endpoint once with auth.DeviceCode. It returns the token
// when the person has approved. Otherwise it returns an *OAuthError with the server's
// code, including authorization_pending and slow_down.
func (c *DeviceAuthorizationClient) PollToken(ctx context.Context, auth DeviceAuthorization) (*TokenResponse, error) {
	if auth.DeviceCode == "" {
		return nil, &ConfigurationError{Message: "device authorization has no device_code"}
	}
	md, err := c.resolveMetadata(ctx)
	if err != nil {
		return nil, err
	}
	if md.TokenEndpoint == "" {
		return nil, &TokenEndpointDiscoveryError{Message: fmt.Sprintf("authorization server %q does not advertise a token_endpoint", c.issuer)}
	}

	form := url.Values{}
	form.Set("grant_type", deviceCodeGrantType)
	form.Set("device_code", auth.DeviceCode)

	resp, err := c.post(ctx, md.TokenEndpoint, form)
	if err != nil {
		return nil, fmt.Errorf("device token request failed: %w", err)
	}
	defer resp.Body.Close()

	if !isSuccess(resp.StatusCode) {
		return nil, errorFromResponse(resp, "token endpoint")
	}
	return deserializeTokenResponse(resp)
}

// WaitForToken polls until the person approves or denies the request, following
// RFC 8628 section 3.5:
//
//   - It waits Interval before each poll, including the first.
//   - On authorization_pending it polls again.
//   - On slow_down it adds 5 seconds to the interval for this and every later poll.
//   - On any other error, including a network error, a 5xx, or a 429, it stops and
//     returns the error. It does not retry.
//   - If the next poll would start after ExpiresAt, it stops without sending it and
//     returns an *OAuthError with code expired_token.
//
// Cancelling ctx stops the wait or the request in progress and returns ctx.Err().
// After a failure the caller may call WaitForToken again with the same auth until
// ExpiresAt. After a connection timeout, the caller MUST wait longer than Interval
// before it does (RFC 8628 section 3.5).
func (c *DeviceAuthorizationClient) WaitForToken(ctx context.Context, auth DeviceAuthorization) (*TokenResponse, error) {
	if auth.DeviceCode == "" {
		return nil, &ConfigurationError{Message: "device authorization has no device_code"}
	}
	if auth.ExpiresAt.IsZero() {
		return nil, &ConfigurationError{Message: "device authorization has no expires_at"}
	}
	interval := time.Duration(auth.Interval) * time.Second
	if interval <= 0 {
		interval = defaultDevicePollInterval
	}

	for {
		if c.cfg.clock.Now().Add(interval).After(auth.ExpiresAt) {
			return nil, &OAuthError{ErrorCode: "expired_token", Message: "the device code expired before the request was approved"}
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-c.cfg.clock.After(interval):
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		token, err := c.PollToken(ctx, auth)
		if err == nil {
			return token, nil
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		var oauthErr *OAuthError
		if !errors.As(err, &oauthErr) {
			return nil, err
		}
		switch oauthErr.ErrorCode {
		case "authorization_pending":
		case "slow_down":
			interval += deviceSlowDownIncrement
		default:
			return nil, err
		}
	}
}

func (c *DeviceAuthorizationClient) resolveMetadata(ctx context.Context) (*AuthorizationServerMetadata, error) {
	if c.cfg.metadata != nil {
		return c.cfg.metadata, nil
	}
	md, err := c.metadata.get(ctx, func(fetchCtx context.Context) (*AuthorizationServerMetadata, error) {
		return FetchAuthorizationServerMetadata(fetchCtx, c.issuer, WithDiscoveryHTTPClient(c.cfg.httpClient))
	})
	if err != nil {
		return nil, fmt.Errorf("discovering authorization server metadata for %q: %w", c.issuer, err)
	}
	return md, nil
}

// post sends form to endpoint with the client authentication added.
func (c *DeviceAuthorizationClient) post(ctx context.Context, endpoint string, form url.Values) (*http.Response, error) {
	header := http.Header{}
	if c.cfg.credential != nil {
		auth, err := c.cfg.credential.ClientAuthentication(ctx, c.issuer, endpoint)
		if err != nil {
			return nil, fmt.Errorf("client authentication: %w", err)
		}
		for k, vs := range auth.Form {
			for _, v := range vs {
				form.Add(k, v)
			}
		}
		for k, vs := range auth.Header {
			for _, v := range vs {
				header.Add(k, v)
			}
		}
	} else {
		form.Set("client_id", c.cfg.clientID)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header = header
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	return c.cfg.httpClient.Do(req)
}

func isSuccess(status int) bool { return status >= 200 && status < 300 }

// errorFromResponse returns an *OAuthError for an RFC 6749 section 5.2 error body, and
// an *HTTPError otherwise.
func errorFromResponse(resp *http.Response, what string) error {
	if oauthErr := parseOAuthErrorResponse(resp); oauthErr != nil {
		return oauthErr
	}
	return &HTTPError{Message: what + " returned an error", Status: resp.StatusCode}
}
