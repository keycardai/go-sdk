package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
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
	credential     ApplicationCredential
	clientID       string
	metadata       *AuthorizationServerMetadata
	httpClient     *http.Client
	clock          Clock
	discoveryTTL   time.Duration
	negativeTTL    time.Duration
	requestTimeout time.Duration
}

// WithDeviceCredential authenticates every request with the credential's client
// authentication. The credential must implement [ClientAuthenticator]. Set exactly one
// of WithDeviceCredential and WithDevicePublicClient.
func WithDeviceCredential(c ApplicationCredential) DeviceAuthorizationOption {
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

// WithDeviceRequestTimeout bounds each request to the authorization server when the
// caller's context has no deadline of its own: discovery, the device authorization
// request, and each poll. It does not bound the wait between polls or the whole
// WaitForToken loop. Default: 10 seconds.
func WithDeviceRequestTimeout(d time.Duration) DeviceAuthorizationOption {
	return func(cfg *deviceAuthorizationConfig) { cfg.requestTimeout = d }
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
	issuer        string
	cfg           deviceAuthorizationConfig
	authenticator ClientAuthenticator
	metadata      discoveryCache[*AuthorizationServerMetadata]
}

// NewDeviceAuthorizationClient creates a DeviceAuthorizationClient for issuer. With
// WithDeviceMetadata, issuer may be empty and defaults to the metadata's issuer. It
// returns a ConfigurationError when the client authentication is not exactly one of
// WithDeviceCredential and WithDevicePublicClient, when the credential does not
// implement [ClientAuthenticator], when there is no issuer, or when issuer and the
// metadata's issuer differ.
func NewDeviceAuthorizationClient(issuer string, opts ...DeviceAuthorizationOption) (*DeviceAuthorizationClient, error) {
	cfg := deviceAuthorizationConfig{
		httpClient:     http.DefaultClient,
		clock:          systemClock{},
		discoveryTTL:   defaultDiscoveryTTL,
		negativeTTL:    defaultNegativeTTL,
		requestTimeout: defaultFetchTimeout,
	}
	for _, opt := range opts {
		opt(&cfg)
	}

	hasCredential, hasClientID := cfg.credential != nil, cfg.clientID != ""
	if hasCredential == hasClientID {
		return nil, &ConfigurationError{Message: "device authorization requires exactly one of WithDeviceCredential and WithDevicePublicClient"}
	}
	var authenticator ClientAuthenticator
	var err error
	if hasCredential {
		if authenticator, err = clientAuthenticator(cfg.credential); err != nil {
			return nil, err
		}
	}
	if issuer, err = issuerOrMetadata(issuer, cfg.metadata); err != nil {
		return nil, err
	}

	c := &DeviceAuthorizationClient{
		issuer:        issuer,
		cfg:           cfg,
		authenticator: authenticator,
		metadata:      newDiscoveryCache[*AuthorizationServerMetadata](cfg.discoveryTTL, cfg.negativeTTL, cfg.requestTimeout),
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

	ctx, cancel := withDefaultTimeout(ctx, c.cfg.requestTimeout)
	defer cancel()
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
	da.ExpiresAt = c.cfg.clock.Now().Add(secondsToDuration(da.ExpiresIn))
	return &da, nil
}

// secondsToDuration converts a server-supplied count of seconds to a Duration. Values
// too large for a Duration become the largest Duration.
func secondsToDuration(s int) time.Duration {
	if int64(s) > math.MaxInt64/int64(time.Second) {
		return math.MaxInt64
	}
	return time.Duration(s) * time.Second
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

	ctx, cancel := withDefaultTimeout(ctx, c.cfg.requestTimeout)
	defer cancel()
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

// WaitForTokenOption configures one WaitForToken call.
type WaitForTokenOption func(*waitForTokenConfig)

type waitForTokenConfig struct {
	startInterval time.Duration
}

// WithStartInterval sets the wait before the first poll and the starting interval.
// Use it to resume with the Interval of a [DevicePollError]. It must not be shorter
// than the DeviceAuthorization's Interval.
func WithStartInterval(d time.Duration) WaitForTokenOption {
	return func(cfg *waitForTokenConfig) { cfg.startInterval = d }
}

// DevicePollError is the error WaitForToken returns when a poll fails with anything
// other than an *OAuthError, such as a network error, a 5xx, or a 429. Interval is
// the wait the loop would have used before its next poll, including every slow_down
// increase. To resume, call WaitForToken with the same DeviceAuthorization and
// WithStartInterval(Interval).
type DevicePollError struct {
	Interval time.Duration
	Err      error
}

func (e *DevicePollError) Error() string {
	return fmt.Sprintf("device token poll failed (next interval %s): %v", e.Interval, e.Err)
}

func (e *DevicePollError) Unwrap() error { return e.Err }

// WaitForToken polls until the person approves or denies the request, following
// RFC 8628 section 3.5:
//
//   - It waits the interval before each poll, including the first. The interval
//     starts at auth.Interval, or at WithStartInterval when set.
//   - On authorization_pending it polls again.
//   - On slow_down it adds 5 seconds to the interval for this and every later poll.
//   - On any other *OAuthError it stops and returns it.
//   - On any other failure, including a network error, a 5xx, or a 429, it stops and
//     returns a *DevicePollError. It does not poll again.
//   - If the next poll would start after ExpiresAt, it stops without waiting or
//     sending it, and returns an *OAuthError with code expired_token.
//
// The request timeout set with WithDeviceRequestTimeout bounds each poll. It does not
// bound the wait between polls or the whole loop. A poll that times out is a
// *DevicePollError, and errors.Is(err, context.DeadlineExceeded) holds.
//
// Polling again on authorization_pending and slow_down is the grant itself, not a
// retry.
//
// Cancelling ctx stops the wait or the request in progress and returns ctx.Err().
// After a *DevicePollError the caller may resume until ExpiresAt. After a connection
// timeout, the caller MUST wait longer than the error's Interval before it does
// (RFC 8628 section 3.5).
//
// When the device authorization request named more than one resource, the token is
// not for any one of them. NEVER store it as the token for one resource. To get a
// token for one resource, call [RefreshAuthorization] with that resource.
func (c *DeviceAuthorizationClient) WaitForToken(ctx context.Context, auth DeviceAuthorization, opts ...WaitForTokenOption) (*TokenResponse, error) {
	if auth.DeviceCode == "" {
		return nil, &ConfigurationError{Message: "device authorization has no device_code"}
	}
	if auth.ExpiresAt.IsZero() {
		return nil, &ConfigurationError{Message: "device authorization has no expires_at"}
	}
	var cfg waitForTokenConfig
	for _, opt := range opts {
		opt(&cfg)
	}
	interval := defaultDevicePollInterval
	if auth.Interval > 0 {
		interval = secondsToDuration(auth.Interval)
	}
	if cfg.startInterval != 0 {
		if cfg.startInterval < interval {
			return nil, &ConfigurationError{Message: fmt.Sprintf("start interval %s is shorter than the device authorization interval %s", cfg.startInterval, interval)}
		}
		interval = cfg.startInterval
	}

	for {
		if interval > auth.ExpiresAt.Sub(c.cfg.clock.Now()) {
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
		if c.cfg.clock.Now().After(auth.ExpiresAt) {
			return nil, &OAuthError{ErrorCode: "expired_token", Message: "the device code expired before the request was approved"}
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
			return nil, &DevicePollError{Interval: interval, Err: err}
		}
		switch oauthErr.ErrorCode {
		case "authorization_pending":
		case "slow_down":
			if interval > math.MaxInt64-deviceSlowDownIncrement {
				interval = math.MaxInt64
			} else {
				interval += deviceSlowDownIncrement
			}
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
	if c.authenticator != nil {
		if err := addClientAuthentication(ctx, c.authenticator, c.issuer, endpoint, header, form); err != nil {
			return nil, err
		}
	} else {
		form.Set("client_id", c.cfg.clientID)
	}
	return postForm(ctx, c.cfg.httpClient, endpoint, header, form)
}

// postForm sends form to endpoint with header and asks for a JSON response.
func postForm(ctx context.Context, httpClient *http.Client, endpoint string, header http.Header, form url.Values) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header = header
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	return httpClient.Do(req)
}

// issuerOrMetadata returns issuer, or the metadata's issuer when issuer is empty. It
// returns a ConfigurationError when both are empty, or when they differ by more than a
// trailing slash.
func issuerOrMetadata(issuer string, md *AuthorizationServerMetadata) (string, error) {
	if md != nil {
		if issuer == "" {
			issuer = md.Issuer
		} else if strings.TrimRight(issuer, "/") != strings.TrimRight(md.Issuer, "/") {
			return "", &ConfigurationError{Message: fmt.Sprintf("issuer %q does not match the metadata issuer %q", issuer, md.Issuer)}
		}
	}
	if issuer == "" {
		return "", &ConfigurationError{Message: "an issuer or metadata is required"}
	}
	return issuer, nil
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
