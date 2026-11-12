package oauth

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	deviceCodeGrantType = "urn:ietf:params:oauth:grant-type:device_code"
	// defaultDevicePollInterval is the poll interval, in seconds, when the device
	// authorization response omits interval (RFC 8628 section 3.2).
	defaultDevicePollInterval = 5
)

// DeviceClock supplies the current time and timers to a DeviceAuthorizationClient.
// Inject a fake in tests so that expiry does not depend on real time.
type DeviceClock interface {
	Now() time.Time
	// After returns a channel that receives the time after d, as time.After.
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
// It is a plain value. Persist it, for example as JSON, to poll from another process
// that authenticates as the same client.
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

// deviceAuthorizationResponse is the wire format of the device authorization
// response. Interval is a pointer so that an absent interval and an interval of 0
// differ.
type deviceAuthorizationResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                *int   `json:"interval"`
}

// DeviceAuthorizationOption configures a DeviceAuthorizationClient.
type DeviceAuthorizationOption func(*deviceAuthorizationConfig)

type deviceAuthorizationConfig struct {
	credential     ApplicationCredential
	clientID       string
	metadata       *AuthorizationServerMetadata
	httpClient     *http.Client
	clock          DeviceClock
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
// then does not send a discovery request.
func WithDeviceMetadata(md *AuthorizationServerMetadata) DeviceAuthorizationOption {
	return func(cfg *deviceAuthorizationConfig) { cfg.metadata = md }
}

// WithDeviceHTTPClient sets the HTTP client for discovery and for requests to the
// authorization server.
func WithDeviceHTTPClient(c *http.Client) DeviceAuthorizationOption {
	return func(cfg *deviceAuthorizationConfig) { cfg.httpClient = c }
}

// WithDeviceClock sets the clock used for ExpiresAt and the discovery cache. Default:
// the system clock.
func WithDeviceClock(c DeviceClock) DeviceAuthorizationOption {
	return func(cfg *deviceAuthorizationConfig) { cfg.clock = c }
}

// WithDeviceRequestTimeout bounds each request to the authorization server: discovery,
// the device authorization request, and each poll. It applies even when the caller's
// context has a later deadline. A caller deadline that ends sooner still applies. It
// also covers the credential's client authentication for that request. It must be
// positive. Default: 10 seconds.
func WithDeviceRequestTimeout(d time.Duration) DeviceAuthorizationOption {
	return func(cfg *deviceAuthorizationConfig) { cfg.requestTimeout = d }
}

// WithDeviceDiscoveryTTL sets how long discovered metadata is cached. Default: 1 hour.
func WithDeviceDiscoveryTTL(d time.Duration) DeviceAuthorizationOption {
	return func(cfg *deviceAuthorizationConfig) { cfg.discoveryTTL = d }
}

// WithDeviceNegativeTTL bounds how long a deterministic discovery failure (a 4xx other
// than 429, an issuer mismatch, or a malformed document) is remembered. It never
// exceeds the discovery TTL. A value <= 0 disables negative caching. Transient
// failures are never cached. Default: 1 minute.
func WithDeviceNegativeTTL(d time.Duration) DeviceAuthorizationOption {
	return func(cfg *deviceAuthorizationConfig) { cfg.negativeTTL = d }
}

// DeviceAuthorizationClient runs the OAuth 2.0 device authorization grant (RFC 8628)
// from the device's side. It reads device_authorization_endpoint and token_endpoint
// from discovery, or from metadata set with WithDeviceMetadata. It does not keep
// state between operations, other than the discovery cache.
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
// implement [ClientAuthenticator], when there is no issuer, when issuer and the
// metadata's issuer differ, when the clock is nil, or when the request timeout is not
// positive.
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
	if cfg.clock == nil {
		return nil, &ConfigurationError{Message: "device clock must not be nil"}
	}
	if cfg.requestTimeout <= 0 {
		return nil, &ConfigurationError{Message: fmt.Sprintf("device request timeout %s is not positive", cfg.requestTimeout)}
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

// RequestDeviceAuthorization asks the zone for a device code and a user code. Show the
// person VerificationURIComplete when it is set, and VerificationURI otherwise,
// together with UserCode.
//
// A failed discovery is a *DeviceAuthorizationDiscoveryError. Metadata whose
// device_authorization_endpoint or token_endpoint is missing, or is not an http or
// https URL, is a ConfigurationError, and the request is not sent. An OAuth error
// response is an *OAuthError. Any other non-2xx response is an *HTTPError. A 2xx
// response that is not valid JSON, lacks device_code, user_code, verification_uri, or
// expires_in, or has an interval that is not a positive integer is an *OAuthError with
// code invalid_response.
func (c *DeviceAuthorizationClient) RequestDeviceAuthorization(ctx context.Context, req DeviceAuthorizationRequest) (*DeviceAuthorization, error) {
	md, err := c.resolveMetadata(ctx)
	if err != nil {
		return nil, err
	}
	endpoint := md.DeviceAuthorizationEndpoint

	form := url.Values{}
	if len(req.Scopes) > 0 {
		form.Set("scope", strings.Join(req.Scopes, " "))
	}
	for _, r := range req.Resources {
		form.Add("resource", r)
	}

	ctx, cancel := c.withRequestTimeout(ctx)
	defer cancel()
	header := http.Header{}
	if err := c.authenticate(ctx, endpoint, header, form); err != nil {
		return nil, err
	}
	resp, _, err := c.postForm(ctx, endpoint, header, form)
	if err != nil {
		return nil, fmt.Errorf("device authorization request failed: %w", err)
	}

	if !isSuccess(resp.StatusCode) {
		return nil, errorFromResponse(resp, "device authorization endpoint")
	}
	return c.parseDeviceAuthorization(resp)
}

func (c *DeviceAuthorizationClient) parseDeviceAuthorization(resp *http.Response) (*DeviceAuthorization, error) {
	var body deviceAuthorizationResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, &OAuthError{ErrorCode: "invalid_response", Message: "decoding device authorization response", Err: err}
	}
	var missing []string
	if body.DeviceCode == "" {
		missing = append(missing, "device_code")
	}
	if body.UserCode == "" {
		missing = append(missing, "user_code")
	}
	if body.VerificationURI == "" {
		missing = append(missing, "verification_uri")
	}
	if body.ExpiresIn <= 0 {
		missing = append(missing, "expires_in")
	}
	if len(missing) > 0 {
		return nil, &OAuthError{ErrorCode: "invalid_response", Message: "device authorization response is missing " + strings.Join(missing, ", ")}
	}
	interval := defaultDevicePollInterval
	if body.Interval != nil {
		if *body.Interval <= 0 {
			return nil, &OAuthError{ErrorCode: "invalid_response", Message: fmt.Sprintf("device authorization response has interval %d, want a positive integer", *body.Interval)}
		}
		interval = *body.Interval
	}
	return &DeviceAuthorization{
		DeviceCode:              body.DeviceCode,
		UserCode:                body.UserCode,
		VerificationURI:         body.VerificationURI,
		VerificationURIComplete: body.VerificationURIComplete,
		ExpiresIn:               body.ExpiresIn,
		Interval:                interval,
		ExpiresAt:               c.cfg.clock.Now().Add(secondsToDuration(body.ExpiresIn)),
	}, nil
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
// when the person has approved. An OAuth error response is an *OAuthError with the
// server's code and error_description, including authorization_pending and
// slow_down. Any other non-2xx response is an *HTTPError. A 2xx response that is not
// a valid token response is an *OAuthError with code invalid_response.
//
// It returns the same discovery and configuration errors as
// RequestDeviceAuthorization.
//
// To call PollToken in your own loop, wait at least auth.Interval between polls, add 5
// seconds on slow_down, and wait longer after a connection timeout (RFC 8628 section
// 3.5).
func (c *DeviceAuthorizationClient) PollToken(ctx context.Context, auth DeviceAuthorization) (*TokenResponse, error) {
	if auth.DeviceCode == "" {
		return nil, &ConfigurationError{Message: "device authorization has no device_code"}
	}
	md, err := c.resolveMetadata(ctx)
	if err != nil {
		return nil, err
	}
	return c.poll(ctx, md, auth)
}

func (c *DeviceAuthorizationClient) poll(ctx context.Context, md *AuthorizationServerMetadata, auth DeviceAuthorization) (*TokenResponse, error) {
	form := url.Values{}
	form.Set("grant_type", deviceCodeGrantType)
	form.Set("device_code", auth.DeviceCode)

	ctx, cancel := c.withRequestTimeout(ctx)
	defer cancel()
	header := http.Header{}
	if err := c.authenticate(ctx, md.TokenEndpoint, header, form); err != nil {
		return nil, err
	}
	resp, _, err := c.postForm(ctx, md.TokenEndpoint, header, form)
	if err != nil {
		return nil, fmt.Errorf("device token request failed: %w", err)
	}

	if !isSuccess(resp.StatusCode) {
		return nil, errorFromResponse(resp, "token endpoint")
	}
	token, err := deserializeTokenResponse(resp)
	if err != nil {
		return nil, &OAuthError{ErrorCode: "invalid_response", Message: "invalid token response", Err: err}
	}
	return token, nil
}

// resolveMetadata returns the metadata set with WithDeviceMetadata, or the discovered
// metadata. Both must pass checkDeviceMetadata. Discovered metadata that fails the
// check is cached as a deterministic failure, for at most the negative TTL.
func (c *DeviceAuthorizationClient) resolveMetadata(ctx context.Context) (*AuthorizationServerMetadata, error) {
	if c.cfg.metadata != nil {
		if err := checkDeviceMetadata(c.issuer, c.cfg.metadata); err != nil {
			return nil, err
		}
		return c.cfg.metadata, nil
	}
	md, err := c.metadata.get(ctx, func(fetchCtx context.Context) (*AuthorizationServerMetadata, error) {
		md, err := FetchAuthorizationServerMetadata(fetchCtx, c.issuer, WithDiscoveryHTTPClient(c.cfg.httpClient))
		if err != nil {
			return nil, err
		}
		if err := checkDeviceMetadata(c.issuer, md); err != nil {
			return nil, err
		}
		return md, nil
	})
	var cfgErr *ConfigurationError
	switch {
	case errors.As(err, &cfgErr):
		return nil, err
	case err != nil:
		return nil, &DeviceAuthorizationDiscoveryError{Message: fmt.Sprintf("discovering authorization server metadata for %q", c.issuer), Err: err}
	}
	return md, nil
}

// checkDeviceMetadata returns a ConfigurationError unless md has a
// device_authorization_endpoint and a token_endpoint that are http or https URLs.
func checkDeviceMetadata(issuer string, md *AuthorizationServerMetadata) error {
	for _, ep := range []struct{ name, url string }{
		{"device_authorization_endpoint", md.DeviceAuthorizationEndpoint},
		{"token_endpoint", md.TokenEndpoint},
	} {
		if ep.url == "" {
			return &ConfigurationError{Message: fmt.Sprintf("authorization server %q does not advertise a %s", issuer, ep.name)}
		}
		if err := checkEndpoint(ep.name, ep.url); err != nil {
			return err
		}
	}
	return nil
}

// DeviceAuthorizationClient returns a DeviceAuthorizationDiscoveryError when it cannot
// fetch the authorization server metadata. Err is the cause, such as an *HTTPError, an
// *IssuerMismatchError, or a network error.
type DeviceAuthorizationDiscoveryError struct {
	Message string
	Err     error
}

func (e *DeviceAuthorizationDiscoveryError) Error() string {
	if e.Err != nil {
		return e.Message + ": " + e.Err.Error()
	}
	return e.Message
}
func (e *DeviceAuthorizationDiscoveryError) Unwrap() error { return e.Err }
func (*DeviceAuthorizationDiscoveryError) keycardError()   {}

// authenticate adds the client authentication for a request to endpoint.
func (c *DeviceAuthorizationClient) authenticate(ctx context.Context, endpoint string, header http.Header, form url.Values) error {
	if c.authenticator == nil {
		form.Set("client_id", c.cfg.clientID)
		return nil
	}
	return addClientAuthentication(ctx, c.authenticator, c.issuer, endpoint, header, form)
}

func (c *DeviceAuthorizationClient) withRequestTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, c.cfg.requestTimeout)
}

// postForm sends form to endpoint and reads the whole response body. network is true
// when the request failed in transport, including a timeout or a failure while
// reading the body. A body that fails to decompress is a malformed response, not a
// network error: postForm returns the response, and reading its Body returns the
// decompression error.
func (c *DeviceAuthorizationClient) postForm(ctx context.Context, endpoint string, header http.Header, form url.Values) (resp *http.Response, network bool, err error) {
	req, err := newFormRequest(ctx, endpoint, header, form)
	if err != nil {
		return nil, false, err
	}
	resp, err = c.cfg.httpClient.Do(req)
	if err != nil {
		return nil, true, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	switch {
	case isCorruptCompression(err):
		resp.Body = io.NopCloser(errReader{fmt.Errorf("reading response: %w", err)})
	case err != nil:
		return nil, true, fmt.Errorf("reading response: %w", err)
	default:
		resp.Body = io.NopCloser(bytes.NewReader(body))
	}
	return resp, false, nil
}

// isCorruptCompression reports whether err is from a gzip body that does not
// decompress. net/http decompresses a gzip response while the body is read.
func isCorruptCompression(err error) bool {
	var corrupt flate.CorruptInputError
	return errors.Is(err, gzip.ErrHeader) || errors.Is(err, gzip.ErrChecksum) || errors.As(err, &corrupt)
}

// errReader is a Body whose every Read returns err.
type errReader struct{ err error }

func (r errReader) Read([]byte) (int, error) { return 0, r.err }

// checkEndpoint returns a ConfigurationError when endpoint is not an absolute http or
// https URL.
func checkEndpoint(name, endpoint string) error {
	u, err := url.Parse(endpoint)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return &ConfigurationError{Message: fmt.Sprintf("%s %q is not an http or https URL", name, endpoint)}
	}
	return nil
}
