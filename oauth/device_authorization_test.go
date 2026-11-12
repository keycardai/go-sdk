package oauth

import (
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"sync"
	"testing"
	"time"
)

// fakeDeviceClock advances only when the code under test waits.
type fakeDeviceClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeDeviceClock() *fakeDeviceClock {
	return &fakeDeviceClock{now: time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)}
}

func (c *fakeDeviceClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeDeviceClock) After(d time.Duration) <-chan time.Time {
	c.mu.Lock()
	c.now = c.now.Add(d)
	now := c.now
	c.mu.Unlock()
	ch := make(chan time.Time, 1)
	ch <- now
	return ch
}

func mustDeviceClient(t *testing.T, issuer string, opts ...DeviceAuthorizationOption) *DeviceAuthorizationClient {
	t.Helper()
	c, err := NewDeviceAuthorizationClient(issuer, opts...)
	if err != nil {
		t.Fatalf("NewDeviceAuthorizationClient: %v", err)
	}
	return c
}

func TestNewDeviceAuthorizationClient_Configuration(t *testing.T) {
	md := &AuthorizationServerMetadata{Issuer: "https://zone.example.com", TokenEndpoint: "https://zone.example.com/token"}
	cases := map[string]struct {
		issuer     string
		opts       []DeviceAuthorizationOption
		wantErr    bool
		wantIssuer string
	}{
		"credential and client id": {
			issuer:  "https://zone.example.com",
			opts:    []DeviceAuthorizationOption{WithDeviceCredential(&fakeAuthenticator{}), WithDevicePublicClient("public-1")},
			wantErr: true,
		},
		"neither credential nor client id": {
			issuer:  "https://zone.example.com",
			wantErr: true,
		},
		"credential without client authentication": {
			issuer:  "https://zone.example.com",
			opts:    []DeviceAuthorizationOption{WithDeviceCredential(noClientAuthentication{})},
			wantErr: true,
		},
		"no issuer and no metadata": {
			opts:    []DeviceAuthorizationOption{WithDevicePublicClient("public-1")},
			wantErr: true,
		},
		"issuer differs from the metadata issuer": {
			issuer:  "https://other.example.com",
			opts:    []DeviceAuthorizationOption{WithDevicePublicClient("public-1"), WithDeviceMetadata(md)},
			wantErr: true,
		},
		"zero request timeout": {
			issuer:  "https://zone.example.com",
			opts:    []DeviceAuthorizationOption{WithDevicePublicClient("public-1"), WithDeviceRequestTimeout(0)},
			wantErr: true,
		},
		"negative request timeout": {
			issuer:  "https://zone.example.com",
			opts:    []DeviceAuthorizationOption{WithDevicePublicClient("public-1"), WithDeviceRequestTimeout(-time.Second)},
			wantErr: true,
		},
		"nil clock": {
			issuer:  "https://zone.example.com",
			opts:    []DeviceAuthorizationOption{WithDevicePublicClient("public-1"), WithDeviceClock(nil)},
			wantErr: true,
		},
		"metadata without an issuer argument": {
			opts:       []DeviceAuthorizationOption{WithDevicePublicClient("public-1"), WithDeviceMetadata(md)},
			wantIssuer: "https://zone.example.com",
		},
		"issuer matching the metadata issuer up to a trailing slash": {
			issuer:     "https://zone.example.com/",
			opts:       []DeviceAuthorizationOption{WithDevicePublicClient("public-1"), WithDeviceMetadata(md)},
			wantIssuer: "https://zone.example.com/",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			c, err := NewDeviceAuthorizationClient(tc.issuer, tc.opts...)
			if tc.wantErr {
				var cfgErr *ConfigurationError
				if !errors.As(err, &cfgErr) {
					t.Fatalf("error: got %v, want *ConfigurationError", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("NewDeviceAuthorizationClient: %v", err)
			}
			if c.issuer != tc.wantIssuer {
				t.Errorf("issuer: got %q, want %q", c.issuer, tc.wantIssuer)
			}
		})
	}
}

func TestRequestDeviceAuthorization_Request(t *testing.T) {
	cases := map[string]struct {
		public        bool
		useMetadata   bool
		req           DeviceAuthorizationRequest
		wantForm      url.Values
		wantHeader    http.Header
		wantDiscovery int32
	}{
		"credential with scopes and two resources": {
			req: DeviceAuthorizationRequest{
				Scopes:    []string{"openid", "profile"},
				Resources: []string{"https://api-1.example.com", "https://api-2.example.com"},
			},
			wantForm: url.Values{
				"scope":                 {"openid profile"},
				"resource":              {"https://api-1.example.com", "https://api-2.example.com"},
				"client_assertion":      {"assertion-1"},
				"client_assertion_type": {clientAssertionTypeJWTBearer},
			},
			wantHeader:    withAuthorization(formHeader, "Basic Y2xpZW50OnNlY3JldA=="),
			wantDiscovery: 1,
		},
		"public client": {
			public:        true,
			wantForm:      url.Values{"client_id": {"public-1"}},
			wantHeader:    formHeader,
			wantDiscovery: 1,
		},
		"pre-discovered metadata makes no discovery request": {
			public:        true,
			useMetadata:   true,
			wantForm:      url.Values{"client_id": {"public-1"}},
			wantHeader:    formHeader,
			wantDiscovery: 0,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			zone := newFakeZone(t)
			cred := &fakeAuthenticator{}
			opts := []DeviceAuthorizationOption{WithDeviceHTTPClient(zone.httpClient()), WithDeviceClock(newFakeDeviceClock())}
			if tc.public {
				opts = append(opts, WithDevicePublicClient("public-1"))
			} else {
				opts = append(opts, WithDeviceCredential(cred))
			}
			if tc.useMetadata {
				opts = append(opts, WithDeviceMetadata(zone.metadata()))
			}
			client := mustDeviceClient(t, zone.URL, opts...)

			if _, err := client.RequestDeviceAuthorization(context.Background(), tc.req); err != nil {
				t.Fatalf("RequestDeviceAuthorization: %v", err)
			}

			calls := zone.deviceCalls()
			if len(calls) != 1 {
				t.Fatalf("device authorization requests: got %d, want 1", len(calls))
			}
			if !reflect.DeepEqual(calls[0].form, tc.wantForm) {
				t.Errorf("form: got %v, want %v", calls[0].form, tc.wantForm)
			}
			if !reflect.DeepEqual(calls[0].header, tc.wantHeader) {
				t.Errorf("header: got %v, want %v", calls[0].header, tc.wantHeader)
			}
			if got := zone.discoveryRequests.Load(); got != tc.wantDiscovery {
				t.Errorf("discovery requests: got %d, want %d", got, tc.wantDiscovery)
			}
			if !tc.public {
				want := [][2]string{{zone.URL, zone.URL + "/device/authorize"}}
				if got := cred.recordedCalls(); !reflect.DeepEqual(got, want) {
					t.Errorf("credential calls: got %v, want %v", got, want)
				}
			}
		})
	}
}

// Metadata without a usable device_authorization_endpoint or token_endpoint is a
// configuration error. The client does not send a device authorization request or
// call the credential.
func TestRequestDeviceAuthorization_BadMetadata(t *testing.T) {
	cases := map[string]struct {
		// discovered uses discovery with the zone's device endpoint left out. Otherwise
		// edit changes pre-discovered metadata.
		discovered bool
		edit       func(md *AuthorizationServerMetadata)
	}{
		"discovered metadata without the device endpoint": {discovered: true},
		"metadata without the device endpoint": {
			edit: func(md *AuthorizationServerMetadata) { md.DeviceAuthorizationEndpoint = "" },
		},
		"device endpoint without a scheme": {
			edit: func(md *AuthorizationServerMetadata) {
				md.DeviceAuthorizationEndpoint = "zone.example.com/device/authorize"
			},
		},
		"device endpoint with another scheme": {
			edit: func(md *AuthorizationServerMetadata) {
				md.DeviceAuthorizationEndpoint = "ftp://zone.example.com/device/authorize"
			},
		},
		"device endpoint that does not parse": {
			edit: func(md *AuthorizationServerMetadata) { md.DeviceAuthorizationEndpoint = "://bad" },
		},
		"metadata without the token endpoint": {
			edit: func(md *AuthorizationServerMetadata) { md.TokenEndpoint = "" },
		},
		"token endpoint with another scheme": {
			edit: func(md *AuthorizationServerMetadata) { md.TokenEndpoint = "ftp://zone.example.com/token" },
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			zone := newFakeZone(t)
			cred := &fakeAuthenticator{}
			opts := []DeviceAuthorizationOption{WithDeviceHTTPClient(zone.httpClient()), WithDeviceCredential(cred)}
			if tc.discovered {
				zone.omitDeviceEndpoint.Store(true)
			} else {
				md := zone.metadata()
				tc.edit(md)
				opts = append(opts, WithDeviceMetadata(md))
			}
			client := mustDeviceClient(t, zone.URL, opts...)

			_, err := client.RequestDeviceAuthorization(context.Background(), DeviceAuthorizationRequest{})
			var cfgErr *ConfigurationError
			if !errors.As(err, &cfgErr) {
				t.Fatalf("error: got %v (%T), want *ConfigurationError", err, err)
			}
			if n := len(zone.deviceCalls()); n != 0 {
				t.Errorf("device authorization requests: got %d, want 0", n)
			}
			if n := len(cred.recordedCalls()); n != 0 {
				t.Errorf("credential calls: got %d, want 0", n)
			}
		})
	}
}

func TestRequestDeviceAuthorization_Response(t *testing.T) {
	full := func() map[string]any {
		return map[string]any{
			"device_code":               "device-code-1",
			"user_code":                 "WDJB-MJHT",
			"verification_uri":          "https://zone.example.com/device",
			"verification_uri_complete": "https://zone.example.com/device?user_code=WDJB-MJHT",
			"expires_in":                600,
			"interval":                  10,
		}
	}
	without := func(field string) map[string]any {
		m := full()
		delete(m, field)
		return m
	}
	with := func(field string, value any) map[string]any {
		m := full()
		m[field] = value
		return m
	}
	clockStart := newFakeDeviceClock().Now()

	cases := map[string]struct {
		status   int
		body     any
		want     *DeviceAuthorization
		wantCode string
		wantHTTP int
		// wantCause, when set, is an error the returned error wraps.
		wantCause error
	}{
		"full response": {
			status: http.StatusOK,
			body:   full(),
			want: &DeviceAuthorization{
				DeviceCode:              "device-code-1",
				UserCode:                "WDJB-MJHT",
				VerificationURI:         "https://zone.example.com/device",
				VerificationURIComplete: "https://zone.example.com/device?user_code=WDJB-MJHT",
				ExpiresIn:               600,
				Interval:                10,
				ExpiresAt:               clockStart.Add(600 * time.Second),
			},
		},
		"interval omitted defaults to 5": {
			status: http.StatusOK,
			body:   without("interval"),
			want: &DeviceAuthorization{
				DeviceCode:              "device-code-1",
				UserCode:                "WDJB-MJHT",
				VerificationURI:         "https://zone.example.com/device",
				VerificationURIComplete: "https://zone.example.com/device?user_code=WDJB-MJHT",
				ExpiresIn:               600,
				Interval:                5,
				ExpiresAt:               clockStart.Add(600 * time.Second),
			},
		},
		"missing device_code":      {status: http.StatusOK, body: without("device_code"), wantCode: "invalid_response"},
		"missing user_code":        {status: http.StatusOK, body: without("user_code"), wantCode: "invalid_response"},
		"missing verification_uri": {status: http.StatusOK, body: without("verification_uri"), wantCode: "invalid_response"},
		"missing expires_in":       {status: http.StatusOK, body: without("expires_in"), wantCode: "invalid_response"},
		"body is not an object":    {status: http.StatusOK, body: "not an object", wantCode: "invalid_response"},
		"interval 0":               {status: http.StatusOK, body: with("interval", 0), wantCode: "invalid_response"},
		"interval -1":              {status: http.StatusOK, body: with("interval", -1), wantCode: "invalid_response"},
		"interval as a string":     {status: http.StatusOK, body: with("interval", "5"), wantCode: "invalid_response"},
		"body that does not decompress": {
			status:    http.StatusOK,
			body:      corruptGzip{},
			wantCode:  "invalid_response",
			wantCause: gzip.ErrHeader,
		},
		"unknown fields are ignored": {
			status: http.StatusOK,
			body:   with("expires_at", "not a time"),
			want: &DeviceAuthorization{
				DeviceCode:              "device-code-1",
				UserCode:                "WDJB-MJHT",
				VerificationURI:         "https://zone.example.com/device",
				VerificationURIComplete: "https://zone.example.com/device?user_code=WDJB-MJHT",
				ExpiresIn:               600,
				Interval:                10,
				ExpiresAt:               clockStart.Add(600 * time.Second),
			},
		},
		"invalid_target":             {status: http.StatusBadRequest, body: map[string]string{"error": "invalid_target"}, wantCode: "invalid_target"},
		"invalid_client":             {status: http.StatusUnauthorized, body: map[string]string{"error": "invalid_client"}, wantCode: "invalid_client"},
		"503 without an OAuth error": {status: http.StatusServiceUnavailable, body: "unavailable", wantHTTP: http.StatusServiceUnavailable},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			zone := newFakeZone(t)
			zone.deviceStatus, zone.deviceBody = tc.status, tc.body
			client := mustDeviceClient(t, zone.URL,
				WithDeviceHTTPClient(zone.httpClient()),
				WithDevicePublicClient("public-1"),
				WithDeviceClock(newFakeDeviceClock()))

			got, err := client.RequestDeviceAuthorization(context.Background(), DeviceAuthorizationRequest{})
			if tc.wantCause != nil && !errors.Is(err, tc.wantCause) {
				t.Errorf("error: got %v, want it to wrap %v", err, tc.wantCause)
			}
			switch {
			case tc.wantCode != "":
				wantOAuthError(t, err, tc.wantCode)
			case tc.wantHTTP != 0:
				wantHTTPError(t, err, tc.wantHTTP)
			default:
				if err != nil {
					t.Fatalf("RequestDeviceAuthorization: %v", err)
				}
				if !reflect.DeepEqual(got, tc.want) {
					t.Errorf("got %+v, want %+v", got, tc.want)
				}
			}
		})
	}
}

func TestPollToken_Request(t *testing.T) {
	cases := map[string]struct {
		public     bool
		wantForm   url.Values
		wantHeader http.Header
	}{
		"credential": {
			wantForm: url.Values{
				"grant_type":            {deviceCodeGrantType},
				"device_code":           {"device-code-1"},
				"client_assertion":      {"assertion-1"},
				"client_assertion_type": {clientAssertionTypeJWTBearer},
			},
			wantHeader: withAuthorization(formHeader, "Basic Y2xpZW50OnNlY3JldA=="),
		},
		"public client": {
			public: true,
			wantForm: url.Values{
				"grant_type":  {deviceCodeGrantType},
				"device_code": {"device-code-1"},
				"client_id":   {"public-1"},
			},
			wantHeader: formHeader,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			zone := newFakeZone(t)
			zone.script(stepToken)
			cred := &fakeAuthenticator{}
			opts := []DeviceAuthorizationOption{WithDeviceHTTPClient(zone.httpClient())}
			if tc.public {
				opts = append(opts, WithDevicePublicClient("public-1"))
			} else {
				opts = append(opts, WithDeviceCredential(cred))
			}
			client := mustDeviceClient(t, zone.URL, opts...)

			auth, err := client.RequestDeviceAuthorization(context.Background(), DeviceAuthorizationRequest{
				Scopes:    []string{"openid"},
				Resources: []string{"https://api-1.example.com"},
			})
			if err != nil {
				t.Fatalf("RequestDeviceAuthorization: %v", err)
			}
			if _, err := client.PollToken(context.Background(), *auth); err != nil {
				t.Fatalf("PollToken: %v", err)
			}

			calls := zone.tokenCalls()
			if len(calls) != 1 {
				t.Fatalf("token requests: got %d, want 1", len(calls))
			}
			if !reflect.DeepEqual(calls[0].form, tc.wantForm) {
				t.Errorf("form: got %v, want %v", calls[0].form, tc.wantForm)
			}
			if !reflect.DeepEqual(calls[0].header, tc.wantHeader) {
				t.Errorf("header: got %v, want %v", calls[0].header, tc.wantHeader)
			}
			if got := zone.discoveryRequests.Load(); got != 1 {
				t.Errorf("discovery requests: got %d, want 1 shared by both operations", got)
			}
			if !tc.public {
				want := [][2]string{{zone.URL, zone.URL + "/device/authorize"}, {zone.URL, zone.URL + "/token"}}
				if got := cred.recordedCalls(); !reflect.DeepEqual(got, want) {
					t.Errorf("credential calls: got %v, want %v", got, want)
				}
			}
		})
	}
}

func TestPollToken_Response(t *testing.T) {
	auth := DeviceAuthorization{DeviceCode: "device-code-1", Interval: 5, ExpiresIn: 600}
	issued := &TokenResponse{
		AccessToken:  "access-1",
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		RefreshToken: "refresh-1",
		IDToken:      "header.claims.signature",
		Scope:        []string{"openid"},
	}
	cases := map[string]struct {
		step      tokenStep
		endpoint  string
		wantToken *TokenResponse
		// At most one of wantCode, wantHTTP, wantNetwork, and wantConfig is set. All
		// four zero means a token.
		wantCode    string
		wantMessage string
		wantHTTP    int
		wantNetwork bool
		wantConfig  bool
		// wantCause, when set, is an error the returned error wraps.
		wantCause error
		wantPolls int
	}{
		"token with refresh_token and id_token as received": {
			step:      stepToken,
			wantToken: issued,
			wantPolls: 1,
		},
		// TokenResponse has no resource field, so the client never ties a token to a
		// resource (spec row 24). This case checks that the field does not break
		// parsing.
		"resource field in the response": {
			step: tokenStep{status: http.StatusOK, body: map[string]any{
				"access_token": "access-1", "token_type": "Bearer", "expires_in": 3600,
				"refresh_token": "refresh-1", "id_token": "header.claims.signature", "scope": "openid",
				"resource": "https://api-1.example.com",
			}},
			wantToken: issued,
			wantPolls: 1,
		},
		"authorization_pending": {
			step:        stepOAuthError("authorization_pending"),
			wantCode:    "authorization_pending",
			wantMessage: "authorization_pending description",
			wantPolls:   1,
		},
		"slow_down": {
			step:        stepOAuthError("slow_down"),
			wantCode:    "slow_down",
			wantMessage: "slow_down description",
			wantPolls:   1,
		},
		"503 without an OAuth error": {
			step:      stepStatus(http.StatusServiceUnavailable),
			wantHTTP:  http.StatusServiceUnavailable,
			wantPolls: 1,
		},
		"2xx without access_token": {
			step:      tokenStep{status: http.StatusOK, body: map[string]any{"token_type": "Bearer"}},
			wantCode:  "invalid_response",
			wantPolls: 1,
		},
		"2xx with a body that does not decompress": {
			step:      tokenStep{status: http.StatusOK, body: corruptGzip{}},
			wantCode:  "invalid_response",
			wantCause: gzip.ErrHeader,
			wantPolls: 1,
		},
		"503 with a body that does not decompress": {
			step:      tokenStep{status: http.StatusServiceUnavailable, body: corruptGzip{}},
			wantHTTP:  http.StatusServiceUnavailable,
			wantPolls: 1,
		},
		"network error": {
			step:        stepNetwork,
			wantNetwork: true,
			wantPolls:   1,
		},
		"token endpoint that is not an http or https URL": {
			step:       stepToken,
			endpoint:   "ftp://zone.example.com/token",
			wantConfig: true,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			zone := newFakeZone(t)
			zone.script(tc.step)
			md := zone.metadata()
			if tc.endpoint != "" {
				md.TokenEndpoint = tc.endpoint
			}
			client := mustDeviceClient(t, zone.URL,
				WithDeviceHTTPClient(zone.httpClient()),
				WithDevicePublicClient("public-1"),
				WithDeviceMetadata(md))

			token, err := client.PollToken(context.Background(), auth)

			if tc.wantCause != nil && !errors.Is(err, tc.wantCause) {
				t.Errorf("error: got %v, want it to wrap %v", err, tc.wantCause)
			}
			switch {
			case tc.wantCode != "":
				wantOAuthError(t, err, tc.wantCode)
				var oauthErr *OAuthError
				if errors.As(err, &oauthErr) && tc.wantMessage != "" && oauthErr.Message != tc.wantMessage {
					t.Errorf("message: got %q, want %q", oauthErr.Message, tc.wantMessage)
				}
			case tc.wantHTTP != 0:
				wantHTTPError(t, err, tc.wantHTTP)
			case tc.wantNetwork:
				if !errors.Is(err, errNetwork) {
					t.Fatalf("error: got %v, want the transport error", err)
				}
			case tc.wantConfig:
				var cfgErr *ConfigurationError
				if !errors.As(err, &cfgErr) {
					t.Fatalf("error: got %v (%T), want *ConfigurationError", err, err)
				}
			default:
				if err != nil {
					t.Fatalf("PollToken: %v", err)
				}
				if !reflect.DeepEqual(token, tc.wantToken) {
					t.Errorf("token: got %+v, want %+v", token, tc.wantToken)
				}
			}
			if got := len(zone.tokenCalls()); got != tc.wantPolls {
				t.Errorf("polls: got %d, want %d", got, tc.wantPolls)
			}
		})
	}
}

// Spec row 22: each request in one flow gets its own WebIdentity assertion, with the
// URL of the endpoint it goes to as aud.
func TestDeviceFlow_WebIdentityAssertionPerRequest(t *testing.T) {
	zone := newFakeZone(t)
	zone.script(stepOAuthError("authorization_pending"), stepToken)
	cred := NewWebIdentity(WithClientID("client-a"), WithStorageDir(t.TempDir()))
	client := mustDeviceClient(t, zone.URL,
		WithDeviceHTTPClient(zone.httpClient()),
		WithDeviceCredential(cred))

	auth, err := client.RequestDeviceAuthorization(context.Background(), DeviceAuthorizationRequest{})
	if err != nil {
		t.Fatalf("RequestDeviceAuthorization: %v", err)
	}
	if _, err := client.PollToken(context.Background(), *auth); err == nil {
		t.Fatal("first poll: got a token, want authorization_pending")
	}
	if _, err := client.PollToken(context.Background(), *auth); err != nil {
		t.Fatalf("second poll: %v", err)
	}

	type sent struct {
		form    url.Values
		wantAud string
	}
	var requests []sent
	for _, c := range zone.deviceCalls() {
		requests = append(requests, sent{c.form, zone.URL + "/device/authorize"})
	}
	for _, c := range zone.tokenCalls() {
		requests = append(requests, sent{c.form, zone.URL + "/token"})
	}
	if len(requests) != 3 {
		t.Fatalf("requests: got %d, want 1 device authorization and 2 polls", len(requests))
	}
	jtis := map[string]bool{}
	for i, r := range requests {
		claims := assertionClaims(t, r.form.Get("client_assertion"))
		if claims["aud"] != r.wantAud {
			t.Errorf("request %d aud: got %v, want %q", i, claims["aud"], r.wantAud)
		}
		jti, _ := claims["jti"].(string)
		if jti == "" || jtis[jti] {
			t.Errorf("request %d jti: got %q, want a new non-empty jti", i, jti)
		}
		jtis[jti] = true
	}
}

// The request timeout bounds each request, including discovery, also when the
// caller's context has a later deadline.
func TestDeviceAuthorization_RequestTimeout(t *testing.T) {
	const timeout = 20 * time.Millisecond
	auth := DeviceAuthorization{DeviceCode: "device-code-1", Interval: 5, ExpiresIn: 600}
	cases := map[string]struct {
		run           func(ctx context.Context, client *DeviceAuthorizationClient) error
		discover      bool
		wantDevice    int
		wantPolls     int
		wantDiscovery int32
	}{
		"device authorization request": {
			run: func(ctx context.Context, c *DeviceAuthorizationClient) error {
				_, err := c.RequestDeviceAuthorization(ctx, DeviceAuthorizationRequest{})
				return err
			},
			wantDevice: 1,
		},
		"poll": {
			run: func(ctx context.Context, c *DeviceAuthorizationClient) error {
				_, err := c.PollToken(ctx, auth)
				return err
			},
			wantPolls: 1,
		},
		"discovery": {
			run: func(ctx context.Context, c *DeviceAuthorizationClient) error {
				_, err := c.RequestDeviceAuthorization(ctx, DeviceAuthorizationRequest{})
				return err
			},
			discover:      true,
			wantDiscovery: 1,
		},
	}
	for name, tc := range cases {
		for _, ctxTimeout := range []time.Duration{0, time.Minute} {
			t.Run(fmt.Sprintf("%s, caller deadline %v", name, ctxTimeout), func(t *testing.T) {
				zone := newFakeZone(t)
				zone.delay = time.Second
				zone.script(stepToken)
				opts := []DeviceAuthorizationOption{
					WithDeviceHTTPClient(zone.httpClient()),
					WithDevicePublicClient("public-1"),
					WithDeviceRequestTimeout(timeout),
				}
				if !tc.discover {
					opts = append(opts, WithDeviceMetadata(zone.metadata()))
				}
				client := mustDeviceClient(t, zone.URL, opts...)
				ctx := context.Background()
				if ctxTimeout != 0 {
					var cancel context.CancelFunc
					ctx, cancel = context.WithTimeout(ctx, ctxTimeout)
					defer cancel()
				}

				start := time.Now()
				err := tc.run(ctx, client)

				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("error: got %v, want context.DeadlineExceeded", err)
				}
				if elapsed := time.Since(start); elapsed >= zone.delay {
					t.Errorf("returned after %v, want before the zone's %v delay", elapsed, zone.delay)
				}
				if got := len(zone.deviceCalls()); got != tc.wantDevice {
					t.Errorf("device authorization requests: got %d, want %d", got, tc.wantDevice)
				}
				if got := len(zone.tokenCalls()); got != tc.wantPolls {
					t.Errorf("polls: got %d, want %d", got, tc.wantPolls)
				}
				if got := zone.discoveryRequests.Load(); got != tc.wantDiscovery {
					t.Errorf("discovery requests: got %d, want %d", got, tc.wantDiscovery)
				}
			})
		}
	}
}
