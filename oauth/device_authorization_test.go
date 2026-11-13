package oauth

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"reflect"
	"sync"
	"testing"
	"time"
)

// fakeDeviceClock advances only when the code under test waits, and records each
// wait. onAfter, when set, replaces the wait.
type fakeDeviceClock struct {
	mu      sync.Mutex
	now     time.Time
	waits   []time.Duration
	onAfter func(d time.Duration) <-chan time.Time
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
	c.waits = append(c.waits, d)
	onAfter := c.onAfter
	if onAfter == nil {
		c.now = c.now.Add(d)
	}
	now := c.now
	c.mu.Unlock()
	if onAfter != nil {
		return onAfter(d)
	}
	ch := make(chan time.Time, 1)
	ch <- now
	return ch
}

func (c *fakeDeviceClock) recordedWaits() []time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]time.Duration(nil), c.waits...)
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
		"row 29: 503 with a permanent code": {
			step:        tokenStep{status: http.StatusServiceUnavailable, body: map[string]string{"error": "access_denied", "error_description": "denied"}},
			wantCode:    "access_denied",
			wantMessage: "denied",
			wantPolls:   1,
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

// newWaitClient returns a public device client on zone with a fake clock, and a
// DeviceAuthorization with the given interval and lifetime in seconds.
func newWaitClient(t *testing.T, zone *fakeZone, interval, expiresIn int, opts ...DeviceAuthorizationOption) (*DeviceAuthorizationClient, *fakeDeviceClock, DeviceAuthorization) {
	t.Helper()
	clock := newFakeDeviceClock()
	opts = append([]DeviceAuthorizationOption{
		WithDeviceHTTPClient(zone.httpClient()),
		WithDevicePublicClient("public-1"),
		WithDeviceClock(clock),
	}, opts...)
	auth := DeviceAuthorization{
		DeviceCode: "device-code-1",
		Interval:   interval,
		ExpiresIn:  expiresIn,
		ExpiresAt:  clock.Now().Add(time.Duration(expiresIn) * time.Second),
	}
	return mustDeviceClient(t, zone.URL, opts...), clock, auth
}

// wantPollError checks that err is a *DevicePollError with the given Interval, or is
// not a *DevicePollError when interval is 0.
func wantPollError(t *testing.T, err error, interval time.Duration) {
	t.Helper()
	var pollErr *DevicePollError
	isPollErr := errors.As(err, &pollErr)
	switch {
	case interval != 0 && !isPollErr:
		t.Errorf("error: got %v (%T), want *DevicePollError", err, err)
	case interval != 0 && pollErr.Interval != interval:
		t.Errorf("DevicePollError.Interval: got %v, want %v", pollErr.Interval, interval)
	case interval == 0 && isPollErr:
		t.Errorf("error: got *DevicePollError %v, want no DevicePollError", err)
	}
}

func TestWaitForToken(t *testing.T) {
	const s = time.Second
	cases := map[string]struct {
		steps     []tokenStep
		interval  int
		expiresIn int
		start     time.Duration
		wantWaits []time.Duration
		wantPolls int
		// At most one of wantCode, wantHTTP, wantNetwork, and wantConfig is set. All
		// four zero means a token.
		wantCode    string
		wantHTTP    int
		wantNetwork bool
		wantConfig  bool
		// wantPollInterval, when set, is the Interval of the expected *DevicePollError.
		wantPollInterval time.Duration
	}{
		"row 8: pending twice, then a token": {
			steps:     []tokenStep{stepOAuthError("authorization_pending"), stepOAuthError("authorization_pending"), stepToken},
			wantWaits: []time.Duration{5 * s, 5 * s, 5 * s},
			wantPolls: 3,
		},
		"row 9: slow_down adds 5 seconds to this and every later wait": {
			steps:     []tokenStep{stepOAuthError("slow_down"), stepOAuthError("authorization_pending"), stepToken},
			wantWaits: []time.Duration{5 * s, 10 * s, 10 * s},
			wantPolls: 3,
		},
		"row 10: access_denied stops": {
			steps:     []tokenStep{stepOAuthError("access_denied")},
			wantWaits: []time.Duration{5 * s},
			wantPolls: 1,
			wantCode:  "access_denied",
		},
		"row 11: clock passes expires_at while pending": {
			steps:     []tokenStep{stepOAuthError("authorization_pending")},
			expiresIn: 12,
			wantWaits: []time.Duration{5 * s, 5 * s},
			wantPolls: 2,
			wantCode:  "expired_token",
		},
		"row 12: expired_token from the server stops": {
			steps:     []tokenStep{stepOAuthError("expired_token")},
			wantWaits: []time.Duration{5 * s},
			wantPolls: 1,
			wantCode:  "expired_token",
		},
		"row 12: invalid_grant from the server stops": {
			steps:     []tokenStep{stepOAuthError("invalid_grant")},
			wantWaits: []time.Duration{5 * s},
			wantPolls: 1,
			wantCode:  "invalid_grant",
		},
		"row 16: slow_down, then a network error doubles the raised interval": {
			steps:            []tokenStep{stepOAuthError("slow_down"), stepNetwork},
			wantWaits:        []time.Duration{5 * s, 10 * s},
			wantPolls:        2,
			wantNetwork:      true,
			wantPollInterval: 20 * s,
		},
		"row 17: 429 stops and reports the interval": {
			steps:            []tokenStep{stepStatus(http.StatusTooManyRequests)},
			wantWaits:        []time.Duration{5 * s},
			wantPolls:        1,
			wantHTTP:         http.StatusTooManyRequests,
			wantPollInterval: 5 * s,
		},
		"row 19: start interval below the authorization's interval": {
			steps:      []tokenStep{stepToken},
			start:      3 * s,
			wantConfig: true,
		},
		"row 21: interval longer than the time left stops without waiting": {
			steps:    []tokenStep{stepToken},
			interval: 700,
			wantCode: "expired_token",
		},
		"row 21: interval too large for a Duration stops without waiting": {
			steps:    []tokenStep{stepToken},
			interval: math.MaxInt,
			wantCode: "expired_token",
		},
		"row 24: token response with a resource field": {
			steps: []tokenStep{{status: http.StatusOK, body: map[string]any{
				"access_token": "access-1", "token_type": "Bearer", "expires_in": 3600,
				"refresh_token": "refresh-1", "id_token": "header.claims.signature", "scope": "openid",
				"resource": "https://api-1.example.com",
			}}},
			wantWaits: []time.Duration{5 * s},
			wantPolls: 1,
		},
		"row 26: 503 with an OAuth error body stops and reports the interval": {
			steps:            []tokenStep{{status: http.StatusServiceUnavailable, body: map[string]string{"error": "temporarily_unavailable"}}},
			wantWaits:        []time.Duration{5 * s},
			wantPolls:        1,
			wantCode:         "temporarily_unavailable",
			wantPollInterval: 5 * s,
		},
		"row 29: 503 with a permanent code stops and reports the interval": {
			steps:            []tokenStep{{status: http.StatusServiceUnavailable, body: map[string]string{"error": "access_denied"}}},
			wantWaits:        []time.Duration{5 * s},
			wantPolls:        1,
			wantCode:         "access_denied",
			wantPollInterval: 5 * s,
		},
		"400 without an OAuth error body stops without an interval": {
			steps:     []tokenStep{stepStatus(http.StatusBadRequest)},
			wantWaits: []time.Duration{5 * s},
			wantPolls: 1,
			wantHTTP:  http.StatusBadRequest,
		},
		"2xx with a body that does not decompress stops without an interval": {
			steps:     []tokenStep{{status: http.StatusOK, body: corruptGzip{}}},
			wantWaits: []time.Duration{5 * s},
			wantPolls: 1,
			wantCode:  "invalid_response",
		},
		"503 with a body that does not decompress reports the interval, not doubled": {
			steps:            []tokenStep{{status: http.StatusServiceUnavailable, body: corruptGzip{}}},
			wantWaits:        []time.Duration{5 * s},
			wantPolls:        1,
			wantHTTP:         http.StatusServiceUnavailable,
			wantPollInterval: 5 * s,
		},
		"2xx without access_token stops without an interval": {
			steps:     []tokenStep{{status: http.StatusOK, body: map[string]any{"token_type": "Bearer"}}},
			wantWaits: []time.Duration{5 * s},
			wantPolls: 1,
			wantCode:  "invalid_response",
		},
		"start interval sets the first wait": {
			steps:     []tokenStep{stepOAuthError("authorization_pending"), stepToken},
			start:     10 * s,
			wantWaits: []time.Duration{10 * s, 10 * s},
			wantPolls: 2,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			zone := newFakeZone(t)
			zone.script(tc.steps...)
			interval, expiresIn := tc.interval, tc.expiresIn
			if interval == 0 {
				interval = 5
			}
			if expiresIn == 0 {
				expiresIn = 600
			}
			client, clock, auth := newWaitClient(t, zone, interval, expiresIn)
			var opts []WaitForTokenOption
			if tc.start != 0 {
				opts = append(opts, WithStartInterval(tc.start))
			}

			token, err := client.WaitForToken(context.Background(), auth, opts...)

			switch {
			case tc.wantCode != "":
				wantOAuthError(t, err, tc.wantCode)
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
					t.Fatalf("WaitForToken: %v", err)
				}
				want := &TokenResponse{
					AccessToken:  "access-1",
					TokenType:    "Bearer",
					ExpiresIn:    3600,
					RefreshToken: "refresh-1",
					IDToken:      "header.claims.signature",
					Scope:        []string{"openid"},
				}
				if !reflect.DeepEqual(token, want) {
					t.Errorf("token: got %+v, want %+v", token, want)
				}
			}
			wantPollError(t, err, tc.wantPollInterval)
			if got := len(zone.tokenCalls()); got != tc.wantPolls {
				t.Errorf("polls: got %d, want %d", got, tc.wantPolls)
			}
			if got := clock.recordedWaits(); !reflect.DeepEqual(got, tc.wantWaits) {
				t.Errorf("waits: got %v, want %v", got, tc.wantWaits)
			}
		})
	}
}

// Spec row 13: each failure stops the loop after one poll. A second WaitForToken call
// with the same DeviceAuthorization polls again.
func TestWaitForToken_TransportAndServerFailuresStop(t *testing.T) {
	zone := newFakeZone(t)
	zone.script(stepNetwork, stepStatus(http.StatusServiceUnavailable))
	client, _, auth := newWaitClient(t, zone, 5, 600)

	_, err := client.WaitForToken(context.Background(), auth)
	if !errors.Is(err, errNetwork) {
		t.Fatalf("first call: got %v, want the transport error", err)
	}
	wantPollError(t, err, 10*time.Second)
	if got := len(zone.tokenCalls()); got != 1 {
		t.Fatalf("polls after first call: got %d, want 1", got)
	}

	_, err = client.WaitForToken(context.Background(), auth)
	wantHTTPError(t, err, http.StatusServiceUnavailable)
	wantPollError(t, err, 5*time.Second)
	if got := len(zone.tokenCalls()); got != 2 {
		t.Errorf("polls after second call: got %d, want 2", got)
	}
}

// Spec row 18: resuming with the Interval from a DevicePollError keeps the slow_down
// increase and the doubling after a network error.
func TestWaitForToken_ResumeAfterSlowDown(t *testing.T) {
	zone := newFakeZone(t)
	zone.script(stepOAuthError("slow_down"), stepNetwork, stepToken)
	client, clock, auth := newWaitClient(t, zone, 5, 600)

	_, err := client.WaitForToken(context.Background(), auth)
	var pollErr *DevicePollError
	if !errors.As(err, &pollErr) {
		t.Fatalf("first call: got %v (%T), want *DevicePollError", err, err)
	}

	if _, err := client.WaitForToken(context.Background(), auth, WithStartInterval(pollErr.Interval)); err != nil {
		t.Fatalf("resumed call: %v", err)
	}
	want := []time.Duration{5 * time.Second, 10 * time.Second, 20 * time.Second}
	if got := clock.recordedWaits(); !reflect.DeepEqual(got, want) {
		t.Errorf("waits: got %v, want %v", got, want)
	}
	if got := len(zone.tokenCalls()); got != 3 {
		t.Errorf("polls: got %d, want 3", got)
	}
}

// Spec rows 14 and 20. The client authenticates with a credential, which the loop
// calls once per poll. Its calls show whether a poll started, also when the request is
// not sent.
func TestWaitForToken_Cancellation(t *testing.T) {
	cases := map[string]struct {
		// setup arranges for cancel to run during the wait or during the request.
		setup     func(zone *fakeZone, clock *fakeDeviceClock, cancel context.CancelFunc)
		wantPolls int
	}{
		"during the wait": {
			setup: func(_ *fakeZone, clock *fakeDeviceClock, cancel context.CancelFunc) {
				clock.onAfter = func(time.Duration) <-chan time.Time {
					cancel()
					return make(chan time.Time) // never fires
				}
			},
			wantPolls: 0,
		},
		"as the wait ends": {
			setup: func(_ *fakeZone, clock *fakeDeviceClock, cancel context.CancelFunc) {
				clock.onAfter = func(time.Duration) <-chan time.Time {
					cancel()
					fired := make(chan time.Time, 1)
					fired <- clock.Now()
					return fired
				}
			},
			wantPolls: 0,
		},
		"during the request": {
			setup: func(zone *fakeZone, _ *fakeDeviceClock, cancel context.CancelFunc) {
				zone.onToken = func(_ http.ResponseWriter, r *http.Request) {
					cancel()
					<-r.Context().Done()
				}
			},
			wantPolls: 1,
		},
	}
	// In "as the wait ends", the wait's select has two ready cases and picks one at
	// random. Each case runs this many times, so that both picks happen.
	const rounds = 32
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			for range rounds {
				zone := newFakeZone(t)
				zone.script(stepOAuthError("authorization_pending"))
				cred := &fakeAuthenticator{}
				clock := newFakeDeviceClock()
				client := mustDeviceClient(t, zone.URL,
					WithDeviceHTTPClient(zone.httpClient()),
					WithDeviceCredential(cred),
					WithDeviceMetadata(zone.metadata()),
					WithDeviceClock(clock))
				auth := DeviceAuthorization{DeviceCode: "device-code-1", Interval: 5, ExpiresIn: 600, ExpiresAt: clock.Now().Add(600 * time.Second)}
				ctx, cancel := context.WithCancel(context.Background())
				tc.setup(zone, clock, cancel)

				_, err := client.WaitForToken(ctx, auth)
				cancel()

				// The caller's own cancellation comes back unwrapped. A *DevicePollError
				// whose cause is context.Canceled also satisfies errors.Is, so the test
				// compares the value.
				if err != context.Canceled {
					t.Fatalf("error: got %v (%T), want context.Canceled", err, err)
				}
				if got := len(cred.recordedCalls()); got != tc.wantPolls {
					t.Fatalf("credential calls: got %d, want %d", got, tc.wantPolls)
				}
				if got := len(zone.tokenCalls()); got != tc.wantPolls {
					t.Fatalf("polls: got %d, want %d", got, tc.wantPolls)
				}
			}
		})
	}
}

// Spec row 15: a DeviceAuthorization round-trips through JSON, so another process can
// poll with it.
func TestWaitForToken_PersistedDeviceAuthorization(t *testing.T) {
	zone := newFakeZone(t)
	zone.script(stepToken)
	opts := []DeviceAuthorizationOption{
		WithDeviceHTTPClient(zone.httpClient()),
		WithDevicePublicClient("public-1"),
		WithDeviceClock(newFakeDeviceClock()),
	}

	auth, err := mustDeviceClient(t, zone.URL, opts...).RequestDeviceAuthorization(context.Background(), DeviceAuthorizationRequest{})
	if err != nil {
		t.Fatalf("RequestDeviceAuthorization: %v", err)
	}
	saved, err := json.Marshal(auth)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var restored DeviceAuthorization
	if err := json.Unmarshal(saved, &restored); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !reflect.DeepEqual(&restored, auth) {
		t.Fatalf("restored: got %+v, want %+v", restored, *auth)
	}

	if _, err := mustDeviceClient(t, zone.URL, opts...).WaitForToken(context.Background(), restored); err != nil {
		t.Fatalf("WaitForToken: %v", err)
	}
	calls := zone.tokenCalls()
	if len(calls) != 1 || calls[0].form.Get("device_code") != "device-code-1" {
		t.Errorf("token requests: got %+v, want one with device_code device-code-1", calls)
	}
}

// A DeviceAuthorization or metadata the loop cannot use is a configuration error,
// returned before the first wait.
func TestWaitForToken_Configuration(t *testing.T) {
	future := time.Now().Add(time.Hour)
	cases := map[string]struct {
		auth          DeviceAuthorization
		tokenEndpoint string
	}{
		"no device_code":    {auth: DeviceAuthorization{Interval: 5, ExpiresAt: future}},
		"no expires_at":     {auth: DeviceAuthorization{DeviceCode: "device-code-1", Interval: 5}},
		"negative interval": {auth: DeviceAuthorization{DeviceCode: "device-code-1", Interval: -1, ExpiresAt: future}},
		"token endpoint that is not an http or https URL": {
			auth:          DeviceAuthorization{DeviceCode: "device-code-1", Interval: 5, ExpiresAt: future},
			tokenEndpoint: "zone.example.com/token",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			zone := newFakeZone(t)
			zone.script(stepToken)
			md := zone.metadata()
			if tc.tokenEndpoint != "" {
				md.TokenEndpoint = tc.tokenEndpoint
			}
			clock := newFakeDeviceClock()
			client := mustDeviceClient(t, zone.URL,
				WithDeviceHTTPClient(zone.httpClient()),
				WithDevicePublicClient("public-1"),
				WithDeviceMetadata(md),
				WithDeviceClock(clock))

			_, err := client.WaitForToken(context.Background(), tc.auth)
			var cfgErr *ConfigurationError
			if !errors.As(err, &cfgErr) {
				t.Fatalf("error: got %v (%T), want *ConfigurationError", err, err)
			}
			if got := len(zone.tokenCalls()); got != 0 {
				t.Errorf("polls: got %d, want 0", got)
			}
			if got := clock.recordedWaits(); len(got) != 0 {
				t.Errorf("waits: got %v, want none", got)
			}
		})
	}
}

// An interval of 0 in a persisted DeviceAuthorization means the RFC 8628 default of
// 5 seconds.
func TestWaitForToken_ZeroIntervalWaitsFiveSeconds(t *testing.T) {
	zone := newFakeZone(t)
	zone.script(stepToken)
	client, clock, auth := newWaitClient(t, zone, 0, 600)

	if _, err := client.WaitForToken(context.Background(), auth); err != nil {
		t.Fatalf("WaitForToken: %v", err)
	}
	if got, want := clock.recordedWaits(), []time.Duration{5 * time.Second}; !reflect.DeepEqual(got, want) {
		t.Errorf("waits: got %v, want %v", got, want)
	}
}

// The clock can move further than the interval during a wait, as after a system
// sleep. The loop then ends without sending the poll.
func TestWaitForToken_ClockPassesExpiryDuringWait(t *testing.T) {
	zone := newFakeZone(t)
	zone.script(stepOAuthError("authorization_pending"))
	client, clock, auth := newWaitClient(t, zone, 5, 600)
	clock.onAfter = func(time.Duration) <-chan time.Time {
		clock.mu.Lock()
		clock.now = auth.ExpiresAt.Add(time.Second)
		clock.mu.Unlock()
		ch := make(chan time.Time, 1)
		ch <- clock.Now()
		return ch
	}

	_, err := client.WaitForToken(context.Background(), auth)
	wantOAuthError(t, err, "expired_token")
	if got := len(zone.tokenCalls()); got != 0 {
		t.Errorf("polls: got %d, want 0", got)
	}
}

// Spec row 27: a credential whose client authentication fails on a poll stops the
// loop. The credential's error comes back as is, without an interval.
func TestWaitForToken_ClientAuthenticationFails(t *testing.T) {
	zone := newFakeZone(t)
	zone.script(stepToken)
	cred := &fakeAuthenticator{failOn: "/token"}
	clock := newFakeDeviceClock()
	client := mustDeviceClient(t, zone.URL,
		WithDeviceHTTPClient(zone.httpClient()),
		WithDeviceCredential(cred),
		WithDeviceClock(clock))
	auth := DeviceAuthorization{DeviceCode: "device-code-1", Interval: 5, ExpiresIn: 600, ExpiresAt: clock.Now().Add(600 * time.Second)}

	_, err := client.WaitForToken(context.Background(), auth)

	if !errors.Is(err, errClientAuthentication) {
		t.Fatalf("error: got %v, want the credential's error", err)
	}
	wantPollError(t, err, 0)
	if got := len(zone.tokenCalls()); got != 0 {
		t.Errorf("polls: got %d, want 0", got)
	}
	want := [][2]string{{zone.URL, zone.URL + "/token"}}
	if got := cred.recordedCalls(); !reflect.DeepEqual(got, want) {
		t.Errorf("credential calls: got %v, want %v", got, want)
	}
}

// Spec row 28: the request timeout bounds each poll, also under a later caller
// deadline. A poll that times out, including while the body is read, is a network
// error, so its interval is doubled. The wait between polls does not count against
// the timeout.
func TestWaitForToken_RequestTimeout(t *testing.T) {
	const timeout = 20 * time.Millisecond
	// hangBody sends the status line and headers, then holds the body back until the
	// client gives up.
	hangBody := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":`))
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}
	cases := map[string]struct {
		zoneDelay  time.Duration
		onToken    func(w http.ResponseWriter, r *http.Request)
		realWait   time.Duration
		ctxTimeout time.Duration
		steps      []tokenStep
		wantPolls  int
		// wantTimeout is true when the call fails with context.DeadlineExceeded.
		wantTimeout      bool
		wantPollInterval time.Duration
	}{
		"a poll that times out": {
			zoneDelay:        time.Second,
			steps:            []tokenStep{stepToken},
			wantPolls:        1,
			wantTimeout:      true,
			wantPollInterval: 10 * time.Second,
		},
		"a poll that times out under a later caller deadline": {
			zoneDelay:        time.Second,
			ctxTimeout:       time.Minute,
			steps:            []tokenStep{stepToken},
			wantPolls:        1,
			wantTimeout:      true,
			wantPollInterval: 10 * time.Second,
		},
		"a poll that times out while the body is read": {
			onToken:          hangBody,
			steps:            []tokenStep{stepToken},
			wantPolls:        1,
			wantTimeout:      true,
			wantPollInterval: 10 * time.Second,
		},
		"the wait between polls is not bounded by the request timeout": {
			realWait:  4 * timeout,
			steps:     []tokenStep{stepOAuthError("authorization_pending"), stepToken},
			wantPolls: 2,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			zone := newFakeZone(t)
			zone.delay = tc.zoneDelay
			zone.onToken = tc.onToken
			zone.script(tc.steps...)
			client, clock, auth := newWaitClient(t, zone, 5, 600,
				WithDeviceMetadata(zone.metadata()),
				WithDeviceRequestTimeout(timeout))
			if tc.realWait != 0 {
				clock.onAfter = func(time.Duration) <-chan time.Time { return time.After(tc.realWait) }
			}
			ctx := context.Background()
			if tc.ctxTimeout != 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, tc.ctxTimeout)
				defer cancel()
			}

			_, err := client.WaitForToken(ctx, auth)

			if tc.wantTimeout {
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("error: got %v, want context.DeadlineExceeded", err)
				}
			} else if err != nil {
				t.Fatalf("got %v, want success", err)
			}
			wantPollError(t, err, tc.wantPollInterval)
			if got := len(zone.tokenCalls()); got != tc.wantPolls {
				t.Errorf("polls: got %d, want %d", got, tc.wantPolls)
			}
		})
	}
}
