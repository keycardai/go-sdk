package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// tokenStep is one scripted token endpoint response. network makes the transport fail
// the request instead of sending it.
type tokenStep struct {
	status  int
	body    any
	network bool
}

var (
	stepToken = tokenStep{status: http.StatusOK, body: map[string]any{
		"access_token":  "access-1",
		"token_type":    "Bearer",
		"expires_in":    3600,
		"refresh_token": "refresh-1",
		"id_token":      "header.claims.signature",
		"scope":         "openid",
	}}
	stepNetwork = tokenStep{network: true}
)

func stepOAuthError(code string) tokenStep {
	return tokenStep{status: http.StatusBadRequest, body: map[string]string{"error": code, "error_description": code + " description"}}
}

func stepStatus(status int) tokenStep {
	return tokenStep{status: status, body: "upstream unavailable"}
}

type recordedRequest struct {
	header http.Header
	form   url.Values
}

var errNetwork = errors.New("connection reset by peer")

// deviceZone is a fake authorization server with discovery, a device authorization
// endpoint, and a token endpoint that plays back scripted steps.
type deviceZone struct {
	*httptest.Server
	t *testing.T

	discoveryRequests  atomic.Int32
	omitDeviceEndpoint bool

	mu             sync.Mutex
	deviceBody     any
	deviceStatus   int
	deviceRequests []recordedRequest
	tokenSteps     []tokenStep
	tokenRequests  []recordedRequest
	onToken        func(r *http.Request)
}

func newDeviceZone(t *testing.T) *deviceZone {
	z := &deviceZone{
		t:            t,
		deviceStatus: http.StatusOK,
		deviceBody: map[string]any{
			"device_code":               "device-code-1",
			"user_code":                 "WDJB-MJHT",
			"verification_uri":          "https://zone.example.com/device",
			"verification_uri_complete": "https://zone.example.com/device?user_code=WDJB-MJHT",
			"expires_in":                600,
			"interval":                  5,
		},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, _ *http.Request) {
		z.discoveryRequests.Add(1)
		writeJSON(w, http.StatusOK, z.metadata())
	})
	mux.HandleFunc("/device/authorize", func(w http.ResponseWriter, r *http.Request) {
		rec := z.record(r)
		z.mu.Lock()
		z.deviceRequests = append(z.deviceRequests, rec)
		status, body := z.deviceStatus, z.deviceBody
		z.mu.Unlock()
		writeJSON(w, status, body)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		rec := z.record(r)
		z.mu.Lock()
		z.tokenRequests = append(z.tokenRequests, rec)
		onToken := z.onToken
		step := z.nextStep()
		z.mu.Unlock()
		if onToken != nil {
			onToken(r)
			return
		}
		writeJSON(w, step.status, step.body)
	})
	z.Server = httptest.NewServer(mux)
	t.Cleanup(z.Close)
	return z
}

func (z *deviceZone) metadata() *AuthorizationServerMetadata {
	md := &AuthorizationServerMetadata{Issuer: z.URL, TokenEndpoint: z.URL + "/token"}
	if !z.omitDeviceEndpoint {
		md.DeviceAuthorizationEndpoint = z.URL + "/device/authorize"
	}
	return md
}

func (z *deviceZone) record(r *http.Request) recordedRequest {
	if err := r.ParseForm(); err != nil {
		z.t.Errorf("parsing form: %v", err)
	}
	h := r.Header.Clone()
	for _, k := range []string{"Accept-Encoding", "Content-Length", "User-Agent"} {
		h.Del(k)
	}
	return recordedRequest{header: h, form: r.PostForm}
}

// nextStep returns the next scripted step. The last step repeats. Callers hold z.mu.
func (z *deviceZone) nextStep() tokenStep {
	if len(z.tokenSteps) == 0 {
		z.t.Error("token endpoint called with no scripted steps")
		return stepStatus(http.StatusInternalServerError)
	}
	step := z.tokenSteps[0]
	if len(z.tokenSteps) > 1 {
		z.tokenSteps = z.tokenSteps[1:]
	}
	return step
}

func (z *deviceZone) script(steps ...tokenStep) {
	z.mu.Lock()
	z.tokenSteps = steps
	z.mu.Unlock()
}

func (z *deviceZone) deviceCalls() []recordedRequest {
	z.mu.Lock()
	defer z.mu.Unlock()
	return append([]recordedRequest(nil), z.deviceRequests...)
}

func (z *deviceZone) tokenCalls() []recordedRequest {
	z.mu.Lock()
	defer z.mu.Unlock()
	return append([]recordedRequest(nil), z.tokenRequests...)
}

// RoundTrip fails a token request when the next scripted step is a network failure,
// so the request never reaches the server. Other requests go to the server.
func (z *deviceZone) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Path == "/token" {
		z.mu.Lock()
		fail := len(z.tokenSteps) > 0 && z.tokenSteps[0].network
		if fail {
			z.tokenRequests = append(z.tokenRequests, recordedRequest{})
			z.nextStep()
		}
		z.mu.Unlock()
		if fail {
			return nil, errNetwork
		}
	}
	return http.DefaultTransport.RoundTrip(r)
}

func (z *deviceZone) httpClient() *http.Client { return &http.Client{Transport: z} }

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

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

// fakeAuthenticator returns fixed client authentication and records each call.
type fakeAuthenticator struct {
	mu    sync.Mutex
	calls [][2]string // issuer, endpoint
}

func (f *fakeAuthenticator) ClientAuthentication(_ context.Context, issuer, endpoint string) (*ClientAuthentication, error) {
	f.mu.Lock()
	f.calls = append(f.calls, [2]string{issuer, endpoint})
	f.mu.Unlock()
	return &ClientAuthentication{
		Header: http.Header{"Authorization": {"Basic Y2xpZW50OnNlY3JldA=="}},
		Form:   url.Values{"client_assertion": {"assertion-1"}, "client_assertion_type": {clientAssertionTypeJWTBearer}},
	}, nil
}

func (f *fakeAuthenticator) recordedCalls() [][2]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([][2]string(nil), f.calls...)
}

var formHeader = http.Header{
	"Content-Type": {"application/x-www-form-urlencoded"},
	"Accept":       {"application/json"},
}

func withAuthorization(h http.Header, value string) http.Header {
	h = h.Clone()
	h.Set("Authorization", value)
	return h
}

func mustDeviceClient(t *testing.T, issuer string, opts ...DeviceAuthorizationOption) *DeviceAuthorizationClient {
	t.Helper()
	c, err := NewDeviceAuthorizationClient(issuer, opts...)
	if err != nil {
		t.Fatalf("NewDeviceAuthorizationClient: %v", err)
	}
	return c
}

func wantOAuthError(t *testing.T, err error, code string) {
	t.Helper()
	var oauthErr *OAuthError
	if !errors.As(err, &oauthErr) {
		t.Fatalf("error: got %v (%T), want *OAuthError %s", err, err, code)
	}
	if oauthErr.ErrorCode != code {
		t.Errorf("error code: got %q, want %q", oauthErr.ErrorCode, code)
	}
}

func wantHTTPError(t *testing.T, err error, status int) {
	t.Helper()
	var httpErr *HTTPError
	if !errors.As(err, &httpErr) {
		t.Fatalf("error: got %v (%T), want *HTTPError %d", err, err, status)
	}
	if httpErr.Status != status {
		t.Errorf("status: got %d, want %d", httpErr.Status, status)
	}
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
		"no issuer and no metadata": {
			opts:    []DeviceAuthorizationOption{WithDevicePublicClient("public-1")},
			wantErr: true,
		},
		"issuer differs from the metadata issuer": {
			issuer:  "https://other.example.com",
			opts:    []DeviceAuthorizationOption{WithDevicePublicClient("public-1"), WithDeviceMetadata(md)},
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
			zone := newDeviceZone(t)
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

func TestRequestDeviceAuthorization_NoDeviceEndpoint(t *testing.T) {
	cases := map[string]bool{"discovered": false, "pre-discovered": true}
	for name, useMetadata := range cases {
		t.Run(name, func(t *testing.T) {
			zone := newDeviceZone(t)
			zone.omitDeviceEndpoint = true
			cred := &fakeAuthenticator{}
			opts := []DeviceAuthorizationOption{WithDeviceHTTPClient(zone.httpClient()), WithDeviceCredential(cred)}
			if useMetadata {
				opts = append(opts, WithDeviceMetadata(zone.metadata()))
			}
			client := mustDeviceClient(t, zone.URL, opts...)

			_, err := client.RequestDeviceAuthorization(context.Background(), DeviceAuthorizationRequest{})
			var cfgErr *ConfigurationError
			if !errors.As(err, &cfgErr) {
				t.Fatalf("error: got %v, want *ConfigurationError", err)
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
	clockStart := newFakeDeviceClock().Now()

	cases := map[string]struct {
		status   int
		body     any
		want     *DeviceAuthorization
		wantCode string
		wantHTTP int
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
		"missing device_code":        {status: http.StatusOK, body: without("device_code"), wantCode: "invalid_response"},
		"missing user_code":          {status: http.StatusOK, body: without("user_code"), wantCode: "invalid_response"},
		"missing verification_uri":   {status: http.StatusOK, body: without("verification_uri"), wantCode: "invalid_response"},
		"missing expires_in":         {status: http.StatusOK, body: without("expires_in"), wantCode: "invalid_response"},
		"body is not an object":      {status: http.StatusOK, body: "not an object", wantCode: "invalid_response"},
		"invalid_target":             {status: http.StatusBadRequest, body: map[string]string{"error": "invalid_target"}, wantCode: "invalid_target"},
		"invalid_client":             {status: http.StatusUnauthorized, body: map[string]string{"error": "invalid_client"}, wantCode: "invalid_client"},
		"503 without an OAuth error": {status: http.StatusServiceUnavailable, body: "unavailable", wantHTTP: http.StatusServiceUnavailable},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			zone := newDeviceZone(t)
			zone.deviceStatus, zone.deviceBody = tc.status, tc.body
			client := mustDeviceClient(t, zone.URL,
				WithDeviceHTTPClient(zone.httpClient()),
				WithDevicePublicClient("public-1"),
				WithDeviceClock(newFakeDeviceClock()))

			got, err := client.RequestDeviceAuthorization(context.Background(), DeviceAuthorizationRequest{})
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
			zone := newDeviceZone(t)
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

func TestWaitForToken(t *testing.T) {
	const s = time.Second
	stepTokenWithResource := tokenStep{status: http.StatusOK, body: map[string]any{
		"access_token":  "access-1",
		"token_type":    "Bearer",
		"expires_in":    3600,
		"refresh_token": "refresh-1",
		"id_token":      "header.claims.signature",
		"scope":         "openid",
		"resource":      "https://api-1.example.com",
	}}
	cases := map[string]struct {
		steps     []tokenStep
		interval  int
		expiresIn int
		start     time.Duration
		wantWaits []time.Duration
		wantPolls int
		// Exactly one of the following describes a failure. All zero means a token.
		wantCode    string
		wantHTTP    int
		wantNetwork bool
		wantConfig  bool
		// wantPollInterval, when set, is the Interval of the expected *DevicePollError.
		wantPollInterval time.Duration
	}{
		"pending twice, then a token": {
			steps:     []tokenStep{stepOAuthError("authorization_pending"), stepOAuthError("authorization_pending"), stepToken},
			wantWaits: []time.Duration{5 * s, 5 * s, 5 * s},
			wantPolls: 3,
		},
		"slow_down adds 5 seconds to this and every later wait": {
			steps:     []tokenStep{stepOAuthError("slow_down"), stepOAuthError("authorization_pending"), stepToken},
			wantWaits: []time.Duration{5 * s, 10 * s, 10 * s},
			wantPolls: 3,
		},
		"access_denied stops": {
			steps:     []tokenStep{stepOAuthError("access_denied")},
			wantWaits: []time.Duration{5 * s},
			wantPolls: 1,
			wantCode:  "access_denied",
		},
		"clock passes expires_at while pending": {
			steps:     []tokenStep{stepOAuthError("authorization_pending")},
			expiresIn: 12,
			wantWaits: []time.Duration{5 * s, 5 * s},
			wantPolls: 2,
			wantCode:  "expired_token",
		},
		"expired_token from the server stops": {
			steps:     []tokenStep{stepOAuthError("expired_token")},
			wantWaits: []time.Duration{5 * s},
			wantPolls: 1,
			wantCode:  "expired_token",
		},
		"invalid_grant from the server stops": {
			steps:     []tokenStep{stepOAuthError("invalid_grant")},
			wantWaits: []time.Duration{5 * s},
			wantPolls: 1,
			wantCode:  "invalid_grant",
		},
		"interval longer than the time left stops without waiting": {
			steps:     []tokenStep{stepToken},
			interval:  700,
			wantPolls: 0,
			wantCode:  "expired_token",
		},
		"interval too large for a Duration stops without waiting": {
			steps:     []tokenStep{stepToken},
			interval:  math.MaxInt,
			wantPolls: 0,
			wantCode:  "expired_token",
		},
		"429 stops and reports the interval": {
			steps:            []tokenStep{stepStatus(http.StatusTooManyRequests)},
			wantWaits:        []time.Duration{5 * s},
			wantPolls:        1,
			wantHTTP:         http.StatusTooManyRequests,
			wantPollInterval: 5 * s,
		},
		"slow_down, then a network error reports the raised interval": {
			steps:            []tokenStep{stepOAuthError("slow_down"), stepNetwork},
			wantWaits:        []time.Duration{5 * s, 10 * s},
			wantPolls:        2,
			wantNetwork:      true,
			wantPollInterval: 10 * s,
		},
		"start interval sets the first wait": {
			steps:     []tokenStep{stepOAuthError("authorization_pending"), stepToken},
			start:     10 * s,
			wantWaits: []time.Duration{10 * s, 10 * s},
			wantPolls: 2,
		},
		"start interval below the authorization's interval": {
			steps:      []tokenStep{stepToken},
			start:      3 * s,
			wantPolls:  0,
			wantConfig: true,
		},
		// The SDK does not associate the token with a resource, so a resource field in
		// the response does not appear in the result.
		"token response with a resource field": {
			steps:     []tokenStep{stepTokenWithResource},
			wantWaits: []time.Duration{5 * s},
			wantPolls: 1,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			zone := newDeviceZone(t)
			zone.script(tc.steps...)
			clock := newFakeDeviceClock()
			client := mustDeviceClient(t, zone.URL,
				WithDeviceHTTPClient(zone.httpClient()),
				WithDevicePublicClient("public-1"),
				WithDeviceClock(clock))

			interval := tc.interval
			if interval == 0 {
				interval = 5
			}
			expiresIn := tc.expiresIn
			if expiresIn == 0 {
				expiresIn = 600
			}
			auth := DeviceAuthorization{
				DeviceCode: "device-code-1",
				Interval:   interval,
				ExpiresIn:  expiresIn,
				ExpiresAt:  clock.Now().Add(time.Duration(expiresIn) * time.Second),
			}
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
			var pollErr *DevicePollError
			isPollErr := errors.As(err, &pollErr)
			switch {
			case tc.wantPollInterval != 0 && !isPollErr:
				t.Errorf("error: got %v (%T), want *DevicePollError", err, err)
			case tc.wantPollInterval != 0 && pollErr.Interval != tc.wantPollInterval:
				t.Errorf("DevicePollError.Interval: got %v, want %v", pollErr.Interval, tc.wantPollInterval)
			case tc.wantPollInterval == 0 && isPollErr:
				t.Errorf("error: got *DevicePollError %v, want no DevicePollError", err)
			}
			if got := len(zone.tokenCalls()); got != tc.wantPolls {
				t.Errorf("polls: got %d, want %d", got, tc.wantPolls)
			}
			if got := clock.recordedWaits(); !reflect.DeepEqual(got, tc.wantWaits) {
				t.Errorf("waits: got %v, want %v", got, tc.wantWaits)
			}
		})
	}
}

// Each failure stops the loop after one poll. The caller retries by calling
// WaitForToken again with the same DeviceAuthorization.
func TestWaitForToken_TransportAndServerFailuresStop(t *testing.T) {
	zone := newDeviceZone(t)
	zone.script(stepNetwork, stepStatus(http.StatusServiceUnavailable))
	clock := newFakeDeviceClock()
	client := mustDeviceClient(t, zone.URL,
		WithDeviceHTTPClient(zone.httpClient()),
		WithDevicePublicClient("public-1"),
		WithDeviceClock(clock))
	auth := DeviceAuthorization{DeviceCode: "device-code-1", Interval: 5, ExpiresIn: 600, ExpiresAt: clock.Now().Add(600 * time.Second)}

	_, err := client.WaitForToken(context.Background(), auth)
	if !errors.Is(err, errNetwork) {
		t.Fatalf("first call: got %v, want the transport error", err)
	}
	var pollErr *DevicePollError
	if !errors.As(err, &pollErr) || pollErr.Interval != 5*time.Second {
		t.Errorf("first call: got %v (%T), want *DevicePollError with Interval 5s", err, err)
	}
	if got := len(zone.tokenCalls()); got != 1 {
		t.Fatalf("polls after first call: got %d, want 1", got)
	}

	_, err = client.WaitForToken(context.Background(), auth)
	wantHTTPError(t, err, http.StatusServiceUnavailable)
	if !errors.As(err, &pollErr) || pollErr.Interval != 5*time.Second {
		t.Errorf("second call: got %v (%T), want *DevicePollError with Interval 5s", err, err)
	}
	if got := len(zone.tokenCalls()); got != 2 {
		t.Errorf("polls after second call: got %d, want 2", got)
	}
}

// Resuming with the Interval from a DevicePollError keeps the slow_down increase, so
// the resumed loop does not poll faster than the server asked.
func TestWaitForToken_ResumeAfterSlowDown(t *testing.T) {
	zone := newDeviceZone(t)
	zone.script(stepOAuthError("slow_down"), stepNetwork, stepToken)
	clock := newFakeDeviceClock()
	client := mustDeviceClient(t, zone.URL,
		WithDeviceHTTPClient(zone.httpClient()),
		WithDevicePublicClient("public-1"),
		WithDeviceClock(clock))
	auth := DeviceAuthorization{DeviceCode: "device-code-1", Interval: 5, ExpiresIn: 600, ExpiresAt: clock.Now().Add(600 * time.Second)}

	_, err := client.WaitForToken(context.Background(), auth)
	var pollErr *DevicePollError
	if !errors.As(err, &pollErr) {
		t.Fatalf("first call: got %v (%T), want *DevicePollError", err, err)
	}

	if _, err := client.WaitForToken(context.Background(), auth, WithStartInterval(pollErr.Interval)); err != nil {
		t.Fatalf("resumed call: %v", err)
	}
	want := []time.Duration{5 * time.Second, 10 * time.Second, 10 * time.Second}
	if got := clock.recordedWaits(); !reflect.DeepEqual(got, want) {
		t.Errorf("waits: got %v, want %v", got, want)
	}
	if got := len(zone.tokenCalls()); got != 3 {
		t.Errorf("polls: got %d, want 3", got)
	}
}

// Each request in one flow signs its own assertion for the endpoint it goes to.
// Reusing the device authorization assertion for a poll would send the wrong aud.
func TestDeviceFlow_WebIdentityAssertionPerRequest(t *testing.T) {
	zone := newDeviceZone(t)
	zone.script(stepOAuthError("authorization_pending"), stepToken)
	clock := newFakeDeviceClock()
	cred := NewWebIdentity(WithClientID("client-a"), WithStorageDir(t.TempDir()))
	client := mustDeviceClient(t, zone.URL,
		WithDeviceHTTPClient(zone.httpClient()),
		WithDeviceCredential(cred),
		WithDeviceClock(clock))

	auth, err := client.RequestDeviceAuthorization(context.Background(), DeviceAuthorizationRequest{})
	if err != nil {
		t.Fatalf("RequestDeviceAuthorization: %v", err)
	}
	if _, err := client.WaitForToken(context.Background(), *auth); err != nil {
		t.Fatalf("WaitForToken: %v", err)
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

func TestWaitForToken_Cancellation(t *testing.T) {
	cases := map[string]struct {
		// setup arranges for cancel to run during the wait or during the request.
		setup     func(zone *deviceZone, clock *fakeDeviceClock, cancel context.CancelFunc)
		wantPolls int
	}{
		"during the wait": {
			setup: func(_ *deviceZone, clock *fakeDeviceClock, cancel context.CancelFunc) {
				clock.onAfter = func(time.Duration) <-chan time.Time {
					cancel()
					return make(chan time.Time) // never fires
				}
			},
			wantPolls: 0,
		},
		"during the request": {
			setup: func(zone *deviceZone, _ *fakeDeviceClock, cancel context.CancelFunc) {
				zone.onToken = func(r *http.Request) {
					cancel()
					<-r.Context().Done()
				}
			},
			wantPolls: 1,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			zone := newDeviceZone(t)
			zone.script(stepOAuthError("authorization_pending"))
			clock := newFakeDeviceClock()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			tc.setup(zone, clock, cancel)
			client := mustDeviceClient(t, zone.URL,
				WithDeviceHTTPClient(zone.httpClient()),
				WithDevicePublicClient("public-1"),
				WithDeviceClock(clock))
			auth := DeviceAuthorization{DeviceCode: "device-code-1", Interval: 5, ExpiresIn: 600, ExpiresAt: clock.Now().Add(600 * time.Second)}

			_, err := client.WaitForToken(ctx, auth)
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("error: got %v, want context.Canceled", err)
			}
			if got := len(zone.tokenCalls()); got != tc.wantPolls {
				t.Errorf("polls: got %d, want %d", got, tc.wantPolls)
			}
		})
	}
}

// A DeviceAuthorization round-trips through JSON, so another process can poll with it.
func TestWaitForToken_PersistedDeviceAuthorization(t *testing.T) {
	zone := newDeviceZone(t)
	zone.script(stepToken)
	clock := newFakeDeviceClock()
	opts := []DeviceAuthorizationOption{
		WithDeviceHTTPClient(zone.httpClient()),
		WithDevicePublicClient("public-1"),
		WithDeviceClock(clock),
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

func TestWaitForToken_IncompleteDeviceAuthorization(t *testing.T) {
	cases := map[string]DeviceAuthorization{
		"no device_code": {Interval: 5, ExpiresAt: time.Now().Add(time.Minute)},
		"no expires_at":  {DeviceCode: "device-code-1", Interval: 5},
	}
	for name, auth := range cases {
		t.Run(name, func(t *testing.T) {
			zone := newDeviceZone(t)
			client := mustDeviceClient(t, zone.URL, WithDeviceHTTPClient(zone.httpClient()), WithDevicePublicClient("public-1"))

			_, err := client.WaitForToken(context.Background(), auth)
			var cfgErr *ConfigurationError
			if !errors.As(err, &cfgErr) {
				t.Fatalf("error: got %v, want *ConfigurationError", err)
			}
			if got := len(zone.tokenCalls()); got != 0 {
				t.Errorf("polls: got %d, want 0", got)
			}
		})
	}
}
