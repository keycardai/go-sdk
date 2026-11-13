package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
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

// fakeZone is a fake authorization server with discovery, a device authorization
// endpoint, and a token endpoint that plays back scripted steps.
type fakeZone struct {
	*httptest.Server
	t *testing.T

	discoveryRequests  atomic.Int32
	omitDeviceEndpoint atomic.Bool
	// discoveryStatus, when set, is the status of every discovery response, with no
	// body.
	discoveryStatus atomic.Int32
	// delay holds each discovery, device authorization, and token response back this
	// long, or until the client gives up on the request. Set it before the first
	// request. mu does not guard it.
	delay time.Duration

	mu             sync.Mutex
	deviceBody     any
	deviceStatus   int
	deviceRequests []recordedRequest
	tokenSteps     []tokenStep
	tokenRequests  []recordedRequest
	// onToken, when set, writes the response to each token request. The request
	// still uses up a scripted step.
	onToken func(w http.ResponseWriter, r *http.Request)
}

func newFakeZone(t *testing.T) *fakeZone {
	z := &fakeZone{
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
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		z.discoveryRequests.Add(1)
		if !z.wait(r) {
			return
		}
		if status := z.discoveryStatus.Load(); status != 0 {
			w.WriteHeader(int(status))
			return
		}
		writeJSON(w, http.StatusOK, z.metadata())
	})
	mux.HandleFunc("/device/authorize", func(w http.ResponseWriter, r *http.Request) {
		rec := z.record(r)
		z.mu.Lock()
		z.deviceRequests = append(z.deviceRequests, rec)
		status, body := z.deviceStatus, z.deviceBody
		z.mu.Unlock()
		if !z.wait(r) {
			return
		}
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
			onToken(w, r)
			return
		}
		if !z.wait(r) {
			return
		}
		writeJSON(w, step.status, step.body)
	})
	z.Server = httptest.NewServer(mux)
	t.Cleanup(z.Close)
	return z
}

// wait sleeps for z.delay. It returns false when the client gave up first.
func (z *fakeZone) wait(r *http.Request) bool {
	if z.delay == 0 {
		return true
	}
	select {
	case <-time.After(z.delay):
		return true
	case <-r.Context().Done():
		return false
	}
}

func (z *fakeZone) metadata() *AuthorizationServerMetadata {
	md := &AuthorizationServerMetadata{Issuer: z.URL, TokenEndpoint: z.URL + "/token"}
	if !z.omitDeviceEndpoint.Load() {
		md.DeviceAuthorizationEndpoint = z.URL + "/device/authorize"
	}
	return md
}

func (z *fakeZone) record(r *http.Request) recordedRequest {
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
func (z *fakeZone) nextStep() tokenStep {
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

func (z *fakeZone) script(steps ...tokenStep) {
	z.mu.Lock()
	z.tokenSteps = steps
	z.mu.Unlock()
}

func (z *fakeZone) deviceCalls() []recordedRequest {
	z.mu.Lock()
	defer z.mu.Unlock()
	return append([]recordedRequest(nil), z.deviceRequests...)
}

func (z *fakeZone) tokenCalls() []recordedRequest {
	z.mu.Lock()
	defer z.mu.Unlock()
	return append([]recordedRequest(nil), z.tokenRequests...)
}

// RoundTrip fails a token request when the next scripted step is a network failure,
// so the request never reaches the server. Other requests go to the server.
func (z *fakeZone) RoundTrip(r *http.Request) (*http.Response, error) {
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

func (z *fakeZone) httpClient() *http.Client { return &http.Client{Transport: z} }

// corruptGzip as a response body sends Content-Encoding gzip with a body that is not
// gzip.
type corruptGzip struct{}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	if _, ok := body.(corruptGzip); ok {
		w.Header().Set("Content-Encoding", "gzip")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"access_token":"access-1"}`))
		return
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// fakeAuthenticator is an ApplicationCredential that returns fixed client
// authentication and records each call.
type fakeAuthenticator struct {
	noClientAuthentication
	// failOn, when set, makes client authentication for that endpoint path fail with
	// errClientAuthentication.
	failOn string
	mu     sync.Mutex
	calls  [][2]string // issuer, endpoint
}

var errClientAuthentication = errors.New("identity token source unavailable")

// noClientAuthentication is an ApplicationCredential that does not implement
// ClientAuthenticator.
type noClientAuthentication struct{}

func (noClientAuthentication) Auth(string) *ClientAuth { return nil }

func (noClientAuthentication) PrepareTokenExchangeRequest(context.Context, string, string, *PrepareOptions) (*TokenExchangeRequest, error) {
	return nil, errors.New("not used")
}

func (f *fakeAuthenticator) ClientAuthentication(_ context.Context, issuer, endpoint string) (*ClientAuthentication, error) {
	f.mu.Lock()
	f.calls = append(f.calls, [2]string{issuer, endpoint})
	f.mu.Unlock()
	if f.failOn != "" && strings.HasSuffix(endpoint, f.failOn) {
		return nil, errClientAuthentication
	}
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
