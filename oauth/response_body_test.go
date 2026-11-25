package oauth

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func makeOversizedJSON(extra int) []byte {
	prefix := `{"access_token":"tok","token_type":"Bearer","pad":"`
	suffix := `"}`
	padLen := int(MaxResponseBodyBytes) - len(prefix) - len(suffix) + extra
	return []byte(prefix + strings.Repeat("a", padLen) + suffix)
}

func makeExactLimitJSON() []byte {
	return makeOversizedJSON(0)
}

func gzipBytes(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write(data); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

// Spec row 1: gzip token response inflates above 1 MiB; reading stops at the decoded limit and returns invalid_response.
func TestResponseBodyLimit_GzipTokenResponse(t *testing.T) {
	compressed := gzipBytes(t, makeOversizedJSON(1024))
	if int64(len(compressed)) >= MaxResponseBodyBytes {
		t.Fatalf("expected compressed size < 1 MiB, got %d", len(compressed))
	}

	var srvURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/oauth-authorization-server" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{
				"issuer":         srvURL,
				"token_endpoint": srvURL + "/token",
			})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", "gzip")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(compressed)
	}))
	defer srv.Close()
	srvURL = srv.URL

	client := NewClientCredentialsClient(srv.URL,
		WithCCBasicAuth("cid", "csec"),
		WithCCHTTPClient(srv.Client()),
	)
	_, err := client.RequestToken(context.Background(), ClientCredentialsRequest{})
	if err == nil {
		t.Fatal("expected error for oversized gzip token response")
	}
	var oauthErr *OAuthError
	if !errors.As(err, &oauthErr) {
		t.Fatalf("want *OAuthError, got %T: %v", err, err)
	}
	if oauthErr.ErrorCode != "invalid_response" {
		t.Errorf("ErrorCode = %q, want invalid_response", oauthErr.ErrorCode)
	}
	if oauthErr.Status != http.StatusOK {
		t.Errorf("Status = %d, want 200", oauthErr.Status)
	}
	if !errors.Is(err, ErrResponseBodyTooLarge) {
		t.Errorf("expected ErrResponseBodyTooLarge in chain, got %v", err)
	}
}

// Spec row 1: exact 1 MiB decoded body succeeds and 1 MiB + 1 byte fails.
func TestResponseBodyLimit_ExactBoundary(t *testing.T) {
	exact := makeExactLimitJSON()
	over := makeOversizedJSON(1)
	if int64(len(exact)) != MaxResponseBodyBytes {
		t.Fatalf("exact len = %d", len(exact))
	}
	if int64(len(over)) != MaxResponseBodyBytes+1 {
		t.Fatalf("over len = %d", len(over))
	}

	var sendOver atomic.Bool
	var srvURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/oauth-authorization-server" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{
				"issuer":         srvURL,
				"token_endpoint": srvURL + "/token",
			})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if sendOver.Load() {
			_, _ = w.Write(over)
		} else {
			_, _ = w.Write(exact)
		}
	}))
	defer srv.Close()
	srvURL = srv.URL

	client := NewClientCredentialsClient(srv.URL,
		WithCCBasicAuth("cid", "csec"),
		WithCCHTTPClient(srv.Client()),
	)
	tok, err := client.RequestToken(context.Background(), ClientCredentialsRequest{})
	if err != nil {
		t.Fatalf("exact 1 MiB body should succeed, got: %v", err)
	}
	if tok.AccessToken != "tok" {
		t.Errorf("AccessToken = %q, want tok", tok.AccessToken)
	}

	sendOver.Store(true)
	_, err = client.RequestToken(context.Background(), ClientCredentialsRequest{})
	if !errors.Is(err, ErrResponseBodyTooLarge) {
		t.Fatalf("1 MiB + 1 byte should fail with ErrResponseBodyTooLarge, got: %v", err)
	}
}

// Spec row 1a: cached discovery lookup receives oversized bodies with 200, 429, 503, or 400; transient statuses are not negatively cached while 400 may be cached.
func TestResponseBodyLimit_DiscoveryNegativeCaching(t *testing.T) {
	cases := []struct {
		status             int
		wantNegativeCached bool
	}{
		{http.StatusOK, false},
		{http.StatusCreated, false},
		{http.StatusTooManyRequests, false},
		{http.StatusServiceUnavailable, false},
		{http.StatusBadRequest, true},
	}

	for _, tc := range cases {
		var calls atomic.Int32
		var failFirst atomic.Bool
		failFirst.Store(true)

		var srvURL string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls.Add(1)
			w.Header().Set("Content-Type", "application/json")
			if failFirst.Load() {
				w.WriteHeader(tc.status)
				_, _ = w.Write(makeOversizedJSON(1024))
				return
			}
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"issuer":         srvURL,
				"token_endpoint": srvURL + "/token",
			})
		}))
		srvURL = srv.URL

		client := NewTokenExchangeClient(srv.URL,
			WithClientCredentials("cid", "csec"),
			WithTokenExchangeHTTPClient(srv.Client()),
			WithTokenExchangeNegativeTTL(time.Minute),
		)
		advance := fakeClock(client)

		_, err := client.TokenEndpoint(context.Background())
		var discoveryErr *TokenEndpointDiscoveryError
		if !errors.As(err, &discoveryErr) {
			srv.Close()
			t.Fatalf("status %d: want *TokenEndpointDiscoveryError, got %T: %v", tc.status, err, err)
		}
		if got := discoveryErr.Retryable(); got == tc.wantNegativeCached {
			t.Errorf("status %d: Retryable() = %v, want %v", tc.status, got, !tc.wantNegativeCached)
		}
		var httpErr *HTTPError
		if !errors.As(err, &httpErr) || httpErr.Status != tc.status {
			t.Errorf("status %d: expected matching HTTPError in %v", tc.status, err)
		}
		if calls.Load() != 1 {
			srv.Close()
			t.Fatalf("status %d: calls = %d, want 1", tc.status, calls.Load())
		}

		failFirst.Store(false)
		if tc.status == http.StatusServiceUnavailable {
			// Past the initial retry delay, well inside negative_ttl.
			advance(2 * time.Second)
		}
		ep, err := client.TokenEndpoint(context.Background())
		srv.Close()

		if tc.wantNegativeCached {
			if err == nil {
				t.Errorf("status %d: expected cached error, got endpoint %q", tc.status, ep)
			}
			if calls.Load() != 1 {
				t.Errorf("status %d: calls = %d, want 1 (negatively cached)", tc.status, calls.Load())
			}
		} else {
			if err != nil {
				t.Errorf("status %d: expected recovery on retry, got error: %v", tc.status, err)
			}
			if ep != srvURL+"/token" {
				t.Errorf("status %d: endpoint = %q, want %q", tc.status, ep, srvURL+"/token")
			}
			if calls.Load() != 2 {
				t.Errorf("status %d: calls = %d, want 2 (not negatively cached)", tc.status, calls.Load())
			}
		}
	}
}

// Spec row 1a: oversized JWKS discovery and key set responses are retryable without a delay.
func TestResponseBodyLimit_JWKS(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for _, status := range []int{http.StatusOK, http.StatusCreated} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			testResponseBodyLimitJWKS(t, privateKey, status)
		})
	}
}

func testResponseBodyLimitJWKS(t *testing.T, privateKey *rsa.PrivateKey, status int) {
	t.Helper()
	var discoveryCalls, jwksCalls atomic.Int32
	var srvURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/.well-known/oauth-authorization-server" {
			if discoveryCalls.Add(1) == 1 {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(makeOversizedJSON(1024))
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]string{
				"issuer":   srvURL,
				"jwks_uri": srvURL + "/jwks.json",
			})
			return
		}
		if jwksCalls.Add(1) == 1 {
			w.WriteHeader(status)
			_, _ = w.Write(makeOversizedJSON(1024))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "kid": "k1", "n": Base64URLEncode(privateKey.N.Bytes()), "e": "AQAB",
		}}})
	}))
	defer srv.Close()
	srvURL = srv.URL

	kr := NewJWKSOAuthKeyring(WithKeyringHTTPClient(srv.Client()))
	kr.now = newFakeDeviceClock().Now
	_, err := kr.Key(context.Background(), srv.URL, "k1")
	var discErr *JWKSDiscoveryError
	if !errors.As(err, &discErr) {
		t.Fatalf("oversized discovery: want *JWKSDiscoveryError, got %T: %v", err, err)
	}
	if !discErr.Retryable() || !errors.Is(err, ErrResponseBodyTooLarge) {
		t.Errorf("expected retryable oversized discovery error, got %v", err)
	}
	var httpErr *HTTPError
	if !errors.As(err, &httpErr) || httpErr.Status != http.StatusOK {
		t.Errorf("expected HTTP 200 in %v", err)
	}

	_, err = kr.Key(context.Background(), srv.URL, "k1")
	var fetchErr *JWKSFetchError
	if !errors.As(err, &fetchErr) {
		t.Fatalf("oversized jwks: want *JWKSFetchError, got %T: %v", err, err)
	}
	if !errors.Is(err, ErrResponseBodyTooLarge) {
		t.Errorf("expected ErrResponseBodyTooLarge in JWKSFetchError chain, got %v", err)
	}
	if !fetchErr.Retryable() {
		t.Errorf("expected retryable JWKSFetchError, got %v", err)
	}
	if !errors.As(err, &httpErr) || httpErr.Status != status {
		t.Errorf("expected HTTP %d in %v", status, err)
	}

	key, err := kr.Key(context.Background(), srv.URL, "k1")
	if err != nil || key == nil {
		t.Errorf("immediate key lookup = (%v, %v), want a key", key, err)
	}
	if got := discoveryCalls.Load(); got != 2 {
		t.Errorf("discovery requests = %d, want 2", got)
	}
	if got := jwksCalls.Load(); got != 2 {
		t.Errorf("JWKS requests = %d, want 2", got)
	}
}

// Spec row 1a: oversized device discovery is retryable without a delay.
func TestResponseBodyLimit_DeviceDiscovery(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.Header().Set("Retry-After", "60")
			_, _ = w.Write(makeOversizedJSON(1024))
			return
		}
		issuer := "http://" + r.Host
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer": issuer, "token_endpoint": issuer + "/token",
			"device_authorization_endpoint": issuer + "/device",
		})
	}))
	defer srv.Close()
	client, err := NewDeviceAuthorizationClient(srv.URL,
		WithDevicePublicClient("cid"), WithDeviceHTTPClient(srv.Client()))
	if err != nil {
		t.Fatal(err)
	}
	client.metadata.now = newFakeDeviceClock().Now

	_, err = client.resolveMetadata(context.Background())
	var discoveryErr *DeviceAuthorizationDiscoveryError
	if !errors.As(err, &discoveryErr) || !errors.Is(err, ErrResponseBodyTooLarge) {
		t.Fatalf("want oversized device discovery error, got %v", err)
	}
	if !discoveryErr.Retryable() {
		t.Errorf("expected retryable device discovery error, got %v", err)
	}
	md, err := client.resolveMetadata(context.Background())
	if err != nil || md == nil || md.DeviceAuthorizationEndpoint != srv.URL+"/device" {
		t.Errorf("immediate discovery = (%v, %v), want device metadata", md, err)
	}
	if got := calls.Load(); got != 2 {
		t.Errorf("discovery requests = %d, want 2", got)
	}
}

// Spec row 1c: token endpoint returns 400 with oversized body; returns invalid_response with status 400 and no OAuth error body parsing.
func TestResponseBodyLimit_TokenEndpoint400Oversized(t *testing.T) {
	prefix := `{"error":"invalid_grant","error_description":"`
	suffix := `"}`
	body := []byte(prefix + strings.Repeat("x", int(MaxResponseBodyBytes)-len(prefix)-len(suffix)+256) + suffix)

	var srvURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/oauth-authorization-server" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{
				"issuer":         srvURL,
				"token_endpoint": srvURL + "/token",
			})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write(body)
	}))
	defer srv.Close()
	srvURL = srv.URL

	te := NewTokenExchangeClient(srv.URL,
		WithClientCredentials("cid", "csec"),
		WithTokenExchangeHTTPClient(srv.Client()),
	)
	_, err := te.ExchangeToken(context.Background(), TokenExchangeRequest{
		SubjectToken: "sub-tok",
		Resource:     "https://api.example",
	})
	var oauthErr *OAuthError
	if !errors.As(err, &oauthErr) {
		t.Fatalf("want *OAuthError, got %T: %v", err, err)
	}
	if oauthErr.ErrorCode != "invalid_response" {
		t.Errorf("ErrorCode = %q, want invalid_response (must not parse invalid_grant)", oauthErr.ErrorCode)
	}
	if oauthErr.Status != http.StatusBadRequest {
		t.Errorf("Status = %d, want 400", oauthErr.Status)
	}
}

// Spec row 1b and device row 36: device poll oversized body on 429/503 wraps in DevicePollError with undoubled interval; PollToken returns invalid_response on 200/400/429/503.
func TestResponseBodyLimit_DevicePolling(t *testing.T) {
	for _, status := range []int{http.StatusTooManyRequests, http.StatusServiceUnavailable} {
		var pollCount atomic.Int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			n := pollCount.Add(1)
			w.Header().Set("Content-Type", "application/json")
			if n == 1 {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"slow_down"}`))
				return
			}
			w.WriteHeader(status)
			_, _ = w.Write(makeOversizedJSON(1024))
		}))

		clk := newFakeDeviceClock()
		md := &AuthorizationServerMetadata{
			Issuer:                      srv.URL,
			DeviceAuthorizationEndpoint: srv.URL + "/device",
			TokenEndpoint:               srv.URL + "/token",
		}
		client, err := NewDeviceAuthorizationClient(srv.URL,
			WithDevicePublicClient("cid"),
			WithDeviceMetadata(md),
			WithDeviceHTTPClient(srv.Client()),
			WithDeviceClock(clk),
		)
		if err != nil {
			srv.Close()
			t.Fatalf("NewDeviceAuthorizationClient: %v", err)
		}

		auth := DeviceAuthorization{
			DeviceCode:      "dev-1",
			UserCode:        "ABCD-1234",
			VerificationURI: srv.URL + "/verify",
			ExpiresIn:       600,
			Interval:        5,
			ExpiresAt:       clk.Now().Add(600 * time.Second),
		}
		_, err = client.WaitForToken(context.Background(), auth)
		srv.Close()

		var pollErr *DevicePollError
		if !errors.As(err, &pollErr) {
			t.Fatalf("status %d: want *DevicePollError, got %T: %v", status, err, err)
		}
		// slow_down raised 5s -> 10s; oversized 429/503 must NOT double to 20s.
		if pollErr.Interval != 10*time.Second {
			t.Errorf("status %d: Interval = %v, want 10s", status, pollErr.Interval)
		}
		var oauthErr *OAuthError
		if !errors.As(pollErr.Err, &oauthErr) {
			t.Fatalf("status %d: pollErr.Err want *OAuthError, got %T: %v", status, pollErr.Err, pollErr.Err)
		}
		if oauthErr.ErrorCode != "invalid_response" || oauthErr.Status != status {
			t.Errorf("status %d: oauthErr = (%q, %d), want (invalid_response, %d)", status, oauthErr.ErrorCode, oauthErr.Status, status)
		}
	}

	for _, status := range []int{http.StatusOK, http.StatusBadRequest, http.StatusTooManyRequests, http.StatusServiceUnavailable} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_, _ = w.Write(makeOversizedJSON(512))
		}))
		md := &AuthorizationServerMetadata{
			Issuer:                      srv.URL,
			DeviceAuthorizationEndpoint: srv.URL + "/device",
			TokenEndpoint:               srv.URL + "/token",
		}
		client, err := NewDeviceAuthorizationClient(srv.URL,
			WithDevicePublicClient("cid"),
			WithDeviceMetadata(md),
			WithDeviceHTTPClient(srv.Client()),
		)
		if err != nil {
			srv.Close()
			t.Fatalf("NewDeviceAuthorizationClient: %v", err)
		}
		_, err = client.PollToken(context.Background(), DeviceAuthorization{DeviceCode: "dev-1"})
		srv.Close()

		var oauthErr *OAuthError
		if !errors.As(err, &oauthErr) {
			t.Fatalf("PollToken status %d: want *OAuthError, got %T: %v", status, err, err)
		}
		if oauthErr.ErrorCode != "invalid_response" || oauthErr.Status != status {
			t.Errorf("PollToken status %d: got (%q, %d), want (invalid_response, %d)", status, oauthErr.ErrorCode, oauthErr.Status, status)
		}
	}
}

// DCR and UserInfo reject oversized 200 bodies with invalid_response.
func TestResponseBodyLimit_DCRAndUserInfo(t *testing.T) {
	var srvURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/.well-known/oauth-authorization-server" {
			_ = json.NewEncoder(w).Encode(map[string]string{
				"issuer":                srvURL,
				"registration_endpoint": srvURL + "/register",
				"userinfo_endpoint":     srvURL + "/userinfo",
			})
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(makeOversizedJSON(1024))
	}))
	defer srv.Close()
	srvURL = srv.URL

	_, err := RegisterClient(context.Background(), srv.URL, RegistrationRequest{ClientName: "app"}, WithRegistrationHTTPClient(srv.Client()))
	var oauthErr *OAuthError
	if !errors.As(err, &oauthErr) || oauthErr.ErrorCode != "invalid_response" {
		t.Errorf("DCR oversized: want *OAuthError(invalid_response), got %T: %v", err, err)
	}

	_, err = FetchUserInfo(context.Background(), srv.URL, "access-tok", WithUserInfoHTTPClient(srv.Client()))
	oauthErr = nil
	if !errors.As(err, &oauthErr) || oauthErr.ErrorCode != "invalid_response" {
		t.Errorf("UserInfo oversized: want *OAuthError(invalid_response), got %T: %v", err, err)
	}
}

// Spec row 1c: an oversized body on a non-2xx status other than 429 or 5xx is not retryable.
func TestResponseBodyLimit_OversizedRetryable(t *testing.T) {
	cases := []struct {
		status int
		want   bool
	}{
		{http.StatusOK, true},
		{http.StatusBadRequest, false},
		{http.StatusUnauthorized, false},
		{http.StatusNotFound, false},
		{http.StatusTooManyRequests, true},
		{http.StatusInternalServerError, true},
		{http.StatusServiceUnavailable, true},
	}
	for _, tc := range cases {
		if got := oversizedOAuthError(tc.status).Retryable(); got != tc.want {
			t.Errorf("status %d: Retryable() = %v, want %v", tc.status, got, tc.want)
		}
	}
}

// Spec row 36: device authorization WaitForToken returns invalid_response directly for an oversized 200 or 400.
func TestResponseBodyLimit_WaitForTokenOversized(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusBadRequest} {
		var polls atomic.Int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			polls.Add(1)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_, _ = w.Write(makeOversizedJSON(512))
		}))
		clk := newFakeDeviceClock()
		md := &AuthorizationServerMetadata{
			Issuer:                      srv.URL,
			DeviceAuthorizationEndpoint: srv.URL + "/device",
			TokenEndpoint:               srv.URL + "/token",
		}
		client, err := NewDeviceAuthorizationClient(srv.URL,
			WithDevicePublicClient("cid"),
			WithDeviceMetadata(md),
			WithDeviceHTTPClient(srv.Client()),
			WithDeviceClock(clk),
		)
		if err != nil {
			srv.Close()
			t.Fatalf("NewDeviceAuthorizationClient: %v", err)
		}
		_, err = client.WaitForToken(context.Background(), DeviceAuthorization{
			DeviceCode:      "dev-1",
			UserCode:        "ABCD-1234",
			VerificationURI: srv.URL + "/verify",
			ExpiresIn:       600,
			Interval:        5,
			ExpiresAt:       clk.Now().Add(600 * time.Second),
		})
		srv.Close()

		var pollErr *DevicePollError
		if errors.As(err, &pollErr) {
			t.Fatalf("status %d: got *DevicePollError %v, want *OAuthError directly", status, err)
		}
		oauthErr, ok := err.(*OAuthError)
		if !ok {
			t.Fatalf("status %d: want *OAuthError, got %T: %v", status, err, err)
		}
		if oauthErr.ErrorCode != "invalid_response" || oauthErr.Status != status {
			t.Errorf("status %d: got (%q, %d), want (invalid_response, %d)", status, oauthErr.ErrorCode, oauthErr.Status, status)
		}
		if !errors.Is(err, ErrResponseBodyTooLarge) {
			t.Errorf("status %d: error does not wrap ErrResponseBodyTooLarge", status)
		}
		if got := polls.Load(); got != 1 {
			t.Errorf("status %d: polls = %d, want 1", status, got)
		}
	}
}
