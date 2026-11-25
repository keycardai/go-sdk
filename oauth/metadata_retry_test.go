package oauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"testing/iotest"
	"time"
)

type metadataTestTransport func(*http.Request) (*http.Response, error)

func (f metadataTestTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

// Spec row 10 (JWKS caching): a JWKS network failure gates lookups until its backoff elapses.
// Spec row 11 (JWKS caching): a discovery network failure gates lookups until its backoff elapses.
// Spec row 20 (JWKS caching): a 429 with Retry-After gates lookups for another kid of the same key set.
func TestKeyringMetadataRetry(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name      string
		discovery bool
		throttle  bool
	}{
		{name: "JWKS network error"}, {name: "discovery network error", discovery: true},
		{name: "JWKS truncated response"}, {name: "discovery truncated response", discovery: true},
		{name: "429 for two kids", throttle: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var failed atomic.Bool
			var requests atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				discovery := r.URL.Path != "/jwks"
				if discovery {
					_ = json.NewEncoder(w).Encode(map[string]string{"issuer": "http://" + r.Host, "jwks_uri": "http://" + r.Host + "/jwks"})
				} else {
					_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
						"kty": "RSA", "kid": "key", "n": Base64URLEncode(privateKey.N.Bytes()),
						"e": Base64URLEncode(big.NewInt(int64(privateKey.E)).Bytes()),
					}}})
				}
			}))
			defer srv.Close()
			clock := newFakeDeviceClock()
			client := &http.Client{Transport: metadataTestTransport(func(r *http.Request) (*http.Response, error) {
				if (r.URL.Path != "/jwks") == test.discovery {
					requests.Add(1)
					if !failed.Swap(true) {
						if test.throttle {
							return &http.Response{StatusCode: 429, Header: http.Header{"Retry-After": {"120"}}, Body: http.NoBody}, nil
						}
						if strings.Contains(test.name, "truncated") {
							return &http.Response{StatusCode: 200, Body: io.NopCloser(io.MultiReader(
								strings.NewReader("{"), iotest.ErrReader(io.ErrUnexpectedEOF)))}, nil
						}
						return nil, io.ErrUnexpectedEOF
					}
				}
				return http.DefaultTransport.RoundTrip(r)
			})}
			keyring := NewJWKSOAuthKeyring(WithKeyringHTTPClient(client))
			keyring.now = clock.Now
			kid := "key"
			if test.throttle {
				kid = "first"
			}
			_, first := keyring.Key(context.Background(), srv.URL, kid)
			_, gated := keyring.Key(context.Background(), srv.URL, "key")
			var transient interface{ Retryable() bool }
			if !errors.As(first, &transient) || !transient.Retryable() || first != gated || requests.Load() != 1 {
				t.Fatalf("expected shared typed failure, got %v then %v (%d requests)", first, gated, requests.Load())
			}
			delay := 1200 * time.Millisecond
			if test.throttle {
				delay = time.Minute
			}
			clock.advance(delay)
			if _, err := keyring.Key(context.Background(), srv.URL, "key"); err != nil || requests.Load() != 2 {
				t.Fatalf("recovery: %v (%d requests)", err, requests.Load())
			}
		})
	}
}

// Spec row 3 (base): network failures start retry pacing.
// Spec row 5 (base): deterministic failures start no transient backoff.
// Spec row 6 (base): a caller deadline starts no retry delay.
func TestMetadataRetryTransportClassification(t *testing.T) {
	now := time.Now()
	for _, cause := range []error{errors.New("unsupported protocol scheme"), errors.New("stopped after 10 redirects"), x509.UnknownAuthorityError{}} {
		err := &url.Error{Op: "Get", URL: "test://issuer", Err: cause}
		if retryableMetadataFailure(err) || (metadataRetry{}).record(now, err).failure(now) != nil {
			t.Errorf("configuration error marked transient: %v", err)
		}
	}
	if !retryableMetadataFailure(context.Canceled) || (metadataRetry{}).record(now, context.Canceled).failure(now) != nil {
		t.Error("caller cancellation must be retryable without recording a delay")
	}
}

// Spec row 3 (base): a peer stream reset before headers is a network failure.
func TestMetadataRetryHTTP2StreamReset(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		panic(http.ErrAbortHandler)
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()

	keyring := NewJWKSOAuthKeyring(WithKeyringHTTPClient(server.Client()))
	keyring.now = newFakeDeviceClock().Now
	_, first := keyring.Key(context.Background(), server.URL, "key")
	_, gated := keyring.Key(context.Background(), server.URL, "key")
	if first == nil || !strings.Contains(first.Error(), "INTERNAL_ERROR") {
		t.Fatalf("expected HTTP/2 INTERNAL_ERROR, got %v", first)
	}
	if first != gated || requests.Load() != 1 {
		t.Fatalf("HTTP/2 stream reset did not pace the next fetch: requests=%d, errors=%v and %v", requests.Load(), first, gated)
	}
}

// Spec row 2 (base): the asctime HTTP-date grammar allows both day representations.
func TestMetadataRetryAsctimeDays(t *testing.T) {
	now := time.Date(2024, 11, 6, 12, 0, 0, 0, time.UTC)
	for _, header := range []string{"Wed Nov  6 12:00:05 2024", "Wed Nov 06 12:00:05 2024"} {
		if delay, ok := metadataRetryAfter(now, header); !ok || delay != 5*time.Second {
			t.Errorf("Retry-After %q: (%s, %t), want (5s, true)", header, delay, ok)
		}
	}
}

// Spec row 2 (base): an invalid HTTP-date cannot start a 429 delay.
func TestMetadataRetryRejectsInvalidHTTPDate(t *testing.T) {
	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, header := range []string{"Wed, 01 Jan 2025 00:01 GMT", "Wed, 01 Jan 2025 00:00:05.1 GMT", "Wed, 01 Jan 2025 00:00:05 GMT junk"} {
		if _, ok := metadataRetryAfter(now, header); ok {
			t.Errorf("accepted invalid Retry-After: %q", header)
		}
	}
}

// Spec row 3 (base): discovery cooldowns are bounded.
// Spec row 11 (JWKS caching): discovery cooldowns do not survive invalidation.
func TestKeyringMetadataRetryBoundAndInvalidate(t *testing.T) {
	keyring := NewJWKSOAuthKeyring()
	clock := newFakeDeviceClock()
	keyring.now = clock.Now
	for i := 0; i <= maxMetadataRetryEntries; i++ {
		keyring.recordRetry(keyring.discoveryRetry, fmt.Sprint(i), io.ErrUnexpectedEOF, 0)
		clock.advance(time.Millisecond)
	}
	if len(keyring.discoveryRetry) != maxMetadataRetryEntries || keyring.retryFailure(keyring.discoveryRetry, "0") != nil {
		t.Fatal("oldest discovery retry was not evicted")
	}
	keyring.Invalidate("1", "kid")
	keyring.recordRetry(keyring.discoveryRetry, "1", io.ErrUnexpectedEOF, 0)
	if keyring.retryFailure(keyring.discoveryRetry, "1") != nil {
		t.Fatal("a fetch from before invalidation restored its retry delay")
	}
}

// Spec row 11 (authorization server discovery): only cache-backed discovery is paced.
func TestCachedDiscoveryRetryAfter(t *testing.T) {
	ds := newDiscoveryServer()
	defer ds.Close()
	ds.set(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "5")
		w.WriteHeader(503)
	})
	client := NewTokenExchangeClient(ds.URL)
	advance := fakeClock(client)
	var discoveryError *TokenEndpointDiscoveryError
	if _, err := client.TokenEndpoint(context.Background()); !errors.As(err, &discoveryError) {
		t.Fatalf("first discovery error: %v", err)
	}
	ds.recover()
	advance(5*time.Second - time.Millisecond)
	if _, err := client.TokenEndpoint(context.Background()); err != discoveryError || ds.requests.Load() != 1 {
		t.Fatalf("gated discovery: requests %d, error %v", ds.requests.Load(), err)
	}
	if _, err := FetchAuthorizationServerMetadata(context.Background(), ds.URL); err != nil {
		t.Fatalf("standalone discovery: %v", err)
	}
	advance(time.Millisecond)
	if _, err := client.TokenEndpoint(context.Background()); err != nil || ds.requests.Load() != 3 {
		t.Fatalf("discovery at expiry: requests %d, error %v", ds.requests.Load(), err)
	}
}

// Spec row 2 (base): HTTP dates and delta-seconds are honored up to 60 seconds.
func TestMetadataRetryAfterCap(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	for _, status := range []int{429, 503} {
		for _, delay := range []time.Duration{5 * time.Second, 120 * time.Second} {
			for _, header := range []string{fmt.Sprint(int(delay.Seconds())), now.Add(delay).Format(http.TimeFormat)} {
				err := &metadataHTTPError{HTTPError: &HTTPError{Status: status}, retryAfter: header}
				retry := (metadataRetry{}).record(now, err)
				expiry := now.Add(min(time.Minute, delay))
				if retry.failure(expiry.Add(-time.Nanosecond)) != err || retry.failure(expiry) != nil {
					t.Errorf("status %d Retry-After %q was not gated up to %s", status, header, expiry)
				}
			}
		}
	}
}

// Spec row 3 (base): network failures and 5xx use exponential jitter capped at 30 seconds.
func TestMetadataRetryExponentialCap(t *testing.T) {
	now := time.Now()
	for _, err := range []error{context.DeadlineExceeded, &HTTPError{Status: 503}} {
		var retry metadataRetry
		for _, nominal := range []time.Duration{1, 2, 4, 8, 16, 32, 64, 64} {
			retry = retry.record(now, err)
			d := retry.until.Sub(now)
			if d < min(30*time.Second, nominal*800*time.Millisecond) || d > min(30*time.Second, nominal*1200*time.Millisecond) {
				t.Errorf("nominal %ds, got %s", nominal, d)
			}
			if retry.failure(retry.until.Add(-time.Nanosecond)) != err || retry.failure(retry.until) != nil {
				t.Fatal("delay did not gate until expiry")
			}
		}
	}
}

// Spec row 4 (base): a successful metadata refresh resets the exponential step.
func TestMetadataRetryResetsOnSuccess(t *testing.T) {
	ds := newDiscoveryServer()
	defer ds.Close()
	client := NewTokenExchangeClient(ds.URL)
	advance := fakeClock(client)
	for _, delay := range []time.Duration{1200, 2400} {
		ds.status(500)
		if _, err := client.TokenEndpoint(context.Background()); err == nil {
			t.Fatal("expected HTTP failure")
		}
		advance(delay * time.Millisecond)
	}
	ds.recover()
	if _, err := client.TokenEndpoint(context.Background()); err != nil {
		t.Fatal(err)
	}
	advance(defaultDiscoveryTTL)
	ds.status(500)
	if _, err := client.TokenEndpoint(context.Background()); err == nil {
		t.Fatal("expected refresh error")
	}
	advance(1200 * time.Millisecond)
	ds.recover()
	if _, err := client.TokenEndpoint(context.Background()); err != nil {
		t.Fatalf("refresh backoff was not reset: %v", err)
	}
}

// Spec row 1a (base): an oversized 429 without Retry-After starts no retry delay.
func TestMetadataRetryOversized429WithoutRetryAfter(t *testing.T) {
	now := time.Now()
	if retry := (metadataRetry{}).record(now, oversizedOAuthError(http.StatusTooManyRequests)); retry.failure(now) != nil || !retry.until.IsZero() {
		t.Fatalf("oversized 429 error started a delay until %s", retry.until)
	}

	var requests atomic.Int32
	var srvURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if requests.Add(1) == 1 {
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write(makeOversizedJSON(1024))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"issuer": srvURL, "token_endpoint": srvURL + "/token"})
	}))
	defer srv.Close()
	srvURL = srv.URL

	client := NewTokenExchangeClient(srv.URL, WithTokenExchangeHTTPClient(srv.Client()))
	fakeClock(client)
	if _, err := client.TokenEndpoint(context.Background()); err == nil {
		t.Fatal("expected a discovery error for the oversized 429")
	}
	if ep, err := client.TokenEndpoint(context.Background()); err != nil || ep != srvURL+"/token" {
		t.Fatalf("second lookup with the clock unchanged: endpoint %q, error %v", ep, err)
	}
	if got := requests.Load(); got != 2 {
		t.Errorf("requests = %d, want 2 (no delay started)", got)
	}
}
