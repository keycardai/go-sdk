package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// discoveryServer counts discovery requests and lets a test swap the response mid-run.
type discoveryServer struct {
	*httptest.Server
	requests atomic.Int32
	mu       sync.Mutex
	respond  func(w http.ResponseWriter, r *http.Request)
}

func newDiscoveryServer() *discoveryServer {
	ds := &discoveryServer{}
	ds.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/oauth-authorization-server" {
			http.NotFound(w, r)
			return
		}
		ds.requests.Add(1)
		ds.mu.Lock()
		respond := ds.respond
		ds.mu.Unlock()
		if respond != nil {
			respond(w, r)
			return
		}
		ds.serveMetadata(w, map[string]string{"issuer": ds.URL, "token_endpoint": ds.URL + "/token"})
	}))
	return ds
}

func (ds *discoveryServer) serveMetadata(w http.ResponseWriter, md map[string]string) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(md)
}

func (ds *discoveryServer) set(respond func(w http.ResponseWriter, r *http.Request)) {
	ds.mu.Lock()
	ds.respond = respond
	ds.mu.Unlock()
}

func (ds *discoveryServer) status(code int) {
	ds.set(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(code) })
}

func (ds *discoveryServer) recover() { ds.set(nil) }

// fakeClock pins the resolver's clock so TTL expiry is driven by the test.
func fakeClock(c *TokenExchangeClient) func(time.Duration) {
	now := time.Now()
	var mu sync.Mutex
	c.endpoint.now = func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return now
	}
	return func(d time.Duration) {
		mu.Lock()
		now = now.Add(d)
		mu.Unlock()
	}
}

func TestTokenEndpoint_TransientFailureNotCached(t *testing.T) {
	cases := map[string]func(*discoveryServer){
		"500": func(ds *discoveryServer) { ds.status(http.StatusInternalServerError) },
		"503": func(ds *discoveryServer) { ds.status(http.StatusServiceUnavailable) },
		"429": func(ds *discoveryServer) { ds.status(http.StatusTooManyRequests) },
		"connection reset": func(ds *discoveryServer) {
			ds.set(func(w http.ResponseWriter, _ *http.Request) {
				conn, _, err := w.(http.Hijacker).Hijack()
				if err == nil {
					conn.Close()
				}
			})
		},
	}
	for name, fail := range cases {
		t.Run(name, func(t *testing.T) {
			ds := newDiscoveryServer()
			defer ds.Close()
			fail(ds)

			client := NewTokenExchangeClient(ds.URL)
			if _, err := client.TokenEndpoint(context.Background()); err == nil {
				t.Fatal("expected a discovery error")
			}

			ds.recover()
			ep, err := client.TokenEndpoint(context.Background())
			if err != nil {
				t.Fatalf("TokenEndpoint after recovery: %v", err)
			}
			if ep != ds.URL+"/token" {
				t.Errorf("endpoint: got %q", ep)
			}
			if got := ds.requests.Load(); got != 2 {
				t.Errorf("discovery requests: got %d, want 2", got)
			}
		})
	}
}

func TestTokenEndpoint_DeterministicFailureRememberedForNegativeTTL(t *testing.T) {
	cases := map[string]struct {
		fail  func(*discoveryServer)
		check func(t *testing.T, err error)
	}{
		"404": {
			fail: func(ds *discoveryServer) { ds.status(http.StatusNotFound) },
			check: func(t *testing.T, err error) {
				var httpErr *HTTPError
				if !errors.As(err, &httpErr) || httpErr.Status != http.StatusNotFound {
					t.Errorf("errors.As(*HTTPError 404): got %v", err)
				}
			},
		},
		"issuer mismatch": {
			fail: func(ds *discoveryServer) {
				ds.set(func(w http.ResponseWriter, _ *http.Request) {
					ds.serveMetadata(w, map[string]string{"issuer": "https://imposter.example.com", "token_endpoint": ds.URL + "/token"})
				})
			},
			check: func(t *testing.T, err error) {
				var mismatch *IssuerMismatchError
				if !errors.As(err, &mismatch) {
					t.Errorf("errors.As(*IssuerMismatchError): got %v", err)
				}
			},
		},
		"missing token_endpoint": {
			fail: func(ds *discoveryServer) {
				ds.set(func(w http.ResponseWriter, _ *http.Request) {
					ds.serveMetadata(w, map[string]string{"issuer": ds.URL})
				})
			},
			check: func(t *testing.T, err error) {
				var disc *TokenEndpointDiscoveryError
				if !errors.As(err, &disc) || disc.Err != nil {
					t.Errorf("want a bare *TokenEndpointDiscoveryError, got %v", err)
				}
			},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			ds := newDiscoveryServer()
			defer ds.Close()
			tc.fail(ds)

			client := NewTokenExchangeClient(ds.URL)
			advance := fakeClock(client)

			_, err := client.TokenEndpoint(context.Background())
			if err == nil {
				t.Fatal("expected a discovery error")
			}
			var disc *TokenEndpointDiscoveryError
			if !errors.As(err, &disc) {
				t.Errorf("errors.As(*TokenEndpointDiscoveryError): got %v", err)
			}
			tc.check(t, err)

			ds.recover()
			if _, err := client.TokenEndpoint(context.Background()); err == nil {
				t.Fatal("failure within negative TTL should be served from cache")
			}
			if got := ds.requests.Load(); got != 1 {
				t.Errorf("discovery requests within negative TTL: got %d, want 1", got)
			}

			advance(defaultNegativeTTL + time.Second)
			ep, err := client.TokenEndpoint(context.Background())
			if err != nil {
				t.Fatalf("TokenEndpoint after negative TTL: %v", err)
			}
			if ep != ds.URL+"/token" {
				t.Errorf("endpoint: got %q", ep)
			}
			if got := ds.requests.Load(); got != 2 {
				t.Errorf("discovery requests after negative TTL: got %d, want 2", got)
			}
		})
	}
}

func TestTokenEndpoint_NegativeTTLNeverExceedsDiscoveryTTL(t *testing.T) {
	ds := newDiscoveryServer()
	defer ds.Close()
	ds.status(http.StatusNotFound)

	client := NewTokenExchangeClient(ds.URL,
		WithTokenExchangeDiscoveryTTL(10*time.Second),
		WithTokenExchangeNegativeTTL(time.Minute))
	advance := fakeClock(client)

	if _, err := client.TokenEndpoint(context.Background()); err == nil {
		t.Fatal("expected a discovery error")
	}
	ds.recover()
	advance(11 * time.Second)
	if _, err := client.TokenEndpoint(context.Background()); err != nil {
		t.Fatalf("negative entry should have expired with the discovery TTL: %v", err)
	}
	if got := ds.requests.Load(); got != 2 {
		t.Errorf("discovery requests: got %d, want 2", got)
	}
}

func TestTokenEndpoint_NegativeCachingDisabled(t *testing.T) {
	ds := newDiscoveryServer()
	defer ds.Close()
	ds.status(http.StatusNotFound)

	client := NewTokenExchangeClient(ds.URL, WithTokenExchangeNegativeTTL(0))
	for i := 0; i < 2; i++ {
		if _, err := client.TokenEndpoint(context.Background()); err == nil {
			t.Fatal("expected a discovery error")
		}
	}
	if got := ds.requests.Load(); got != 2 {
		t.Errorf("discovery requests: got %d, want 2", got)
	}
}

func TestTokenEndpoint_RediscoversAfterDiscoveryTTL(t *testing.T) {
	ds := newDiscoveryServer()
	defer ds.Close()

	client := NewTokenExchangeClient(ds.URL)
	advance := fakeClock(client)

	for i := 0; i < 2; i++ {
		if _, err := client.TokenEndpoint(context.Background()); err != nil {
			t.Fatalf("TokenEndpoint: %v", err)
		}
	}
	if got := ds.requests.Load(); got != 1 {
		t.Fatalf("discovery requests within TTL: got %d, want 1", got)
	}

	advance(defaultDiscoveryTTL + time.Second)
	if _, err := client.TokenEndpoint(context.Background()); err != nil {
		t.Fatalf("TokenEndpoint after TTL: %v", err)
	}
	if got := ds.requests.Load(); got != 2 {
		t.Errorf("discovery requests after TTL: got %d, want 2", got)
	}
}

func TestTokenEndpoint_CancelledCallerDoesNotPoisonFetch(t *testing.T) {
	ds := newDiscoveryServer()
	defer ds.Close()

	started := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	ds.set(func(w http.ResponseWriter, r *http.Request) {
		once.Do(func() { close(started) })
		select {
		case <-release:
		case <-r.Context().Done():
			return
		}
		ds.serveMetadata(w, map[string]string{"issuer": ds.URL, "token_endpoint": ds.URL + "/token"})
	})

	client := NewTokenExchangeClient(ds.URL)

	ctx, cancel := context.WithCancel(context.Background())
	firstErr := make(chan error, 1)
	go func() {
		_, err := client.TokenEndpoint(ctx)
		firstErr <- err
	}()

	<-started
	cancel()
	err := <-firstErr
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled caller: want context.Canceled, got %v", err)
	}
	var disc *TokenEndpointDiscoveryError
	if !errors.As(err, &disc) {
		t.Errorf("cancelled caller: want *TokenEndpointDiscoveryError, got %v", err)
	}

	// The fetch must still be in flight and complete for other callers.
	close(release)
	ep, err := client.TokenEndpoint(context.Background())
	if err != nil {
		t.Fatalf("second caller: %v", err)
	}
	if ep != ds.URL+"/token" {
		t.Errorf("endpoint: got %q", ep)
	}
	if got := ds.requests.Load(); got != 1 {
		t.Errorf("discovery requests: got %d, want 1 (fetch was poisoned and restarted)", got)
	}
}

func TestTokenEndpoint_ConcurrentColdCallsShareOneFetch(t *testing.T) {
	ds := newDiscoveryServer()
	defer ds.Close()
	ds.set(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(50 * time.Millisecond)
		ds.serveMetadata(w, map[string]string{"issuer": ds.URL, "token_endpoint": ds.URL + "/token"})
	})

	client := NewTokenExchangeClient(ds.URL)

	const callers = 16
	var wg sync.WaitGroup
	errs := make(chan error, callers)
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := client.TokenEndpoint(context.Background())
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("TokenEndpoint: %v", err)
		}
	}
	if got := ds.requests.Load(); got != 1 {
		t.Errorf("discovery requests: got %d, want 1", got)
	}
}

func TestTokenEndpoint_FetchTimeoutBoundsDetachedFetch(t *testing.T) {
	ds := newDiscoveryServer()
	defer ds.Close()
	ds.set(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(2 * time.Second):
		case <-r.Context().Done():
		}
	})

	client := NewTokenExchangeClient(ds.URL, WithTokenExchangeFetchTimeout(50*time.Millisecond))
	_, err := client.TokenEndpoint(context.Background())
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("want context.DeadlineExceeded from fetch timeout, got %v", err)
	}

	ds.recover()
	if _, err := client.TokenEndpoint(context.Background()); err != nil {
		t.Fatalf("timeout must not be cached: %v", err)
	}
}

func TestClientCredentialsClient_TransientDiscoveryFailureNotCached(t *testing.T) {
	var discoveryRequests atomic.Int32
	var failFirst atomic.Bool
	failFirst.Store(true)
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/oauth-authorization-server":
			discoveryRequests.Add(1)
			if failFirst.Swap(false) {
				w.WriteHeader(http.StatusBadGateway)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"issuer": srv.URL, "token_endpoint": srv.URL + "/token"})
		case "/token":
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "token_type": "Bearer"})
		}
	}))
	defer srv.Close()

	client := NewClientCredentialsClient(srv.URL,
		WithCCDiscoveryTTL(time.Hour),
		WithCCNegativeTTL(time.Minute),
		WithCCFetchTimeout(time.Second))

	_, err := client.RequestToken(context.Background(), ClientCredentialsRequest{})
	var disc *TokenEndpointDiscoveryError
	if !errors.As(err, &disc) {
		t.Fatalf("want *TokenEndpointDiscoveryError, got %v", err)
	}

	resp, err := client.RequestToken(context.Background(), ClientCredentialsRequest{})
	if err != nil {
		t.Fatalf("RequestToken after recovery: %v", err)
	}
	if resp.AccessToken != "at" {
		t.Errorf("access_token: got %q", resp.AccessToken)
	}
	if got := discoveryRequests.Load(); got != 2 {
		t.Errorf("discovery requests: got %d, want 2", got)
	}
}

func TestExchangeAuthorizationCode_DiscoveryFailureIsTyped(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()

	_, err := ExchangeAuthorizationCode(context.Background(), srv.URL, AuthorizationCodeExchangeRequest{Code: "c", CodeVerifier: "v", RedirectURI: "http://127.0.0.1/cb"})
	var disc *TokenEndpointDiscoveryError
	if !errors.As(err, &disc) {
		t.Fatalf("want *TokenEndpointDiscoveryError, got %v", err)
	}
	var httpErr *HTTPError
	if !errors.As(err, &httpErr) {
		t.Errorf("nested *HTTPError was dropped: %v", err)
	}
}
