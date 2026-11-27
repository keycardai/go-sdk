package oauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// SDK-93, spec jwks-caching rows 14 to 19: the per-jwks_uri key set and the
// unknown-kid refetch cooldown.

func cooldownZone(t *testing.T, kids *atomic.Value, fetches *atomic.Int32) *httptest.Server {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/oauth-authorization-server":
			_ = json.NewEncoder(w).Encode(map[string]any{"issuer": srv.URL, "jwks_uri": srv.URL + "/.well-known/jwks.json"})
		case "/.well-known/jwks.json":
			fetches.Add(1)
			var keys []map[string]any
			for _, kid := range kids.Load().([]string) {
				keys = append(keys, map[string]any{"kty": "RSA", "kid": kid, "alg": "RS256", "use": "sig",
					"n": Base64URLEncode(key.PublicKey.N.Bytes()), "e": Base64URLEncode(big.NewInt(int64(key.PublicKey.E)).Bytes())})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": keys})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestJWKSOAuthKeyring_UnknownKidsWithinCooldownCauseOneFetch(t *testing.T) {
	var kids atomic.Value
	kids.Store([]string{"k1"})
	var fetches atomic.Int32
	srv := cooldownZone(t, &kids, &fetches)
	k := NewJWKSOAuthKeyring(WithKeyringHTTPClient(srv.Client()))
	if _, err := k.Key(context.Background(), srv.URL, "k1"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		var notFound *JWKSKeyNotFoundError
		if _, err := k.Key(context.Background(), srv.URL, "forged-"+string(rune('a'+i))); !errors.As(err, &notFound) {
			t.Fatalf("want JWKSKeyNotFoundError, got %v", err)
		}
	}
	if got := fetches.Load(); got != 1 {
		t.Fatalf("want 1 JWKS fetch, got %d", got)
	}
}

func TestJWKSOAuthKeyring_KidInCachedSetNeedsNoFetch(t *testing.T) {
	var kids atomic.Value
	kids.Store([]string{"k1", "k2"})
	var fetches atomic.Int32
	srv := cooldownZone(t, &kids, &fetches)
	k := NewJWKSOAuthKeyring(WithKeyringHTTPClient(srv.Client()))
	for _, kid := range []string{"k1", "k2"} {
		if _, err := k.Key(context.Background(), srv.URL, kid); err != nil {
			t.Fatal(err)
		}
	}
	if got := fetches.Load(); got != 1 {
		t.Fatalf("want 1 JWKS fetch, got %d", got)
	}
}

func TestJWKSOAuthKeyring_RotatedInKidFoundAfterCooldown(t *testing.T) {
	var kids atomic.Value
	kids.Store([]string{"k1"})
	var fetches atomic.Int32
	srv := cooldownZone(t, &kids, &fetches)
	k := NewJWKSOAuthKeyring(WithKeyringHTTPClient(srv.Client()), WithJWKSRefetchCooldown(50*time.Millisecond))
	if _, err := k.Key(context.Background(), srv.URL, "k1"); err != nil {
		t.Fatal(err)
	}
	kids.Store([]string{"k1", "rotated"})
	if _, err := k.Key(context.Background(), srv.URL, "rotated"); err == nil {
		t.Fatal("want key-not-found inside the cooldown")
	}
	time.Sleep(60 * time.Millisecond)
	if _, err := k.Key(context.Background(), srv.URL, "rotated"); err != nil {
		t.Fatalf("want the rotated key after the cooldown, got %v", err)
	}
	if got := fetches.Load(); got != 2 {
		t.Fatalf("want 2 JWKS fetches, got %d", got)
	}
}

type jwksWaitingContext struct {
	context.Context
	waiting chan<- struct{}
}

// sharedFetch calls Done after registering the caller with the singleflight group.
func (c jwksWaitingContext) Done() <-chan struct{} {
	c.waiting <- struct{}{}
	return c.Context.Done()
}

// Spec row 17: concurrent lookups for different kids share a single JWKS fetch.
func TestJWKSOAuthKeyring_ConcurrentMissesForDifferentKidsShareOneFetch(t *testing.T) {
	t.Run("cold cache", func(t *testing.T) {
		var kids atomic.Value
		requestedKids := []string{"a", "b", "c", "d"}
		kids.Store(requestedKids)
		var fetches atomic.Int32
		srv := cooldownZone(t, &kids, &fetches)
		releaseFetch := make(chan struct{})
		release := sync.OnceFunc(func() { close(releaseFetch) })
		defer release()
		client := &http.Client{Transport: metadataTestTransport(func(req *http.Request) (*http.Response, error) {
			if req.URL.Path == "/.well-known/jwks.json" {
				<-releaseFetch
			}
			return srv.Client().Transport.RoundTrip(req)
		})}
		k := NewJWKSOAuthKeyring(WithKeyringHTTPClient(client))
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := k.resolveJWKSURI(ctx, srv.URL, 0); err != nil {
			t.Fatal(err)
		}

		waiting := make(chan struct{}, len(requestedKids))
		results := make(chan error, len(requestedKids))
		for _, kid := range requestedKids {
			go func() {
				_, err := k.Key(jwksWaitingContext{ctx, waiting}, srv.URL, kid)
				results <- err
			}()
		}
		for range requestedKids {
			select {
			case <-waiting:
			case <-ctx.Done():
				t.Fatal("lookups did not join the JWKS flight")
			}
		}
		release()
		for range requestedKids {
			if err := <-results; err != nil {
				t.Error(err)
			}
		}
		if got := fetches.Load(); got != 1 {
			t.Fatalf("want 1 shared JWKS fetch, got %d", got)
		}
	})

	t.Run("one caller paused after a cache miss", func(t *testing.T) {
		testJWKSRefreshDuringCacheMiss(t, DefaultJWKSRefetchCooldown, []string{"a", "b"}, 1)
	})
	t.Run("one caller paused with cooldown disabled", func(t *testing.T) {
		testJWKSRefreshDuringCacheMiss(t, 0, []string{"b"}, 2)
	})
}

func testJWKSRefreshDuringCacheMiss(t *testing.T, cooldown time.Duration, firstRefreshKids []string, wantRefreshes int32) {
	t.Helper()
	var kids atomic.Value
	kids.Store([]string{"old"})
	var fetches atomic.Int32
	srv := cooldownZone(t, &kids, &fetches)
	k := NewJWKSOAuthKeyring(WithKeyringHTTPClient(srv.Client()), WithJWKSRefetchCooldown(cooldown))
	clock := newFakeDeviceClock()
	k.now = clock.Now
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := k.Key(ctx, srv.URL, "old"); err != nil {
		t.Fatal(err)
	}
	kids.Store(firstRefreshKids)
	<-clock.After(DefaultJWKSRefetchCooldown)

	checkedCache := make(chan struct{})
	resumeLookup := make(chan struct{})
	resume := sync.OnceFunc(func() { close(resumeLookup) })
	defer resume()
	var clockReads atomic.Int32
	k.now = func() time.Time {
		// The first read checks the cached set's TTL. The second checks the
		// cooldown after the caller has missed its kid and released k.mu.
		if clockReads.Add(1) == 2 {
			close(checkedCache)
			select {
			case <-resumeLookup:
			case <-ctx.Done():
			}
		}
		return clock.Now()
	}

	result := make(chan error, 1)
	go func() {
		uri := srv.URL + "/.well-known/jwks.json"
		_, err := k.resolveKey(ctx, srv.URL, "a", uri, srv.URL+"::a", 0)
		result <- err
	}()
	select {
	case <-checkedCache:
	case <-ctx.Done():
		t.Fatal("first lookup did not reach the cooldown check")
	}
	if _, err := k.Key(ctx, srv.URL, "b"); err != nil {
		t.Fatal(err)
	}
	// If the first refresh lacked "a", it is now available on the endpoint.
	kids.Store([]string{"a", "b"})
	resume()
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	if got := fetches.Load() - 1; got != wantRefreshes {
		t.Fatalf("want %d JWKS refreshes, got %d", wantRefreshes, got)
	}
}

func TestJWKSOAuthKeyring_InvalidateDropsKeySet(t *testing.T) {
	var kids atomic.Value
	kids.Store([]string{"k1"})
	var fetches atomic.Int32
	srv := cooldownZone(t, &kids, &fetches)
	k := NewJWKSOAuthKeyring(WithKeyringHTTPClient(srv.Client()))
	if _, err := k.Key(context.Background(), srv.URL, "k1"); err != nil {
		t.Fatal(err)
	}
	k.Invalidate(srv.URL, "k1")
	kids.Store([]string{"rotated"})
	if _, err := k.Key(context.Background(), srv.URL, "rotated"); err != nil {
		t.Fatalf("want a fetch after invalidate, got %v", err)
	}
}

func TestJWKSOAuthKeyring_CooldownZeroFetchesOnEveryMiss(t *testing.T) {
	var kids atomic.Value
	kids.Store([]string{"k1"})
	var fetches atomic.Int32
	srv := cooldownZone(t, &kids, &fetches)
	k := NewJWKSOAuthKeyring(WithKeyringHTTPClient(srv.Client()), WithJWKSRefetchCooldown(0))
	if _, err := k.Key(context.Background(), srv.URL, "k1"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		_, _ = k.Key(context.Background(), srv.URL, "forged")
	}
	if got := fetches.Load(); got != 4 {
		t.Fatalf("want 4 JWKS fetches with cooldown 0, got %d", got)
	}
}

func TestWithDefaultTimeout(t *testing.T) {
	ctx, cancel := withDefaultTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if _, ok := ctx.Deadline(); !ok {
		t.Fatal("want a deadline when the caller set none")
	}
	parent, pcancel := context.WithTimeout(context.Background(), time.Hour)
	defer pcancel()
	ctx2, cancel2 := withDefaultTimeout(parent, 10*time.Millisecond)
	defer cancel2()
	d, _ := ctx2.Deadline()
	if time.Until(d) < 30*time.Minute {
		t.Fatal("a caller's longer deadline must win")
	}
}

func TestClientCredentials_TimesOutByDefault(t *testing.T) {
	hang := make(chan struct{})
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/oauth-authorization-server" {
			_ = json.NewEncoder(w).Encode(map[string]any{"issuer": srv.URL, "token_endpoint": srv.URL + "/token"})
			return
		}
		<-hang
	}))
	defer srv.Close()
	defer close(hang) // runs before srv.Close, so the blocked handler returns
	c := NewClientCredentialsClient(srv.URL, WithCCHTTPClient(srv.Client()), WithCCRequestTimeout(50*time.Millisecond))
	_, err := c.RequestToken(context.Background(), ClientCredentialsRequest{})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("want context.DeadlineExceeded through errors.Is, got %v", err)
	}
}
