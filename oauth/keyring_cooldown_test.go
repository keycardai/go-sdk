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

func TestJWKSOAuthKeyring_ConcurrentMissesForDifferentKidsShareOneFetch(t *testing.T) {
	var kids atomic.Value
	kids.Store([]string{"a", "b", "c", "d"})
	var fetches atomic.Int32
	srv := cooldownZone(t, &kids, &fetches)
	k := NewJWKSOAuthKeyring(WithKeyringHTTPClient(srv.Client()))
	if _, err := k.resolveJWKSURI(context.Background(), srv.URL); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for _, kid := range []string{"a", "b", "c", "d"} {
		wg.Add(1)
		go func(kid string) {
			defer wg.Done()
			if _, err := k.Key(context.Background(), srv.URL, kid); err != nil {
				t.Error(err)
			}
		}(kid)
	}
	wg.Wait()
	if got := fetches.Load(); got != 1 {
		t.Fatalf("want 1 shared JWKS fetch, got %d", got)
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
