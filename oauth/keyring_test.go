package oauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestJWKSOAuthKeyring_Key(t *testing.T) {
	// Generate a test RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	// Create JWKS server
	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/jwks.json" {
			jwks := map[string]any{
				"keys": []map[string]any{
					{
						"kty": "RSA",
						"kid": "test-key-1",
						"n":   Base64URLEncode(privateKey.PublicKey.N.Bytes()),
						"e":   Base64URLEncode(big.NewInt(int64(privateKey.PublicKey.E)).Bytes()),
						"alg": "RS256",
						"use": "sig",
					},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(jwks)
		} else if r.URL.Path == "/.well-known/oauth-authorization-server" {
			metadata := map[string]string{
				"issuer":   "http://" + r.Host,
				"jwks_uri": "http://" + r.Host + "/.well-known/jwks.json",
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(metadata)
		}
	}))
	defer jwksServer.Close()

	keyring := NewJWKSOAuthKeyring(
		WithKeyTTL(1*time.Minute),
		WithDiscoveryTTL(1*time.Minute),
		WithFetchTimeout(5*time.Second),
		WithKeyringHTTPClient(jwksServer.Client()),
	)

	key, err := keyring.Key(context.Background(), jwksServer.URL, "test-key-1")
	if err != nil {
		t.Fatalf("resolving key: %v", err)
	}

	rsaKey, ok := key.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("expected *rsa.PublicKey, got %T", key)
	}

	if rsaKey.N.Cmp(privateKey.PublicKey.N) != 0 {
		t.Error("public key modulus mismatch")
	}
}

func TestJWKSOAuthKeyring_KeyNotFound(t *testing.T) {
	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/jwks.json" {
			jwks := map[string]any{"keys": []map[string]any{}}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(jwks)
		} else if r.URL.Path == "/.well-known/oauth-authorization-server" {
			metadata := map[string]string{
				"issuer":   "http://" + r.Host,
				"jwks_uri": "http://" + r.Host + "/.well-known/jwks.json",
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(metadata)
		}
	}))
	defer jwksServer.Close()

	keyring := NewJWKSOAuthKeyring(
		WithKeyringHTTPClient(jwksServer.Client()),
	)

	_, err := keyring.Key(context.Background(), jwksServer.URL, "nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent key")
	}
}

func TestJWKSOAuthKeyring_CachesKeys(t *testing.T) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	fetchCount := 0

	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/jwks.json" {
			fetchCount++
			jwks := map[string]any{
				"keys": []map[string]any{
					{
						"kty": "RSA",
						"kid": "test-key-1",
						"n":   Base64URLEncode(privateKey.PublicKey.N.Bytes()),
						"e":   Base64URLEncode(big.NewInt(int64(privateKey.PublicKey.E)).Bytes()),
					},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(jwks)
		} else if r.URL.Path == "/.well-known/oauth-authorization-server" {
			metadata := map[string]string{
				"issuer":   "http://" + r.Host,
				"jwks_uri": "http://" + r.Host + "/.well-known/jwks.json",
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(metadata)
		}
	}))
	defer jwksServer.Close()

	keyring := NewJWKSOAuthKeyring(
		WithKeyTTL(1*time.Hour),
		WithKeyringHTTPClient(jwksServer.Client()),
	)

	// First call
	_, err := keyring.Key(context.Background(), jwksServer.URL, "test-key-1")
	if err != nil {
		t.Fatalf("first call: %v", err)
	}

	// Second call should use cache
	_, err = keyring.Key(context.Background(), jwksServer.URL, "test-key-1")
	if err != nil {
		t.Fatalf("second call: %v", err)
	}

	if fetchCount != 1 {
		t.Errorf("JWKS should be fetched once (cached), got %d fetches", fetchCount)
	}
}

func TestJWKSOAuthKeyring_Invalidate(t *testing.T) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	fetchCount := 0

	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/jwks.json" {
			fetchCount++
			jwks := map[string]any{
				"keys": []map[string]any{
					{
						"kty": "RSA",
						"kid": "test-key-1",
						"n":   Base64URLEncode(privateKey.PublicKey.N.Bytes()),
						"e":   Base64URLEncode(big.NewInt(int64(privateKey.PublicKey.E)).Bytes()),
					},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(jwks)
		} else if r.URL.Path == "/.well-known/oauth-authorization-server" {
			metadata := map[string]string{
				"issuer":   "http://" + r.Host,
				"jwks_uri": "http://" + r.Host + "/.well-known/jwks.json",
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(metadata)
		}
	}))
	defer jwksServer.Close()

	keyring := NewJWKSOAuthKeyring(
		WithKeyTTL(1*time.Hour),
		WithKeyringHTTPClient(jwksServer.Client()),
	)

	_, _ = keyring.Key(context.Background(), jwksServer.URL, "test-key-1")
	keyring.Invalidate(jwksServer.URL, "test-key-1")
	_, _ = keyring.Key(context.Background(), jwksServer.URL, "test-key-1")

	if fetchCount != 2 {
		t.Errorf("JWKS should be fetched twice after invalidation, got %d", fetchCount)
	}
}

// A JWKS fetch failure must preserve its cause so callers can errors.Is the transport
// error (e.g. a timeout) and errors.As the typed *JWKSFetchError.
func TestJWKSOAuthKeyring_FetchErrorPreservesCause(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/oauth-authorization-server":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{
				"issuer":   "http://" + r.Host,
				"jwks_uri": "http://" + r.Host + "/.well-known/jwks.json",
			})
		case "/.well-known/jwks.json":
			// Block past the fetch timeout so the JWKS fetch context expires.
			select {
			case <-time.After(2 * time.Second):
			case <-r.Context().Done():
			}
		}
	}))
	defer server.Close()

	keyring := NewJWKSOAuthKeyring(
		WithFetchTimeout(100*time.Millisecond),
		WithKeyringHTTPClient(server.Client()),
	)

	_, err := keyring.Key(context.Background(), server.URL, "test-key-1")
	if err == nil {
		t.Fatal("expected a fetch error")
	}

	var fetchErr *JWKSFetchError
	if !errors.As(err, &fetchErr) {
		t.Errorf("errors.As(*JWKSFetchError): got %v", err)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("errors.Is(context.DeadlineExceeded): cause was dropped, got %v", err)
	}
}

// A discovery failure during key resolution must preserve its cause so a nested
// *IssuerMismatchError remains reachable via errors.As, matching a direct discovery call.
func TestJWKSOAuthKeyring_DiscoveryErrorPreservesIssuerMismatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/oauth-authorization-server" {
			w.Header().Set("Content-Type", "application/json")
			// Report a different issuer than requested to trigger an IssuerMismatchError.
			json.NewEncoder(w).Encode(map[string]string{
				"issuer":   "https://imposter.example.com",
				"jwks_uri": "http://" + r.Host + "/.well-known/jwks.json",
			})
		}
	}))
	defer server.Close()

	keyring := NewJWKSOAuthKeyring(
		WithKeyringHTTPClient(server.Client()),
	)

	_, err := keyring.Key(context.Background(), server.URL, "test-key-1")
	if err == nil {
		t.Fatal("expected a discovery error")
	}

	var discErr *JWKSDiscoveryError
	if !errors.As(err, &discErr) {
		t.Errorf("errors.As(*JWKSDiscoveryError): got %v", err)
	}
	var mismatch *IssuerMismatchError
	if !errors.As(err, &mismatch) {
		t.Errorf("errors.As(*IssuerMismatchError): nested cause was dropped, got %v", err)
	}
}

func TestAssertSameOrigin(t *testing.T) {
	tests := []struct {
		name    string
		issuer  string
		jwksURI string
		wantErr bool
	}{
		{"same origin", "https://auth.example.com", "https://auth.example.com/.well-known/jwks.json", false},
		{"different host", "https://auth.example.com", "https://evil.example.com/jwks.json", true},
		{"different scheme", "https://auth.example.com", "http://auth.example.com/jwks.json", true},
		{"different port", "https://auth.example.com:8443", "https://auth.example.com:9443/jwks.json", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := assertSameOrigin(tt.issuer, tt.jwksURI)
			if (err != nil) != tt.wantErr {
				t.Errorf("assertSameOrigin(%q, %q) error = %v, wantErr %v", tt.issuer, tt.jwksURI, err, tt.wantErr)
			}
		})
	}
}

// A caller that cancels mid-fetch must not fail the shared JWKS fetch for the others:
// the fetch completes on a detached context and populates the cache.
func TestJWKSOAuthKeyring_CancelledCallerDoesNotPoisonFetch(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	var jwksFetches atomic.Int32
	inner := b1RSAJWKS(t, "k0")
	defer inner.Close()

	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/oauth-authorization-server":
			json.NewEncoder(w).Encode(map[string]string{
				"issuer":   srv.URL,
				"jwks_uri": srv.URL + "/.well-known/jwks.json",
			})
		case "/.well-known/jwks.json":
			jwksFetches.Add(1)
			once.Do(func() { close(started) })
			select {
			case <-release:
			case <-r.Context().Done():
				return
			}
			resp, err := http.Get(inner.URL + "/.well-known/jwks.json")
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadGateway)
				return
			}
			defer resp.Body.Close()
			io.Copy(w, resp.Body)
		}
	}))
	defer srv.Close()

	keyring := NewJWKSOAuthKeyring(WithKeyringHTTPClient(srv.Client()))

	ctx, cancel := context.WithCancel(context.Background())
	firstErr := make(chan error, 1)
	go func() {
		_, err := keyring.Key(ctx, srv.URL, "k0")
		firstErr <- err
	}()

	<-started
	cancel()
	err := <-firstErr
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled caller: want context.Canceled, got %v", err)
	}
	var fetchErr *JWKSFetchError
	if !errors.As(err, &fetchErr) {
		t.Errorf("cancelled caller: want *JWKSFetchError, got %v", err)
	}

	close(release)
	if _, err := keyring.Key(context.Background(), srv.URL, "k0"); err != nil {
		t.Fatalf("second caller: %v", err)
	}
	if got := jwksFetches.Load(); got != 1 {
		t.Errorf("JWKS fetches: got %d, want 1 (fetch was poisoned and restarted)", got)
	}
}
