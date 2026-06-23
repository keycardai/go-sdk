package mcp

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/keycardai/credentials-go/oauth"
)

// zoneServer is a fake authorization server for one zone: it serves discovery and a
// /token endpoint that records the Basic-auth client id it received, so tests can
// assert that the exchange used the right zone's credential.
type zoneServer struct {
	*httptest.Server
	mu           sync.Mutex
	lastClientID string
}

func newZoneServer(t *testing.T) *zoneServer {
	t.Helper()
	zs := &zoneServer{}
	mux := http.NewServeMux()
	zs.Server = httptest.NewServer(mux)
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":         zs.URL,
			"token_endpoint": zs.URL + "/token",
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		id, _, _ := r.BasicAuth()
		zs.mu.Lock()
		zs.lastClientID = id
		zs.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "tok-from-" + zs.URL, "token_type": "Bearer"})
	})
	t.Cleanup(zs.Close)
	return zs
}

func (zs *zoneServer) clientID() string {
	zs.mu.Lock()
	defer zs.mu.Unlock()
	return zs.lastClientID
}

// multiZoneKeyring resolves a verification key per issuer, so a zone-A token can only be
// verified with zone A's key.
type multiZoneKeyring struct {
	keys map[string]crypto.PublicKey
}

func (k *multiZoneKeyring) Key(_ context.Context, issuer, _ string) (crypto.PublicKey, error) {
	if pub, ok := k.keys[issuer]; ok {
		return pub, nil
	}
	return nil, fmt.Errorf("no key for issuer %q", issuer)
}

// issuerSignKeyring mints tokens for a single issuer.
type issuerSignKeyring struct {
	key    *rsa.PrivateKey
	issuer string
}

func (s *issuerSignKeyring) Key(_ context.Context, _ string) (oauth.IdentifiableKey, error) {
	return oauth.IdentifiableKey{Key: s.key, Issuer: s.issuer, KID: "kid"}, nil
}

func mintZoneToken(t *testing.T, key *rsa.PrivateKey, issuer string) string {
	t.Helper()
	signer := oauth.NewJWTSigner(&issuerSignKeyring{key: key, issuer: issuer})
	now := time.Now().Unix()
	token, err := signer.Sign(context.Background(), oauth.JWTClaims{
		Subject:  "user-1",
		ClientID: "user-client",
		Audience: []string{"https://mcp.example.com"},
		IssuedAt: now,
		Expiry:   now + 3600,
	})
	if err != nil {
		t.Fatalf("signing token: %v", err)
	}
	return token
}

func serveWithToken(h http.Handler, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("GET", "/api", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// Spec row 1: a multi-zone credential is self-describing and resolves per zone.
func TestMultiZoneClientSecret_ResolvesPerZone(t *testing.T) {
	cred := NewMultiZoneClientSecret(map[string]ClientAuth{
		"https://zone-a.keycard.cloud": {ClientID: "client-a", ClientSecret: "secret-a"},
		"https://zone-b.keycard.cloud": {ClientID: "client-b", ClientSecret: "secret-b"},
	})

	if len(cred.Zones()) != 2 {
		t.Errorf("Zones: got %d, want 2", len(cred.Zones()))
	}
	if a := cred.Auth("https://zone-a.keycard.cloud"); a == nil || a.ClientID != "client-a" {
		t.Errorf("zone A auth: got %+v, want client-a", a)
	}
	if b := cred.Auth("https://zone-b.keycard.cloud"); b == nil || b.ClientID != "client-b" {
		t.Errorf("zone B auth: got %+v, want client-b", b)
	}
	if cred.Auth("https://zone-c.keycard.cloud") != nil {
		t.Error("unknown zone should resolve to nil (fail-closed)")
	}
}

// Spec rows 3 + 6: the exchange routes to the resolved zone's credential, and
// interleaved zones do not leak each other's credentials.
func TestAuthProvider_ExchangeRoutesToZoneCredential(t *testing.T) {
	zoneA := newZoneServer(t)
	zoneB := newZoneServer(t)

	cred := NewMultiZoneClientSecret(map[string]ClientAuth{
		zoneA.URL: {ClientID: "client-a", ClientSecret: "secret-a"},
		zoneB.URL: {ClientID: "client-b", ClientSecret: "secret-b"},
	})
	provider, err := NewAuthProvider(WithApplicationCredential(cred))
	if err != nil {
		t.Fatalf("NewAuthProvider: %v", err)
	}

	acA := provider.ExchangeTokensForZone(context.Background(), zoneA.URL, "user-token", "https://api.example.com")
	if acA.HasErrors() {
		_, ge := acA.GetErrors()
		t.Fatalf("zone A exchange failed: %+v", ge)
	}
	if zoneA.clientID() != "client-a" {
		t.Errorf("zone A exchange used client %q, want client-a", zoneA.clientID())
	}

	acB := provider.ExchangeTokensForZone(context.Background(), zoneB.URL, "user-token", "https://api.example.com")
	if acB.HasErrors() {
		t.Fatal("zone B exchange failed")
	}
	if zoneB.clientID() != "client-b" {
		t.Errorf("zone B exchange used client %q, want client-b", zoneB.clientID())
	}
	// No leakage: zone A's endpoint never saw zone B's credential.
	if zoneA.clientID() != "client-a" {
		t.Errorf("zone A client changed to %q after a zone B exchange", zoneA.clientID())
	}
}

// Spec row 5: a resolved zone with no configured credential fails closed.
func TestAuthProvider_MultiZoneUnknownZoneFailsClosed(t *testing.T) {
	cred := NewMultiZoneClientSecret(map[string]ClientAuth{
		"https://zone-a.keycard.cloud": {ClientID: "client-a", ClientSecret: "secret-a"},
	})
	provider, err := NewAuthProvider(WithApplicationCredential(cred))
	if err != nil {
		t.Fatalf("NewAuthProvider: %v", err)
	}

	ac := provider.ExchangeTokensForZone(context.Background(), "https://zone-unknown.keycard.cloud", "user-token", "https://api.example.com")
	if !ac.HasError() {
		t.Fatal("expected a fail-closed global error for an unconfigured zone")
	}
}

// Spec row 4: a request whose zone cannot be resolved fails closed.
func TestAuthProvider_MultiZoneUnresolvedZoneFailsClosed(t *testing.T) {
	cred := NewMultiZoneClientSecret(map[string]ClientAuth{
		"https://zone-a.keycard.cloud": {ClientID: "client-a", ClientSecret: "secret-a"},
	})
	provider, err := NewAuthProvider(WithApplicationCredential(cred))
	if err != nil {
		t.Fatalf("NewAuthProvider: %v", err)
	}

	// ExchangeTokens carries no issuer; a multi-zone provider cannot resolve a zone.
	ac := provider.ExchangeTokens(context.Background(), "user-token", "https://api.example.com")
	if !ac.HasError() {
		t.Fatal("expected a fail-closed global error when the zone is unresolved")
	}
}

// Spec rows 2 + 3 end to end: a request's token issuer selects the zone for both
// verification and the outbound exchange.
func TestAuthProvider_GrantRoutesByTokenIssuer(t *testing.T) {
	zoneA := newZoneServer(t)
	zoneB := newZoneServer(t)
	keyA, _ := rsa.GenerateKey(rand.Reader, 2048)
	keyB, _ := rsa.GenerateKey(rand.Reader, 2048)

	verifier, err := NewJWTOAuthTokenVerifier(
		&multiZoneKeyring{keys: map[string]crypto.PublicKey{zoneA.URL: &keyA.PublicKey, zoneB.URL: &keyB.PublicKey}},
		[]string{zoneA.URL, zoneB.URL},
	)
	if err != nil {
		t.Fatalf("NewJWTOAuthTokenVerifier: %v", err)
	}

	cred := NewMultiZoneClientSecret(map[string]ClientAuth{
		zoneA.URL: {ClientID: "client-a", ClientSecret: "secret-a"},
		zoneB.URL: {ClientID: "client-b", ClientSecret: "secret-b"},
	})
	provider, err := NewAuthProvider(WithApplicationCredential(cred))
	if err != nil {
		t.Fatalf("NewAuthProvider: %v", err)
	}

	handler := RequireBearerAuth(verifier)(
		provider.Grant("https://api.example.com")(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				ac := AccessContextFromRequest(r)
				if _, err := ac.Access("https://api.example.com"); err != nil {
					http.Error(w, err.Error(), http.StatusBadGateway)
					return
				}
				w.WriteHeader(http.StatusOK)
			}),
		),
	)

	if rec := serveWithToken(handler, mintZoneToken(t, keyA, zoneA.URL)); rec.Code != http.StatusOK {
		t.Fatalf("zone A request: status %d, body %q", rec.Code, rec.Body.String())
	}
	if zoneA.clientID() != "client-a" {
		t.Errorf("zone A token routed to client %q, want client-a", zoneA.clientID())
	}

	if rec := serveWithToken(handler, mintZoneToken(t, keyB, zoneB.URL)); rec.Code != http.StatusOK {
		t.Fatalf("zone B request: status %d, body %q", rec.Code, rec.Body.String())
	}
	if zoneB.clientID() != "client-b" {
		t.Errorf("zone B token routed to client %q, want client-b", zoneB.clientID())
	}
}
