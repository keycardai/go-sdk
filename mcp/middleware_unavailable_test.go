package mcp

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/keycardai/go-sdk/oauth"
)

// These tests drive RequireBearerAuth with a real JWKS-backed verifier against
// an httptest zone, proving the split between "the zone's keys could not be
// fetched" (503, no challenge) and "the token is invalid" (401 invalid_token).

// jwksZone serves authorization-server metadata and a JWKS from one httptest
// server. Each handler can be swapped per test.
type jwksZone struct {
	srv       *httptest.Server
	discovery func(w http.ResponseWriter)
	jwks      func(w http.ResponseWriter)
}

func newJWKSZone(t *testing.T) *jwksZone {
	t.Helper()
	z := &jwksZone{}
	z.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/oauth-authorization-server":
			z.discovery(w)
		case "/.well-known/jwks.json":
			z.jwks(w)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(z.srv.Close)
	z.discovery = func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":         z.srv.URL,
			"jwks_uri":       z.srv.URL + "/.well-known/jwks.json",
			"token_endpoint": z.srv.URL + "/oauth/token",
		})
	}
	return z
}

func (z *jwksZone) serveKeys(pub *rsa.PublicKey, kid string) {
	z.jwks = func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "use": "sig", "alg": "RS256", "kid": kid,
			"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		}}})
	}
}

func unavailableHandler(t *testing.T, z *jwksZone) (http.Handler, *bool) {
	t.Helper()
	keyring := oauth.NewJWKSOAuthKeyring(oauth.WithKeyringHTTPClient(z.srv.Client()))
	verifier, err := NewJWTOAuthTokenVerifier(keyring, []string{z.srv.URL}, oauth.WithAudiences(testResource))
	if err != nil {
		t.Fatalf("NewJWTOAuthTokenVerifier: %v", err)
	}
	ran := false
	handler := RequireBearerAuth(verifier)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		ran = true
	}))
	return handler, &ran
}

func zoneToken(t *testing.T, key *rsa.PrivateKey, issuer string) string {
	t.Helper()
	now := time.Now().Unix()
	return mintToken(t, key, issuer, oauth.JWTClaims{
		Subject: "user-1", ClientID: "client-1", Audience: []string{testResource},
		Scope: "mcp:tools", IssuedAt: now, Expiry: now + 3600,
	})
}

func assertUnavailable(t *testing.T, rec *httptest.ResponseRecorder, ran bool) {
	t.Helper()
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status: got %d, want 503 (body %q)", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("WWW-Authenticate"); got != "" {
		t.Errorf("WWW-Authenticate must be absent on 503, got %q", got)
	}
	if body := strings.TrimSpace(rec.Body.String()); body != `{"error":"temporarily_unavailable"}` {
		t.Errorf("body: got %q", body)
	}
	if ran {
		t.Error("downstream handler must not run")
	}
}

func TestRequireBearerAuth_JWKSFetchFailureIs503(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	z := newJWKSZone(t)
	z.jwks = func(w http.ResponseWriter) { w.WriteHeader(http.StatusBadGateway) }
	handler, ran := unavailableHandler(t, z)

	assertUnavailable(t, serve(handler, zoneToken(t, key, z.srv.URL)), *ran)
}

func TestRequireBearerAuth_DiscoveryFailureIs503(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	z := newJWKSZone(t)
	z.discovery = func(w http.ResponseWriter) { w.WriteHeader(http.StatusInternalServerError) }
	handler, ran := unavailableHandler(t, z)

	assertUnavailable(t, serve(handler, zoneToken(t, key, z.srv.URL)), *ran)
}

func TestRequireBearerAuth_MalformedMetadataIs503(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	z := newJWKSZone(t)
	z.discovery = func(w http.ResponseWriter) { _, _ = w.Write([]byte("not json")) }
	handler, ran := unavailableHandler(t, z)

	assertUnavailable(t, serve(handler, zoneToken(t, key, z.srv.URL)), *ran)
}

func TestRequireBearerAuth_UnknownKidIs401(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	z := newJWKSZone(t)
	z.serveKeys(&key.PublicKey, "kid-rotated") // the token is signed under kid-1
	handler, ran := unavailableHandler(t, z)

	rec := serve(handler, zoneToken(t, key, z.srv.URL))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status: got %d, want 401 (body %q)", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("WWW-Authenticate"); !strings.Contains(got, `error="invalid_token"`) {
		t.Errorf("challenge: got %q", got)
	}
	if *ran {
		t.Error("downstream handler must not run")
	}
}

func TestRequireBearerAuth_BadSignatureAgainstLoadedKeysIs401(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	z := newJWKSZone(t)
	z.serveKeys(&key.PublicKey, "kid-1")
	handler, _ := unavailableHandler(t, z)

	rec := serve(handler, zoneToken(t, other, z.srv.URL))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status: got %d, want 401 (body %q)", rec.Code, rec.Body.String())
	}
}

func TestInvalidTokenError_KeepsKeyResolutionCause(t *testing.T) {
	z := newJWKSZone(t)
	z.jwks = func(w http.ResponseWriter) { w.WriteHeader(http.StatusBadGateway) }
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	keyring := oauth.NewJWKSOAuthKeyring(oauth.WithKeyringHTTPClient(z.srv.Client()))
	verifier, err := NewJWTOAuthTokenVerifier(keyring, []string{z.srv.URL}, oauth.WithAudiences(testResource))
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "/", nil)
	_, err = verifier.VerifyAccessToken(req.Context(), zoneToken(t, key, z.srv.URL))
	if !keysUnavailable(err) {
		t.Fatalf("expected a key-resolution cause reachable through errors.As, got %v", err)
	}
}
