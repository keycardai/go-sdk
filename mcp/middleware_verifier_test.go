package mcp

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/keycardai/go-sdk/oauth"
)

// These tests drive real signed JWTs through RequireBearerAuth with a hardened
// verifier, proving the issuer and audience binding the middleware now enforces
// (bearer-token-verification-middleware spec).

const (
	testZone     = "https://zone.keycard.cloud"
	testResource = "https://mcp.example.com"
)

// signKeyring is a private keyring for minting test tokens.
type signKeyring struct {
	key    *rsa.PrivateKey
	issuer string
}

func (k *signKeyring) Key(_ context.Context, _ string) (oauth.IdentifiableKey, error) {
	return oauth.IdentifiableKey{Key: k.key, Issuer: k.issuer, KID: "kid-1"}, nil
}

// pubKeyring resolves the matching public key for any (issuer, kid).
type pubKeyring struct {
	pub crypto.PublicKey
}

func (k *pubKeyring) Key(_ context.Context, _, _ string) (crypto.PublicKey, error) {
	return k.pub, nil
}

func mintToken(t *testing.T, key *rsa.PrivateKey, issuer string, claims oauth.JWTClaims) string {
	t.Helper()
	signer := oauth.NewJWTSigner(&signKeyring{key: key, issuer: issuer})
	token, err := signer.Sign(context.Background(), claims)
	if err != nil {
		t.Fatalf("signing token: %v", err)
	}
	return token
}

// zoneVerifier builds a hardened verifier backed by a static public keyring so the
// test needs no JWKS endpoint.
func zoneVerifier(t *testing.T, pub crypto.PublicKey, opts ...oauth.JWTVerifierOption) TokenVerifier {
	t.Helper()
	v, err := NewJWTOAuthTokenVerifier(&pubKeyring{pub: pub}, []string{testZone}, opts...)
	if err != nil {
		t.Fatalf("NewJWTOAuthTokenVerifier: %v", err)
	}
	return v
}

func serve(handler http.Handler, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("GET", "/api/test", nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func TestBearerMiddleware_ValidTokenPopulatesAuthInfo(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	now := time.Now().Unix()
	token := mintToken(t, key, testZone, oauth.JWTClaims{
		Subject:  "user-1",
		ClientID: "client-1",
		Audience: []string{testResource},
		Scope:    "mcp:tools",
		IssuedAt: now,
		Expiry:   now + 3600,
		Extra:    map[string]any{"resource": testResource},
	})

	verifier := zoneVerifier(t, &key.PublicKey, oauth.WithAudiences(testResource))

	var got *AuthInfo
	handler := RequireBearerAuth(
		verifier,
		WithRequiredScopes("mcp:tools"),
	)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got = AuthInfoFromRequest(r)
	}))

	rec := serve(handler, token)
	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200 (body %q)", rec.Code, rec.Body.String())
	}
	if got == nil {
		t.Fatal("auth info not populated")
	}
	if got.ClientID != "client-1" {
		t.Errorf("client_id: got %q, want client-1", got.ClientID)
	}
	if got.Resource != testResource {
		t.Errorf("resource: got %q, want %q", got.Resource, testResource)
	}
	if len(got.Scopes) != 1 || got.Scopes[0] != "mcp:tools" {
		t.Errorf("scopes: got %v, want [mcp:tools]", got.Scopes)
	}
	if got.ExpiresAt == 0 {
		t.Error("expiry should be populated")
	}
}

func TestBearerMiddleware_IdentityClaims(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	now := time.Now().Unix()
	verifier := zoneVerifier(t, &key.PublicKey, oauth.WithAudiences(testResource))

	tests := []struct {
		name             string
		claims           oauth.JWTClaims
		wantClientID     string
		wantSubject      string
		wantSubProfile   string
		wantKeycardAppID string
	}{
		{
			name: "keycard user token surfaces all identity claims",
			claims: oauth.JWTClaims{
				Subject:  "alice@example.com",
				ClientID: "cred-123",
				Audience: []string{testResource},
				IssuedAt: now,
				Expiry:   now + 3600,
				Extra: map[string]any{
					"sub_profile":    "user",
					"keycard_app_id": "app-456",
				},
			},
			wantClientID:     "cred-123",
			wantSubject:      "alice@example.com",
			wantSubProfile:   "user",
			wantKeycardAppID: "app-456",
		},
		{
			name: "keycard app token has sub equal to keycard_app_id",
			claims: oauth.JWTClaims{
				Subject:  "app-456",
				ClientID: "cred-789",
				Audience: []string{testResource},
				IssuedAt: now,
				Expiry:   now + 3600,
				Extra: map[string]any{
					"sub_profile":    "app",
					"keycard_app_id": "app-456",
				},
			},
			wantClientID:     "cred-789",
			wantSubject:      "app-456",
			wantSubProfile:   "app",
			wantKeycardAppID: "app-456",
		},
		{
			name: "token without keycard claims verifies with empty fields",
			claims: oauth.JWTClaims{
				Subject:  "some-subject",
				ClientID: "client-1",
				Audience: []string{testResource},
				IssuedAt: now,
				Expiry:   now + 3600,
			},
			wantClientID: "client-1",
			wantSubject:  "some-subject",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := mintToken(t, key, testZone, tt.claims)

			var got *AuthInfo
			handler := RequireBearerAuth(verifier)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				got = AuthInfoFromRequest(r)
			}))

			rec := serve(handler, token)
			if rec.Code != http.StatusOK {
				t.Fatalf("status: got %d, want 200 (body %q)", rec.Code, rec.Body.String())
			}
			if got == nil {
				t.Fatal("auth info not populated")
			}
			if got.ClientID != tt.wantClientID {
				t.Errorf("ClientID: got %q, want %q", got.ClientID, tt.wantClientID)
			}
			if got.Subject != tt.wantSubject {
				t.Errorf("Subject: got %q, want %q", got.Subject, tt.wantSubject)
			}
			if got.SubProfile != tt.wantSubProfile {
				t.Errorf("SubProfile: got %q, want %q", got.SubProfile, tt.wantSubProfile)
			}
			if got.KeycardAppID != tt.wantKeycardAppID {
				t.Errorf("KeycardAppID: got %q, want %q", got.KeycardAppID, tt.wantKeycardAppID)
			}
		})
	}
}

func TestBearerMiddleware_UntrustedIssuerRejected(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	now := time.Now().Unix()
	token := mintToken(t, key, "https://evil.example.com", oauth.JWTClaims{
		Subject:  "user-1",
		ClientID: "client-1",
		Audience: []string{testResource},
		IssuedAt: now,
		Expiry:   now + 3600,
	})

	handler := RequireBearerAuth(
		zoneVerifier(t, &key.PublicKey),
	)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("handler must not run for an untrusted issuer")
	}))

	rec := serve(handler, token)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status: got %d, want 401", rec.Code)
	}
	if !strings.Contains(rec.Header().Get("WWW-Authenticate"), "invalid_token") {
		t.Errorf("expected invalid_token challenge, got %q", rec.Header().Get("WWW-Authenticate"))
	}
}

func TestBearerMiddleware_WrongAudienceRejected(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	now := time.Now().Unix()
	token := mintToken(t, key, testZone, oauth.JWTClaims{
		Subject:  "user-1",
		ClientID: "client-1",
		Audience: []string{"https://other.example.com"},
		IssuedAt: now,
		Expiry:   now + 3600,
	})

	handler := RequireBearerAuth(
		zoneVerifier(t, &key.PublicKey, oauth.WithAudiences(testResource)),
	)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("handler must not run for a token issued to a different audience")
	}))

	rec := serve(handler, token)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status: got %d, want 401", rec.Code)
	}
}

func TestBearerMiddleware_NonBearerSchemeRejected(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	handler := RequireBearerAuth(
		zoneVerifier(t, &key.PublicKey),
	)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("handler must not run for a non-bearer scheme")
	}))

	req := httptest.NewRequest("GET", "/api/test", nil)
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status: got %d, want 401", rec.Code)
	}
	if !strings.Contains(rec.Header().Get("WWW-Authenticate"), "invalid_token") {
		t.Errorf("expected invalid_token challenge, got %q", rec.Header().Get("WWW-Authenticate"))
	}
}

func TestRequireBearerAuth_PanicsOnNilVerifier(t *testing.T) {
	// An auth boundary with no verifier is a programming error: fail fast at
	// construction rather than silently allowing or denying requests.
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic when verifier is nil")
		}
	}()
	RequireBearerAuth(nil)
}
