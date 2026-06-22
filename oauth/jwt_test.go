package oauth

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const testIssuer = "https://auth.example.com"

type testPrivateKeyring struct {
	key    *rsa.PrivateKey
	issuer string
}

func (r *testPrivateKeyring) Key(_ context.Context, _ string) (IdentifiableKey, error) {
	return IdentifiableKey{
		Key:    r.key,
		Issuer: r.issuer,
		KID:    "test-key-1",
	}, nil
}

// staticTestKeyring implements OAuthKeyring with a fixed public key.
type staticTestKeyring struct {
	publicKey crypto.PublicKey
}

func (r *staticTestKeyring) Key(_ context.Context, _, _ string) (crypto.PublicKey, error) {
	return r.publicKey, nil
}

// spyKeyring records whether key resolution was attempted, so tests can assert that
// policy checks rejected a token before any key lookup or network I/O.
type spyKeyring struct {
	publicKey crypto.PublicKey
	called    bool
}

func (r *spyKeyring) Key(_ context.Context, _, _ string) (crypto.PublicKey, error) {
	r.called = true
	return r.publicKey, nil
}

// validClaims returns a fully populated RFC 9068 access-token claim set. Negative
// tests start from this and drop or alter a single claim.
func validClaims() JWTClaims {
	now := time.Now().Unix()
	return JWTClaims{
		Subject:  "user-123",
		ClientID: "client-1",
		Audience: []string{"https://api.example.com"},
		Expiry:   now + 3600,
		IssuedAt: now,
	}
}

func newVerifier(t *testing.T, keyring OAuthKeyring, issuers []string, opts ...JWTVerifierOption) *JWTVerifier {
	t.Helper()
	v, err := NewJWTVerifier(keyring, issuers, opts...)
	if err != nil {
		t.Fatalf("NewJWTVerifier: %v", err)
	}
	return v
}

func TestJWTSignAndVerify(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	signer := NewJWTSigner(&testPrivateKeyring{key: privateKey, issuer: testIssuer})

	claims := validClaims()
	claims.Scope = "read write"

	token, err := signer.Sign(context.Background(), claims)
	if err != nil {
		t.Fatalf("signing: %v", err)
	}

	if token == "" {
		t.Fatal("token should not be empty")
	}

	verifier := newVerifier(t, &staticTestKeyring{publicKey: &privateKey.PublicKey}, []string{testIssuer})

	verified, err := verifier.Verify(context.Background(), token)
	if err != nil {
		t.Fatalf("verifying: %v", err)
	}

	if verified.Issuer != testIssuer {
		t.Errorf("issuer: got %q, want %q", verified.Issuer, testIssuer)
	}
	if verified.Subject != "user-123" {
		t.Errorf("subject: got %q, want %q", verified.Subject, "user-123")
	}
	if verified.Scope != "read write" {
		t.Errorf("scope: got %q, want %q", verified.Scope, "read write")
	}
	if verified.ClientID != "client-1" {
		t.Errorf("client_id: got %q, want %q", verified.ClientID, "client-1")
	}
}

func TestJWTSignerSetsIssuerFromKeyring(t *testing.T) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	signer := NewJWTSigner(&testPrivateKeyring{key: privateKey, issuer: "https://auto-issuer.example.com"})

	// Sign without setting issuer in claims; the signer fills it from the keyring.
	token, err := signer.Sign(context.Background(), validClaims())
	if err != nil {
		t.Fatalf("signing: %v", err)
	}

	verifier := newVerifier(t, &staticTestKeyring{publicKey: &privateKey.PublicKey}, []string{"https://auto-issuer.example.com"})
	verified, err := verifier.Verify(context.Background(), token)
	if err != nil {
		t.Fatalf("verifying: %v", err)
	}

	if verified.Issuer != "https://auto-issuer.example.com" {
		t.Errorf("issuer should be set from keyring: got %q", verified.Issuer)
	}
}

func TestJWTVerifier_InvalidSignature(t *testing.T) {
	signingKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	wrongKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	signer := NewJWTSigner(&testPrivateKeyring{key: signingKey, issuer: testIssuer})
	token, err := signer.Sign(context.Background(), validClaims())
	if err != nil {
		t.Fatalf("signing: %v", err)
	}

	verifier := newVerifier(t, &staticTestKeyring{publicKey: &wrongKey.PublicKey}, []string{testIssuer})
	_, err = verifier.Verify(context.Background(), token)
	if err == nil {
		t.Fatal("expected error for invalid signature")
	}

	if _, ok := err.(*InvalidTokenError); !ok {
		t.Errorf("expected InvalidTokenError, got %T: %v", err, err)
	}
}

func TestJWTVerifier_MissingIssuer(t *testing.T) {
	signingKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	// Token signed without an issuer claim.
	signer := NewJWTSigner(&testPrivateKeyring{key: signingKey, issuer: ""})
	token, err := signer.Sign(context.Background(), validClaims())
	if err != nil {
		t.Fatalf("signing: %v", err)
	}

	keyring := &spyKeyring{publicKey: &signingKey.PublicKey}
	verifier := newVerifier(t, keyring, []string{testIssuer})
	_, err = verifier.Verify(context.Background(), token)
	if err == nil {
		t.Fatal("expected error for missing issuer")
	}
	if keyring.called {
		t.Error("key lookup must not occur for a token with no issuer")
	}
}

func TestJWTVerifier_UntrustedIssuer(t *testing.T) {
	signingKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	signer := NewJWTSigner(&testPrivateKeyring{key: signingKey, issuer: "https://evil.example.com"})
	token, err := signer.Sign(context.Background(), validClaims())
	if err != nil {
		t.Fatalf("signing: %v", err)
	}

	keyring := &spyKeyring{publicKey: &signingKey.PublicKey}
	verifier := newVerifier(t, keyring, []string{testIssuer})
	_, err = verifier.Verify(context.Background(), token)
	if err == nil {
		t.Fatal("expected error for untrusted issuer")
	}
	if _, ok := err.(*InvalidTokenError); !ok {
		t.Errorf("expected InvalidTokenError, got %T: %v", err, err)
	}
	if keyring.called {
		t.Error("key lookup must not occur for an untrusted issuer")
	}
}

func TestJWTVerifier_AlgorithmNoneRejected(t *testing.T) {
	keyring := &spyKeyring{}
	tok := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{
		"iss":       testIssuer,
		"sub":       "user-123",
		"client_id": "client-1",
		"aud":       "https://api.example.com",
		"iat":       time.Now().Unix(),
		"exp":       time.Now().Add(time.Hour).Unix(),
	})
	tok.Header["kid"] = "test-key-1"
	token, err := tok.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("signing none token: %v", err)
	}

	verifier := newVerifier(t, keyring, []string{testIssuer})
	_, err = verifier.Verify(context.Background(), token)
	if err == nil {
		t.Fatal("expected error for alg=none")
	}
	if keyring.called {
		t.Error("key lookup must not occur for alg=none")
	}
}

func TestJWTVerifier_AlgorithmOutsideAllowlist(t *testing.T) {
	signingKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	signer := NewJWTSigner(&testPrivateKeyring{key: signingKey, issuer: testIssuer})
	token, err := signer.Sign(context.Background(), validClaims())
	if err != nil {
		t.Fatalf("signing: %v", err)
	}

	// Token is RS256, but the verifier only allows ES256.
	keyring := &spyKeyring{publicKey: &signingKey.PublicKey}
	verifier := newVerifier(t, keyring, []string{testIssuer}, WithAlgorithms("ES256"))
	_, err = verifier.Verify(context.Background(), token)
	if err == nil {
		t.Fatal("expected error for algorithm outside the allowlist")
	}
	if keyring.called {
		t.Error("key lookup must not occur for a disallowed algorithm")
	}
}

func TestJWTVerifier_MissingRequiredClaims(t *testing.T) {
	signingKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	signer := NewJWTSigner(&testPrivateKeyring{key: signingKey, issuer: testIssuer})
	verifier := newVerifier(t, &staticTestKeyring{publicKey: &signingKey.PublicKey}, []string{testIssuer})

	cases := map[string]func(*JWTClaims){
		"missing sub":       func(c *JWTClaims) { c.Subject = "" },
		"missing client_id": func(c *JWTClaims) { c.ClientID = "" },
		"missing aud":       func(c *JWTClaims) { c.Audience = nil },
		"missing exp":       func(c *JWTClaims) { c.Expiry = 0 },
		"missing iat":       func(c *JWTClaims) { c.IssuedAt = 0 },
	}

	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			claims := validClaims()
			mutate(&claims)
			token, err := signer.Sign(context.Background(), claims)
			if err != nil {
				t.Fatalf("signing: %v", err)
			}
			if _, err := verifier.Verify(context.Background(), token); err == nil {
				t.Fatalf("expected error for %s", name)
			}
		})
	}
}

func TestJWTVerifier_MissingKid(t *testing.T) {
	signingKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	// Sign directly so the kid header is omitted, with otherwise valid claims.
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss":       testIssuer,
		"sub":       "user-123",
		"client_id": "client-1",
		"aud":       "https://api.example.com",
		"iat":       time.Now().Unix(),
		"exp":       time.Now().Add(time.Hour).Unix(),
	})
	token, err := tok.SignedString(signingKey)
	if err != nil {
		t.Fatalf("signing: %v", err)
	}

	keyring := &spyKeyring{publicKey: &signingKey.PublicKey}
	verifier := newVerifier(t, keyring, []string{testIssuer})
	_, err = verifier.Verify(context.Background(), token)
	if err == nil {
		t.Fatal("expected error for missing kid header")
	}
	if keyring.called {
		t.Error("key lookup must not occur when kid is missing")
	}
}

func TestJWTVerifier_AudienceNoIntersection(t *testing.T) {
	signingKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	signer := NewJWTSigner(&testPrivateKeyring{key: signingKey, issuer: testIssuer})
	claims := validClaims()
	claims.Audience = []string{"https://other.example.com"}
	token, err := signer.Sign(context.Background(), claims)
	if err != nil {
		t.Fatalf("signing: %v", err)
	}

	verifier := newVerifier(t, &staticTestKeyring{publicKey: &signingKey.PublicKey},
		[]string{testIssuer}, WithAudiences("https://api.example.com"))
	_, err = verifier.Verify(context.Background(), token)
	if err == nil {
		t.Fatal("expected error when aud does not intersect the configured audiences")
	}
}

func TestJWTVerifier_AudienceMatch(t *testing.T) {
	signingKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	signer := NewJWTSigner(&testPrivateKeyring{key: signingKey, issuer: testIssuer})
	claims := validClaims()
	claims.Audience = []string{"https://api.example.com", "https://other.example.com"}
	token, err := signer.Sign(context.Background(), claims)
	if err != nil {
		t.Fatalf("signing: %v", err)
	}

	verifier := newVerifier(t, &staticTestKeyring{publicKey: &signingKey.PublicKey},
		[]string{testIssuer}, WithAudiences("https://api.example.com"))
	if _, err := verifier.Verify(context.Background(), token); err != nil {
		t.Fatalf("token with intersecting audience should verify: %v", err)
	}
}

func TestJWTVerifier_ExpiredToken(t *testing.T) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	signer := NewJWTSigner(&testPrivateKeyring{key: privateKey, issuer: testIssuer})

	// Token expired 1 hour ago (well beyond leeway).
	claims := validClaims()
	claims.Expiry = time.Now().Unix() - 3600
	claims.IssuedAt = time.Now().Unix() - 7200
	token, err := signer.Sign(context.Background(), claims)
	if err != nil {
		t.Fatalf("signing: %v", err)
	}

	verifier := newVerifier(t, &staticTestKeyring{publicKey: &privateKey.PublicKey}, []string{testIssuer})
	_, err = verifier.Verify(context.Background(), token)
	if err == nil {
		t.Fatal("expected error for expired token")
	}

	if _, ok := err.(*InvalidTokenError); !ok {
		t.Errorf("expected InvalidTokenError, got %T: %v", err, err)
	}
}

func TestJWTVerifier_NotYetValid(t *testing.T) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	signer := NewJWTSigner(&testPrivateKeyring{key: privateKey, issuer: testIssuer})

	// Token not valid until 1 hour from now (well beyond leeway).
	claims := validClaims()
	claims.NotBefore = time.Now().Unix() + 3600
	claims.Expiry = time.Now().Unix() + 7200
	token, err := signer.Sign(context.Background(), claims)
	if err != nil {
		t.Fatalf("signing: %v", err)
	}

	verifier := newVerifier(t, &staticTestKeyring{publicKey: &privateKey.PublicKey}, []string{testIssuer})
	_, err = verifier.Verify(context.Background(), token)
	if err == nil {
		t.Fatal("expected error for not-yet-valid token")
	}

	if _, ok := err.(*InvalidTokenError); !ok {
		t.Errorf("expected InvalidTokenError, got %T: %v", err, err)
	}
}

func TestJWTVerifier_WithinLeeway(t *testing.T) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	signer := NewJWTSigner(&testPrivateKeyring{key: privateKey, issuer: testIssuer})

	// Token expired 30 seconds ago, within the default 60s leeway.
	claims := validClaims()
	claims.Expiry = time.Now().Unix() - 30
	claims.IssuedAt = time.Now().Unix() - 3600
	token, err := signer.Sign(context.Background(), claims)
	if err != nil {
		t.Fatalf("signing: %v", err)
	}

	verifier := newVerifier(t, &staticTestKeyring{publicKey: &privateKey.PublicKey}, []string{testIssuer})
	_, err = verifier.Verify(context.Background(), token)
	if err != nil {
		t.Fatalf("token expired by 30s should be accepted within 60s leeway: %v", err)
	}
}

func TestJWTVerifier_CustomLeeway(t *testing.T) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	signer := NewJWTSigner(&testPrivateKeyring{key: privateKey, issuer: testIssuer})

	// Token expired 30 seconds ago.
	claims := validClaims()
	claims.Expiry = time.Now().Unix() - 30
	claims.IssuedAt = time.Now().Unix() - 3600
	token, err := signer.Sign(context.Background(), claims)
	if err != nil {
		t.Fatalf("signing: %v", err)
	}

	// A 10-second leeway rejects a token that expired 30s ago.
	verifier := newVerifier(t, &staticTestKeyring{publicKey: &privateKey.PublicKey},
		[]string{testIssuer}, WithVerifierLeeway(10*time.Second))
	_, err = verifier.Verify(context.Background(), token)
	if err == nil {
		t.Fatal("token expired by 30s should be rejected with 10s leeway")
	}
}

func TestNewJWTVerifier_ConfigurationErrors(t *testing.T) {
	keyring := &staticTestKeyring{}

	if _, err := NewJWTVerifier(keyring, nil); err == nil {
		t.Error("expected configuration error for empty issuers")
	} else if _, ok := err.(*ConfigurationError); !ok {
		t.Errorf("expected ConfigurationError, got %T: %v", err, err)
	}

	if _, err := NewJWTVerifier(keyring, []string{testIssuer}, WithAlgorithms("none")); err == nil {
		t.Error("expected configuration error for alg=none")
	}

	if _, err := NewJWTVerifier(keyring, []string{testIssuer}, WithAlgorithms("HS256")); err == nil {
		t.Error("expected configuration error for an unsupported algorithm")
	}
}

func TestJWTClaims_Accessors(t *testing.T) {
	now := time.Now().Unix()
	c := JWTClaims{
		Expiry:    now + 3600,
		IssuedAt:  now,
		NotBefore: now - 60,
	}

	exp, err := c.GetExpirationTime()
	if err != nil {
		t.Fatalf("GetExpirationTime error: %v", err)
	}
	if exp == nil || exp.Unix() != now+3600 {
		t.Errorf("GetExpirationTime: got %v, want %d", exp, now+3600)
	}

	iat, err := c.GetIssuedAt()
	if err != nil {
		t.Fatalf("GetIssuedAt error: %v", err)
	}
	if iat == nil || iat.Unix() != now {
		t.Errorf("GetIssuedAt: got %v, want %d", iat, now)
	}

	nbf, err := c.GetNotBefore()
	if err != nil {
		t.Fatalf("GetNotBefore error: %v", err)
	}
	if nbf == nil || nbf.Unix() != now-60 {
		t.Errorf("GetNotBefore: got %v, want %d", nbf, now-60)
	}

	// Zero values should return nil.
	empty := JWTClaims{}
	exp, _ = empty.GetExpirationTime()
	if exp != nil {
		t.Errorf("zero Expiry should return nil, got %v", exp)
	}
	iat, _ = empty.GetIssuedAt()
	if iat != nil {
		t.Errorf("zero IssuedAt should return nil, got %v", iat)
	}
	nbf, _ = empty.GetNotBefore()
	if nbf != nil {
		t.Errorf("zero NotBefore should return nil, got %v", nbf)
	}
}
