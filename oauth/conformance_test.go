package oauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"io"
	"math"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// --- authorization-server discovery validation ---

func TestFetchAuthorizationServerMetadata_IssuerMismatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"issuer": "https://attacker.example.com"})
	}))
	defer server.Close()

	_, err := FetchAuthorizationServerMetadata(context.Background(), server.URL)
	var mismatch *IssuerMismatchError
	if err == nil || !errors.As(err, &mismatch) {
		t.Fatalf("expected *IssuerMismatchError, got %v", err)
	}
}

func TestFetchAuthorizationServerMetadata_TrailingSlash(t *testing.T) {
	var serverURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Report the issuer with a trailing slash; it must still match a request without one.
		json.NewEncoder(w).Encode(map[string]string{"issuer": serverURL + "/"})
	}))
	defer server.Close()
	serverURL = server.URL

	if _, err := FetchAuthorizationServerMetadata(context.Background(), server.URL); err != nil {
		t.Fatalf("trailing slash should be tolerated, got %v", err)
	}
}

func TestFetchAuthorizationServerMetadata_UnknownFieldsPreserved(t *testing.T) {
	var serverURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 serverURL,
			"token_endpoint":         serverURL + "/token",
			"code_challenge_methods": []string{"S256"},
			"some_vendor_extension":  "keep-me",
		})
	}))
	defer server.Close()
	serverURL = server.URL

	md, err := FetchAuthorizationServerMetadata(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if md.Extra["some_vendor_extension"] != "keep-me" {
		t.Errorf("unknown field not preserved: Extra=%v", md.Extra)
	}
	if _, ok := md.Extra["issuer"]; ok {
		t.Error("known field 'issuer' should not appear in Extra")
	}
}

// --- token-exchange response defaults ---

func TestDeserializeTokenResponse_BearerDefaultAndIDToken(t *testing.T) {
	resp := &http.Response{Body: io.NopCloser(strings.NewReader(
		`{"access_token":"at","id_token":"the-id-token"}`))}
	tr, err := deserializeTokenResponse(resp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tr.TokenType != "Bearer" {
		t.Errorf("token_type default: got %q, want Bearer", tr.TokenType)
	}
	if tr.IDToken != "the-id-token" {
		t.Errorf("id_token: got %q, want the-id-token", tr.IDToken)
	}
}

func TestDeserializeTokenResponse_ExplicitTokenTypePreserved(t *testing.T) {
	resp := &http.Response{Body: io.NopCloser(strings.NewReader(
		`{"access_token":"at","token_type":"DPoP"}`))}
	tr, err := deserializeTokenResponse(resp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tr.TokenType != "DPoP" {
		t.Errorf("explicit token_type should be preserved: got %q", tr.TokenType)
	}
}

func TestDeserializeTokenResponse_ExpiresIn(t *testing.T) {
	tests := []struct {
		name string
		body string
		want *int
	}{
		{"absent is nil", `{"access_token":"at"}`, nil},
		{"zero is kept", `{"access_token":"at","expires_in":0}`, intPtr(0)},
		{"present", `{"access_token":"at","expires_in":3600}`, intPtr(3600)},
		{"negative is floored at zero", `{"access_token":"at","expires_in":-5}`, intPtr(0)},
		{"fraction is truncated", `{"access_token":"at","expires_in":59.9}`, intPtr(59)},
		{"MaxInt32 is kept", `{"access_token":"at","expires_in":2147483647}`, intPtr(math.MaxInt32)},
		{"above MaxInt32 is capped", `{"access_token":"at","expires_in":2147483648}`, intPtr(math.MaxInt32)},
		{"overflowing int64 is capped", `{"access_token":"at","expires_in":1e300}`, intPtr(math.MaxInt32)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{Body: io.NopCloser(strings.NewReader(tt.body))}
			tr, err := deserializeTokenResponse(resp)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			switch {
			case tt.want == nil && tr.ExpiresIn != nil:
				t.Errorf("expires_in: got %d, want nil", *tr.ExpiresIn)
			case tt.want != nil && (tr.ExpiresIn == nil || *tr.ExpiresIn != *tt.want):
				t.Errorf("expires_in: got %v, want %d", tr.ExpiresIn, *tt.want)
			}
		})
	}
}

// --- JWKS keyring: bounded cache + typed errors ---

// b1RSAJWKS returns an httptest server that serves discovery metadata plus a JWKS
// document containing one RSA key per kid in kids.
func b1RSAJWKS(t *testing.T, kids ...string) *httptest.Server {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	n := Base64URLEncode(priv.N.Bytes())
	e := Base64URLEncode(big.NewInt(int64(priv.E)).Bytes())

	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/oauth-authorization-server":
			json.NewEncoder(w).Encode(map[string]string{
				"issuer":   srv.URL,
				"jwks_uri": srv.URL + "/.well-known/jwks.json",
			})
		case "/.well-known/jwks.json":
			keys := make([]map[string]string, 0, len(kids))
			for _, kid := range kids {
				keys = append(keys, map[string]string{"kty": "RSA", "kid": kid, "n": n, "e": e})
			}
			json.NewEncoder(w).Encode(map[string]any{"keys": keys})
		default:
			http.NotFound(w, r)
		}
	}))
	return srv
}

func TestJWKSOAuthKeyring_BoundedKeyCache(t *testing.T) {
	srv := b1RSAJWKS(t, "k0", "k1", "k2", "k3", "k4", "k5")
	defer srv.Close()

	kr := NewJWKSOAuthKeyring(WithMaxKeyCacheSize(3), WithKeyringHTTPClient(srv.Client()))
	for _, kid := range []string{"k0", "k1", "k2", "k3", "k4", "k5"} {
		if _, err := kr.Key(context.Background(), srv.URL, kid); err != nil {
			t.Fatalf("resolving %s: %v", kid, err)
		}
	}

	kr.mu.Lock()
	size := len(kr.keyCache)
	kr.mu.Unlock()
	if size > 3 {
		t.Errorf("key cache not bounded: got %d entries, want <= 3", size)
	}
}

func TestJWKSOAuthKeyring_FetchError(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/oauth-authorization-server" {
			json.NewEncoder(w).Encode(map[string]string{"issuer": srv.URL, "jwks_uri": srv.URL + "/.well-known/jwks.json"})
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	kr := NewJWKSOAuthKeyring(WithKeyringHTTPClient(srv.Client()))
	_, err := kr.Key(context.Background(), srv.URL, "k0")
	var fetchErr *JWKSFetchError
	if err == nil || !errors.As(err, &fetchErr) {
		t.Fatalf("expected *JWKSFetchError, got %v", err)
	}
}

func TestJWKSOAuthKeyring_KeyNotFoundTyped(t *testing.T) {
	srv := b1RSAJWKS(t, "present-key")
	defer srv.Close()

	kr := NewJWKSOAuthKeyring(WithKeyringHTTPClient(srv.Client()))
	_, err := kr.Key(context.Background(), srv.URL, "absent-key")
	var notFound *JWKSKeyNotFoundError
	if err == nil || !errors.As(err, &notFound) {
		t.Fatalf("expected *JWKSKeyNotFoundError, got %v", err)
	}
}

func TestJWKSOAuthKeyring_UriValidationError(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/oauth-authorization-server" {
			// Cross-origin jwks_uri must be rejected.
			json.NewEncoder(w).Encode(map[string]string{"issuer": srv.URL, "jwks_uri": "https://evil.example.com/jwks.json"})
		}
	}))
	defer srv.Close()

	kr := NewJWKSOAuthKeyring(WithKeyringHTTPClient(srv.Client()))
	_, err := kr.Key(context.Background(), srv.URL, "k0")
	var valErr *JWKSUriValidationError
	if err == nil || !errors.As(err, &valErr) {
		t.Fatalf("expected *JWKSUriValidationError, got %v", err)
	}
}
