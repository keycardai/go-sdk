package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/keycardai/go-sdk/oauth"
)

type mockTokenVerifier struct {
	verifyFunc func(ctx context.Context, token string) (*AuthInfo, error)
}

func (m *mockTokenVerifier) VerifyAccessToken(ctx context.Context, token string) (*AuthInfo, error) {
	return m.verifyFunc(ctx, token)
}

func TestRequireBearerAuth_ValidToken(t *testing.T) {
	verifier := &mockTokenVerifier{
		verifyFunc: func(_ context.Context, token string) (*AuthInfo, error) {
			return &AuthInfo{
				Token:    token,
				ClientID: "client-123",
				Scopes:   []string{"read", "write"},
			}, nil
		},
	}

	handler := RequireBearerAuth(verifier)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		info := AuthInfoFromRequest(r)
		json.NewEncoder(w).Encode(info)
	}))

	req := httptest.NewRequest("GET", "/api/test", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status: got %d, want 200", rec.Code)
	}
}

func TestRequireBearerAuth_MissingHeader(t *testing.T) {
	verifier := &mockTokenVerifier{}

	handler := RequireBearerAuth(verifier)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called")
	}))

	req := httptest.NewRequest("GET", "/api/test", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status: got %d, want 401", rec.Code)
	}

	challenge := rec.Header().Get("WWW-Authenticate")
	if !strings.Contains(challenge, "Bearer") {
		t.Errorf("expected Bearer challenge, got %q", challenge)
	}
	if !strings.Contains(challenge, "resource_metadata") {
		t.Errorf("expected resource_metadata in challenge, got %q", challenge)
	}
}

func TestRequireBearerAuth_ChallengeIncludesResourcePath(t *testing.T) {
	verifier := &mockTokenVerifier{}

	handler := RequireBearerAuth(verifier)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called")
	}))

	// RFC 9728 path insertion: the challenge for a resource at /mcp must advertise
	// .well-known/oauth-protected-resource/mcp, not the bare origin (ACC-591).
	req := httptest.NewRequest("POST", "/mcp", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	challenge := rec.Header().Get("WWW-Authenticate")
	if !strings.Contains(challenge, "/.well-known/oauth-protected-resource/mcp") {
		t.Errorf("expected path-inserted resource_metadata in challenge, got %q", challenge)
	}
}

func TestRequireBearerAuth_ChallengeRootPath(t *testing.T) {
	verifier := &mockTokenVerifier{}

	handler := RequireBearerAuth(verifier)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called")
	}))

	// A resource at the root advertises the bare well-known path, with no trailing slash.
	req := httptest.NewRequest("POST", "/", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	challenge := rec.Header().Get("WWW-Authenticate")
	if !strings.Contains(challenge, `/.well-known/oauth-protected-resource"`) {
		t.Errorf("expected bare resource_metadata (no trailing path) for root resource, got %q", challenge)
	}
}

func TestRequireBearerAuth_MalformedHeader(t *testing.T) {
	verifier := &mockTokenVerifier{}

	handler := RequireBearerAuth(verifier)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called")
	}))

	req := httptest.NewRequest("GET", "/api/test", nil)
	req.Header.Set("Authorization", "Bearer")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status: got %d, want 400", rec.Code)
	}
}

func TestRequireBearerAuth_InvalidToken(t *testing.T) {
	verifier := &mockTokenVerifier{
		verifyFunc: func(_ context.Context, _ string) (*AuthInfo, error) {
			return nil, &oauth.InvalidTokenError{Message: "bad signature"}
		},
	}

	handler := RequireBearerAuth(verifier)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called")
	}))

	req := httptest.NewRequest("GET", "/api/test", nil)
	req.Header.Set("Authorization", "Bearer bad-token")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status: got %d, want 401", rec.Code)
	}

	challenge := rec.Header().Get("WWW-Authenticate")
	if !strings.Contains(challenge, "invalid_token") {
		t.Errorf("expected invalid_token in challenge, got %q", challenge)
	}
}

func TestRequireBearerAuth_InsufficientScope(t *testing.T) {
	verifier := &mockTokenVerifier{
		verifyFunc: func(_ context.Context, token string) (*AuthInfo, error) {
			return &AuthInfo{
				Token:    token,
				ClientID: "client-123",
				Scopes:   []string{"read"},
			}, nil
		},
	}

	handler := RequireBearerAuth(
		verifier,
		WithRequiredScopes("admin"),
	)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called")
	}))

	req := httptest.NewRequest("GET", "/api/test", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("status: got %d, want 403", rec.Code)
	}

	challenge := rec.Header().Get("WWW-Authenticate")
	if !strings.Contains(challenge, "insufficient_scope") {
		t.Errorf("expected insufficient_scope in challenge, got %q", challenge)
	}
}

func TestRequireBearerAuth_ExpiredToken(t *testing.T) {
	verifier := &mockTokenVerifier{
		verifyFunc: func(_ context.Context, token string) (*AuthInfo, error) {
			return &AuthInfo{
				Token:     token,
				ClientID:  "client-123",
				Scopes:    []string{"read"},
				ExpiresAt: 1000, // far in the past
			}, nil
		},
	}

	handler := RequireBearerAuth(verifier)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called for expired token")
	}))

	req := httptest.NewRequest("GET", "/api/test", nil)
	req.Header.Set("Authorization", "Bearer expired-token")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status: got %d, want 401", rec.Code)
	}

	challenge := rec.Header().Get("WWW-Authenticate")
	if !strings.Contains(challenge, "Token has expired") {
		t.Errorf("expected 'Token has expired' in challenge, got %q", challenge)
	}
}

func TestRequireBearerAuth_NoExpiry(t *testing.T) {
	verifier := &mockTokenVerifier{
		verifyFunc: func(_ context.Context, token string) (*AuthInfo, error) {
			return &AuthInfo{
				Token:     token,
				ClientID:  "client-123",
				Scopes:    []string{"read"},
				ExpiresAt: 0, // no expiry set
			}, nil
		},
	}

	handler := RequireBearerAuth(verifier)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/api/test", nil)
	req.Header.Set("Authorization", "Bearer no-expiry-token")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status: got %d, want 200 (no expiry should pass)", rec.Code)
	}
}

func TestAuthInfoFromRequest_NilWhenNotSet(t *testing.T) {
	req := httptest.NewRequest("GET", "/api/test", nil)
	info := AuthInfoFromRequest(req)
	if info != nil {
		t.Error("expected nil AuthInfo when not set")
	}
}

func TestAuthInfoFromContext(t *testing.T) {
	if info := AuthInfoFromContext(context.Background()); info != nil {
		t.Error("expected nil AuthInfo when not set")
	}

	verifier := &mockTokenVerifier{
		verifyFunc: func(_ context.Context, token string) (*AuthInfo, error) {
			return &AuthInfo{Token: token, ClientID: "client-123"}, nil
		},
	}

	// The context handed to the next handler must carry the same AuthInfo the
	// request accessor sees: MCP framework tool handlers receive that context,
	// not the *http.Request.
	handler := RequireBearerAuth(verifier)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		info := AuthInfoFromContext(r.Context())
		if info == nil {
			t.Fatal("expected AuthInfo from context")
		}
		if info != AuthInfoFromRequest(r) {
			t.Error("AuthInfoFromContext and AuthInfoFromRequest should return the same AuthInfo")
		}
		if info.ClientID != "client-123" {
			t.Errorf("ClientID: got %q, want %q", info.ClientID, "client-123")
		}
	}))

	req := httptest.NewRequest("GET", "/api/test", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status: got %d, want 200", rec.Code)
	}
}

func TestAccessContextFromContext(t *testing.T) {
	if ac := AccessContextFromContext(context.Background()); ac != nil {
		t.Error("expected nil AccessContext when not set")
	}

	ac := NewAccessContext()
	ctx := context.WithValue(context.Background(), accessContextKey, ac)

	got := AccessContextFromContext(ctx)
	if got != ac {
		t.Error("expected the AccessContext stored in the context")
	}

	req := httptest.NewRequest("GET", "/api/test", nil).WithContext(ctx)
	if AccessContextFromRequest(req) != ac {
		t.Error("AccessContextFromRequest should return the same AccessContext as AccessContextFromContext")
	}
}
