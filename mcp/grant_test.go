package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"

	"github.com/keycardai/go-sdk/oauth"
)

// grantTokenServer is a fake zone that serves discovery and a /token endpoint, recording
// the form of every token request so a test can assert how the grant exchanged.
type grantTokenServer struct {
	*httptest.Server
	mu    sync.Mutex
	forms []url.Values
}

func newGrantTokenServer(t *testing.T) *grantTokenServer {
	t.Helper()
	s := &grantTokenServer{}
	mux := http.NewServeMux()
	s.Server = httptest.NewServer(mux)
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"issuer": s.URL, "token_endpoint": s.URL + "/token"})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		s.mu.Lock()
		s.forms = append(s.forms, r.Form)
		s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "tok-for-" + r.Form.Get("resource"), "token_type": "bearer"})
	})
	t.Cleanup(s.Close)
	return s
}

func (s *grantTokenServer) tokenForms() []url.Values {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]url.Values, len(s.forms))
	copy(out, s.forms)
	return out
}

// runGrant drives the grant middleware with an injected AuthInfo and returns the
// resulting AccessContext.
func runGrant(t *testing.T, issuer, token string, mw func(http.Handler) http.Handler) *AccessContext {
	t.Helper()
	var captured *AccessContext
	handler := mw(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		captured = AccessContextFromRequest(r)
	}))
	req := httptest.NewRequest("POST", "/mcp", nil)
	req = req.WithContext(context.WithValue(req.Context(), authInfoKey, &AuthInfo{Token: token, Issuer: issuer}))
	handler.ServeHTTP(httptest.NewRecorder(), req)
	return captured
}

func newSingleZoneProvider(t *testing.T, zoneURL string) *AuthProvider {
	t.Helper()
	provider, err := NewAuthProvider(
		WithZoneURL(zoneURL),
		WithApplicationCredential(mustClientSecret(t, "agent-client", "agent-secret")),
	)
	if err != nil {
		t.Fatalf("NewAuthProvider: %v", err)
	}
	return provider
}

func TestGrant_RequestScopes(t *testing.T) {
	zone := newGrantTokenServer(t)
	provider := newSingleZoneProvider(t, zone.URL)

	ac := runGrant(t, zone.URL, "user-token",
		provider.Grant([]string{"https://api.example.com"}, WithRequestScopes("read", "write")))

	if ac.Status() != StatusSuccess {
		t.Fatalf("status: got %q, want success", ac.Status())
	}

	var exchange url.Values
	for _, f := range zone.tokenForms() {
		if f.Get("grant_type") == "urn:ietf:params:oauth:grant-type:token-exchange" {
			exchange = f
		}
	}
	if exchange == nil {
		t.Fatalf("no token-exchange request reached the zone; forms=%v", zone.tokenForms())
	}
	if got := exchange.Get("scope"); got != "read write" {
		t.Errorf("scope: got %q, want %q", got, "read write")
	}
}

func TestGrant_RequestScopesByResource(t *testing.T) {
	zone := newGrantTokenServer(t)
	provider := newSingleZoneProvider(t, zone.URL)

	ac := runGrant(t, zone.URL, "user-token",
		provider.Grant(
			[]string{"https://a.example.com", "https://b.example.com"},
			WithRequestScopes("default.scope"), // fallback for resources not in the map
			WithRequestScopesByResource(map[string][]string{
				"https://a.example.com": {"a.read", "a.write"},
			}),
		))

	if ac.Status() != StatusSuccess {
		t.Fatalf("status: got %q, want success", ac.Status())
	}

	byResource := map[string]string{}
	for _, f := range zone.tokenForms() {
		if f.Get("grant_type") == "urn:ietf:params:oauth:grant-type:token-exchange" {
			byResource[f.Get("resource")] = f.Get("scope")
		}
	}
	if got := byResource["https://a.example.com"]; got != "a.read a.write" {
		t.Errorf("resource a scope: got %q, want %q (per-resource)", got, "a.read a.write")
	}
	if got := byResource["https://b.example.com"]; got != "default.scope" {
		t.Errorf("resource b scope: got %q, want %q (falls back to flat)", got, "default.scope")
	}
}

func TestGrant_UserIdentifierImpersonates(t *testing.T) {
	zone := newGrantTokenServer(t)
	provider := newSingleZoneProvider(t, zone.URL)

	resolved := false
	ac := runGrant(t, zone.URL, "user-token",
		provider.Grant([]string{"https://api.example.com"},
			WithUserIdentifier(func(_ *http.Request) (string, error) {
				resolved = true
				return "user-42", nil
			}),
			WithRequestScopes("inventory.read"),
		))

	if !resolved {
		t.Error("user identifier resolver was not called")
	}
	if ac.Status() != StatusSuccess {
		t.Fatalf("status: got %q, want success", ac.Status())
	}

	// Impersonation performs the exchange as a substitute-user (not the caller's token),
	// and the requested scopes reach that exchange.
	var substituteUser url.Values
	for _, f := range zone.tokenForms() {
		if f.Get("subject_token_type") == oauth.SubstituteUserTokenType {
			substituteUser = f
		}
	}
	if substituteUser == nil {
		t.Fatalf("expected a substitute-user exchange (impersonation); forms=%v", zone.tokenForms())
	}
	if got := substituteUser.Get("scope"); got != "inventory.read" {
		t.Errorf("impersonation scope: got %q, want %q", got, "inventory.read")
	}
}

func TestGrant_UserIdentifierErrorFailsClosed(t *testing.T) {
	zone := newGrantTokenServer(t)
	provider := newSingleZoneProvider(t, zone.URL)

	ac := runGrant(t, zone.URL, "user-token",
		provider.Grant([]string{"https://api.example.com"},
			WithUserIdentifier(func(_ *http.Request) (string, error) {
				return "", context.DeadlineExceeded
			}),
		))

	if !ac.HasError() {
		t.Error("expected a global error when the user-identifier resolver fails")
	}
	if n := len(zone.tokenForms()); n != 0 {
		t.Errorf("token endpoint was hit %d times; a failed resolver must not exchange", n)
	}
}

func TestGrant_StacksAndMerges(t *testing.T) {
	zone := newGrantTokenServer(t)
	provider := newSingleZoneProvider(t, zone.URL)

	// Two stacked grants for different resources merge into one AccessContext.
	inner := provider.Grant([]string{"https://b.example.com"})
	outer := provider.Grant([]string{"https://a.example.com"})

	ac := runGrant(t, zone.URL, "user-token", func(next http.Handler) http.Handler {
		return outer(inner(next))
	})

	if ac.Status() != StatusSuccess {
		t.Fatalf("status: got %q, want success", ac.Status())
	}
	if _, err := ac.Access("https://a.example.com"); err != nil {
		t.Errorf("resource a: %v", err)
	}
	if _, err := ac.Access("https://b.example.com"); err != nil {
		t.Errorf("resource b: %v", err)
	}
}
