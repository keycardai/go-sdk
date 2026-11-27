package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/keycardai/go-sdk/oauth"
)

// grantTokenServer is a fake zone that records requests to its token endpoint.
type grantTokenServer struct {
	*httptest.Server
	mu       sync.Mutex
	requests []*http.Request
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
		s.requests = append(s.requests, r)
		s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "tok-for-" + r.Form.Get("resource"), "token_type": "bearer"})
	})
	t.Cleanup(s.Close)
	return s
}

func (s *grantTokenServer) tokenForms() []url.Values {
	requests := s.tokenRequests()
	forms := make([]url.Values, 0, len(requests))
	for _, r := range requests {
		forms = append(forms, r.Form)
	}
	return forms
}

func (s *grantTokenServer) tokenRequests() []*http.Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*http.Request(nil), s.requests...)
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

// Spec row 3 (token-exchange): a configured client secret authenticates the grant with Basic.
func TestGrant_AuthenticatesWithClientSecret(t *testing.T) {
	zone := newGrantTokenServer(t)
	provider := newSingleZoneProvider(t, zone.URL)

	testGrantClientAuthentication(t, provider, zone, func(t *testing.T, r *http.Request) {
		assertGrantBasicAuth(t, r, "agent-client", "agent-secret")
	})
}

// Spec row 4b (client-credentials and token-exchange): the grant client supplies assertion authentication.
// Spec row 6 (impersonation): a configured assertion credential authenticates the substitute-user exchange.
func TestGrant_AuthenticatesWithWebIdentity(t *testing.T) {
	zone := newGrantTokenServer(t)
	provider, err := NewAuthProvider(WithZoneURL(zone.URL), WithApplicationCredential(
		oauth.NewWebIdentity(oauth.WithClientID("web-client"), oauth.WithStorageDir(t.TempDir())),
	))
	if err != nil {
		t.Fatalf("NewAuthProvider: %v", err)
	}

	testGrantClientAuthentication(t, provider, zone, func(t *testing.T, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Error("assertion authentication sends an Authorization header")
		}
		const assertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
		if got := r.Form.Get("client_assertion_type"); got != assertionType {
			t.Errorf("client_assertion_type: got %q, want %q", got, assertionType)
		}
		claims := &jwt.RegisteredClaims{}
		if _, _, err := jwt.NewParser().ParseUnverified(r.Form.Get("client_assertion"), claims); err != nil {
			t.Fatalf("parse client_assertion: %v", err)
		}
		if claims.Issuer != "web-client" || claims.Subject != "web-client" {
			t.Errorf("assertion iss/sub: got %q/%q, want web-client/web-client", claims.Issuer, claims.Subject)
		}
		if len(claims.Audience) != 1 || claims.Audience[0] != zone.URL+"/token" {
			t.Errorf("assertion audience: got %v, want [%s/token]", claims.Audience, zone.URL)
		}
	})
}

// Spec rows 3 and 6 (multi-zone-support): each zone's client authenticates with its own credential.
func TestGrant_AuthenticatesWithResolvedZoneCredential(t *testing.T) {
	zoneA, zoneB := newGrantTokenServer(t), newGrantTokenServer(t)
	provider, err := NewAuthProvider(WithApplicationCredential(mustMultiZone(t, map[string]ClientAuth{
		zoneA.URL: {ClientID: "client-a", ClientSecret: "secret-a"},
		zoneB.URL: {ClientID: "client-b", ClientSecret: "secret-b"},
	})))
	if err != nil {
		t.Fatalf("NewAuthProvider: %v", err)
	}

	t.Run("zone A", func(t *testing.T) {
		testGrantClientAuthentication(t, provider, zoneA, func(t *testing.T, r *http.Request) {
			assertGrantBasicAuth(t, r, "client-a", "secret-a")
		})
	})
	t.Run("zone B", func(t *testing.T) {
		testGrantClientAuthentication(t, provider, zoneB, func(t *testing.T, r *http.Request) {
			assertGrantBasicAuth(t, r, "client-b", "secret-b")
		})
	})
}

func assertGrantBasicAuth(t *testing.T, r *http.Request, clientID, secret string) {
	t.Helper()
	if id, password, ok := r.BasicAuth(); !ok || id != clientID || password != secret {
		t.Errorf("request lacks the expected Basic authentication for %q", clientID)
	}
	for _, key := range []string{"client_id", "client_secret", "client_assertion", "client_assertion_type"} {
		if r.Form.Has(key) {
			t.Errorf("Basic authentication sends %s in the form", key)
		}
	}
}

func testGrantClientAuthentication(t *testing.T, provider *AuthProvider, zone *grantTokenServer, checkAuth func(*testing.T, *http.Request)) {
	t.Helper()
	for _, tc := range []struct {
		name, subjectTokenType string
		opts                   []GrantOption
	}{
		{name: "exchange", subjectTokenType: "urn:ietf:params:oauth:token-type:access_token"},
		{name: "impersonation", subjectTokenType: oauth.SubstituteUserTokenType, opts: []GrantOption{
			WithUserIdentifier(func(*http.Request) (string, error) { return "user-42", nil }),
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const resource = "https://api.example.com"
			before := len(zone.tokenRequests())
			ac := runGrant(t, zone.URL, "user-token", provider.Grant([]string{resource}, tc.opts...))
			if ac.Status() != StatusSuccess {
				re, ge := ac.GetErrors()
				t.Fatalf("status: got %q, want success; errors: %+v %+v", ac.Status(), re, ge)
			}
			requests := zone.tokenRequests()[before:]
			if len(requests) != 1 {
				t.Fatalf("token requests: got %d, want 1", len(requests))
			}
			if got := requests[0].Form.Get("subject_token_type"); got != tc.subjectTokenType {
				t.Errorf("subject_token_type: got %q, want %q", got, tc.subjectTokenType)
			}
			checkAuth(t, requests[0])
		})
	}
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
