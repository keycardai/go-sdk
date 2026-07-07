package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

// impersonateFixture stands up a fake authorization server that records the
// form payload of every /token request so tests can assert on them.
type impersonateFixture struct {
	server     *httptest.Server
	mu         sync.Mutex
	calls      []url.Values
	responders []http.HandlerFunc
}

func newImpersonateFixture(t *testing.T, responders ...http.HandlerFunc) *impersonateFixture {
	t.Helper()
	f := &impersonateFixture{responders: responders}

	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/oauth-authorization-server":
			_ = json.NewEncoder(w).Encode(map[string]string{
				"issuer":         "http://" + r.Host,
				"token_endpoint": "http://" + r.Host + "/token",
			})
		case "/token":
			if err := r.ParseForm(); err != nil {
				t.Fatalf("parsing form: %v", err)
			}
			f.mu.Lock()
			idx := len(f.calls)
			f.calls = append(f.calls, r.Form)
			f.mu.Unlock()

			if idx >= len(f.responders) {
				t.Fatalf("unexpected token call #%d", idx+1)
			}
			f.responders[idx](w, r)
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	t.Cleanup(f.server.Close)
	return f
}

func ccOKResponder() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "actor-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}
}

func exchangeOKResponder() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "issued-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
			"scope":        "read:mail",
		})
	}
}

func oauthErrorResponder(status int, code string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": code})
	}
}

// Spec table row 1: valid user, valid resource → token returned, substitute-user URN
// sent, and by default no actor token — zones without RFC 8693 actor-token support
// reject any actor_token_type, so the zero value must produce the plain exchange.
func TestImpersonate_FullCall(t *testing.T) {
	f := newImpersonateFixture(t, exchangeOKResponder())

	client := NewTokenExchangeClient(f.server.URL, WithClientCredentials("app", "secret"))
	resp, err := client.Impersonate(context.Background(), ImpersonateRequest{
		UserIdentifier: "alice@example.com",
		Resource:       "https://graph.microsoft.com",
		Scopes:         []string{"read:mail", "read:calendar"},
	})
	if err != nil {
		t.Fatalf("Impersonate: %v", err)
	}
	if resp.AccessToken != "issued-token" {
		t.Errorf("access_token: got %q, want issued-token", resp.AccessToken)
	}

	if len(f.calls) != 1 {
		t.Fatalf("token endpoint hit count: got %d, want 1 (exchange only)", len(f.calls))
	}

	exchange := f.calls[0]
	if got := exchange.Get("grant_type"); got != "urn:ietf:params:oauth:grant-type:token-exchange" {
		t.Errorf("exchange grant_type: got %q", got)
	}
	if got := exchange.Get("subject_token_type"); got != SubstituteUserTokenType {
		t.Errorf("subject_token_type: got %q, want %q", got, SubstituteUserTokenType)
	}
	if exchange.Has("actor_token") {
		t.Errorf("actor_token: got %q, want absent", exchange.Get("actor_token"))
	}
	if exchange.Has("actor_token_type") {
		t.Errorf("actor_token_type: got %q, want absent", exchange.Get("actor_token_type"))
	}
	if got := exchange.Get("resource"); got != "https://graph.microsoft.com" {
		t.Errorf("resource: got %q", got)
	}
	if got := exchange.Get("scope"); got != "read:mail read:calendar" {
		t.Errorf("scope: got %q", got)
	}

	payload := decodeSubstituteUserPayload(t, exchange.Get("subject_token"))
	if payload["sub"] != "alice@example.com" {
		t.Errorf("subject_token sub: got %v", payload["sub"])
	}
}

// ActorResource set → an actor token is minted via client_credentials audienced to
// it and attached to the exchange; ClientAssertion rides on both calls.
func TestImpersonate_WithActorResource(t *testing.T) {
	f := newImpersonateFixture(t, ccOKResponder(), exchangeOKResponder())

	client := NewTokenExchangeClient(f.server.URL, WithClientCredentials("app", "secret"))
	resp, err := client.Impersonate(context.Background(), ImpersonateRequest{
		UserIdentifier:      "alice@example.com",
		Resource:            "https://graph.microsoft.com",
		ActorResource:       "urn:example:agent:self",
		ClientAssertion:     "assertion.jwt.value",
		ClientAssertionType: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
	})
	if err != nil {
		t.Fatalf("Impersonate: %v", err)
	}
	if resp.AccessToken != "issued-token" {
		t.Errorf("access_token: got %q, want issued-token", resp.AccessToken)
	}

	if len(f.calls) != 2 {
		t.Fatalf("token endpoint hit count: got %d, want 2 (actor mint + exchange)", len(f.calls))
	}

	cc, exchange := f.calls[0], f.calls[1]
	if got := cc.Get("grant_type"); got != "client_credentials" {
		t.Errorf("actor mint grant_type: got %q", got)
	}
	if got := cc.Get("resource"); got != "urn:example:agent:self" {
		t.Errorf("actor mint resource: got %q, want urn:example:agent:self", got)
	}
	if got := cc.Get("client_assertion"); got != "assertion.jwt.value" {
		t.Errorf("actor mint client_assertion: got %q", got)
	}

	if got := exchange.Get("actor_token"); got != "actor-access-token" {
		t.Errorf("actor_token: got %q", got)
	}
	if got := exchange.Get("actor_token_type"); got != substituteUserActorTokenType {
		t.Errorf("actor_token_type: got %q", got)
	}
	if got := exchange.Get("client_assertion"); got != "assertion.jwt.value" {
		t.Errorf("exchange client_assertion: got %q", got)
	}
	if got := exchange.Get("client_assertion_type"); got != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
		t.Errorf("exchange client_assertion_type: got %q", got)
	}
}

// Spec table row 2: unknown user_identifier → invalid_grant.
func TestImpersonate_UnknownUserIdentifier(t *testing.T) {
	f := newImpersonateFixture(t, oauthErrorResponder(http.StatusBadRequest, "invalid_grant"))

	client := NewTokenExchangeClient(f.server.URL, WithClientCredentials("app", "secret"))
	_, err := client.Impersonate(context.Background(), ImpersonateRequest{
		UserIdentifier: "ghost@example.com",
		Resource:       "https://api.example.com",
	})
	var oauthErr *OAuthError
	if !errors.As(err, &oauthErr) {
		t.Fatalf("expected *OAuthError, got %T: %v", err, err)
	}
	if oauthErr.ErrorCode != "invalid_grant" {
		t.Errorf("error code: got %q, want invalid_grant", oauthErr.ErrorCode)
	}
}

// Spec table row 3: client lacks impersonation permission → unauthorized_client.
func TestImpersonate_UnauthorizedClient(t *testing.T) {
	f := newImpersonateFixture(t, oauthErrorResponder(http.StatusBadRequest, "unauthorized_client"))

	client := NewTokenExchangeClient(f.server.URL, WithClientCredentials("app", "secret"))
	_, err := client.Impersonate(context.Background(), ImpersonateRequest{
		UserIdentifier: "alice@example.com",
		Resource:       "https://api.example.com",
	})
	var oauthErr *OAuthError
	if !errors.As(err, &oauthErr) {
		t.Fatalf("expected *OAuthError, got %T: %v", err, err)
	}
	if oauthErr.ErrorCode != "unauthorized_client" {
		t.Errorf("error code: got %q, want unauthorized_client", oauthErr.ErrorCode)
	}
}

// Spec table row 4: resource omitted → client-side validation error (resource is required).
func TestImpersonate_ResourceRequiredLocally(t *testing.T) {
	// No fixture — the request must be rejected before any HTTP call.
	client := NewTokenExchangeClient("http://unused.invalid")
	_, err := client.Impersonate(context.Background(), ImpersonateRequest{
		UserIdentifier: "alice@example.com",
	})
	if err == nil {
		t.Fatal("expected error for missing Resource")
	}
	if !strings.Contains(err.Error(), "Resource") {
		t.Errorf("error should mention Resource, got: %v", err)
	}
}

// Spec table row 5: scopes omitted → exchange call omits scope param.
func TestImpersonate_ScopesOmitted(t *testing.T) {
	f := newImpersonateFixture(t, exchangeOKResponder())

	client := NewTokenExchangeClient(f.server.URL, WithClientCredentials("app", "secret"))
	_, err := client.Impersonate(context.Background(), ImpersonateRequest{
		UserIdentifier: "alice@example.com",
		Resource:       "https://api.example.com",
	})
	if err != nil {
		t.Fatalf("Impersonate: %v", err)
	}
	exchange := f.calls[0]
	if exchange.Has("scope") {
		t.Errorf("scope should be omitted, got %q", exchange.Get("scope"))
	}
}

func TestImpersonate_EmptyUserIdentifierRejectedLocally(t *testing.T) {
	// No fixture — request must be rejected before any HTTP call.
	client := NewTokenExchangeClient("http://unused.invalid")
	_, err := client.Impersonate(context.Background(), ImpersonateRequest{})
	if err == nil {
		t.Fatal("expected error for empty UserIdentifier")
	}
	if !strings.Contains(err.Error(), "UserIdentifier") {
		t.Errorf("error should mention UserIdentifier, got: %v", err)
	}
}

// buildSubstituteUserToken format checks.
func TestBuildSubstituteUserToken_Format(t *testing.T) {
	token := buildSubstituteUserToken("alice@example.com")

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 parts, got %d: %q", len(parts), token)
	}
	if parts[2] != "" {
		t.Errorf("signature segment must be empty, got %q", parts[2])
	}

	headerBytes, err := Base64URLDecode(parts[0])
	if err != nil {
		t.Fatalf("decoding header: %v", err)
	}
	var header map[string]string
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		t.Fatalf("parsing header: %v", err)
	}
	if header["typ"] != "vnd.kc.su+jwt" {
		t.Errorf("header.typ: got %q", header["typ"])
	}
	if header["alg"] != "none" {
		t.Errorf("header.alg: got %q", header["alg"])
	}

	payloadBytes, err := Base64URLDecode(parts[1])
	if err != nil {
		t.Fatalf("decoding payload: %v", err)
	}
	var payload map[string]string
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		t.Fatalf("parsing payload: %v", err)
	}
	if payload["sub"] != "alice@example.com" {
		t.Errorf("payload.sub: got %q", payload["sub"])
	}
}

func decodeSubstituteUserPayload(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 parts, got %d", len(parts))
	}
	raw, err := Base64URLDecode(parts[1])
	if err != nil {
		t.Fatalf("decoding payload: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("parsing payload: %v", err)
	}
	return out
}
