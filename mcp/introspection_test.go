package mcp

import (
	"crypto"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/keycardai/go-sdk/oauth"
)

const (
	introspectionPath = "/oauth/introspect-custom"
	discoveryPath     = "/.well-known/oauth-authorization-server"
)

type introspectionTransport func(*http.Request) (*http.Response, error)

func (f introspectionTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func introspectionResponse(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}
}

func introspectionClient(t *testing.T, endpoint introspectionTransport) *http.Client {
	t.Helper()
	return &http.Client{Transport: introspectionTransport(func(r *http.Request) (*http.Response, error) {
		switch r.URL.Path {
		case discoveryPath:
			if r.Method != http.MethodGet || r.Header.Get("Authorization") != "" {
				t.Errorf("unexpected discovery method or authorization")
			}
			issuer := "https://" + r.URL.Host
			return introspectionResponse(200, fmt.Sprintf(`{"issuer":%q,"introspection_endpoint":%q}`, issuer, issuer+introspectionPath)), nil
		case introspectionPath:
			return endpoint(r)
		default:
			t.Errorf("unexpected request: %s", r.URL)
			return nil, errors.New("unexpected request")
		}
	})}
}

func checkIntrospectionForm(t *testing.T, r *http.Request, issuer, token, id, secret string) {
	t.Helper()
	if r.Method != http.MethodPost || r.URL.String() != issuer+introspectionPath {
		t.Errorf("unexpected introspection target: %s %s", r.Method, r.URL)
	}
	if err := r.ParseForm(); err != nil || r.PostForm.Get("token") != token || len(r.PostForm) != 1 {
		t.Error("expected the presented token as the only form field")
	}
	gotID, gotSecret, ok := r.BasicAuth()
	if !ok || gotID != id || gotSecret != secret {
		t.Error("expected the resource application's client authentication")
	}
}

func singleIntrospectionBinding(t *testing.T, key *rsa.PrivateKey, opts ...BearerAuthOption) http.Handler {
	t.Helper()
	b := makeBinding(t, bindingIssuer, WithResourceIdentifier(bindingMCP))
	return bindingAuth(t, b, append([]BearerAuthOption{WithBearerKeyring(&pubKeyring{pub: &key.PublicKey})}, opts...)...)
}

// Spec row 18 (bearer-token-verification-middleware): send the presented token and configured credential; active runs the handler.
// Spec row 2 (net-http): pass the option and application credential through net/http.
// Spec integration row 3 (bearer-token-verification-middleware) and row 1 (net-http), hermetic: the owning Application can introspect another client's token.
func TestBearerIntrospection_ActiveTokenFromAnotherClient(t *testing.T) {
	key := bindingKey(t)
	token := bindingToken(t, key, bindingIssuer, bindingMCP)
	cred := mustClientSecret(t, "resource-server", "app-secret")
	calls := 0
	client := introspectionClient(t, func(r *http.Request) (*http.Response, error) {
		calls++
		checkIntrospectionForm(t, r, bindingIssuer, token, "resource-server", "app-secret")
		return introspectionResponse(200, `{"active":true,"client_id":"different-introspection-claim"}`), nil
	})
	opts := []BearerAuthOption{WithIntrospect(true), WithIntrospectionCredential(cred), WithIntrospectionHTTPClient(client)}
	bound := singleIntrospectionBinding(t, key, opts...)
	assertBindingResponse(t, sendBindingRequest(bound, bindingMCP, token, nil), 204, "", "")

	verifier, err := NewJWTOAuthTokenVerifier(&pubKeyring{pub: &key.PublicKey}, []string{bindingIssuer}, oauth.WithAudiences(bindingMCP))
	if err != nil {
		t.Fatal(err)
	}
	legacy := RequireBearerAuth(verifier, opts...)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if info := AuthInfoFromRequest(r); info == nil || info.ClientID != "client" || info.Issuer != bindingIssuer {
			t.Errorf("handler must receive the original verified claims: %v", info)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	assertBindingResponse(t, sendBindingRequest(legacy, bindingMCP, token, nil), 204, "", "")
	if calls != 2 {
		t.Errorf("introspection calls = %d, want 2", calls)
	}
}

// Spec row 19 (bearer-token-verification-middleware): an inactive token gets a 401 challenge, with metadata only on the matching route.
// Spec row 3 (net-http): an inactive token never reaches the handler.
func TestBearerIntrospection_InactiveChallenge(t *testing.T) {
	key := bindingKey(t)
	client := introspectionClient(t, func(*http.Request) (*http.Response, error) {
		return introspectionResponse(200, `{"active":false}`), nil
	})
	h := singleIntrospectionBinding(t, key, WithIntrospect(true),
		WithIntrospectionCredential(mustClientSecret(t, "app", "secret")), WithIntrospectionHTTPClient(client))
	token := bindingToken(t, key, bindingIssuer, bindingMCP)
	assertBindingResponse(t, sendBindingRequest(h, bindingMCP, token, nil), 401, "invalid_token", bindingHost+protectedResourcePath+"/mcp")
	assertBindingResponse(t, sendBindingRequest(h, bindingHost+"/elsewhere", token, nil), 401, "invalid_token", "")
}

// Spec row 20 (bearer-token-verification-middleware): any introspection failure is a 503 without a challenge.
// Spec row 4 (net-http): the introspection failure does not reach the HTTP handler.
func TestBearerIntrospection_FailuresAreUnavailable(t *testing.T) {
	key := bindingKey(t)
	token := bindingToken(t, key, bindingIssuer, bindingMCP)
	for _, tc := range []struct {
		name, metadata, body string
		status               int
		transportError       bool
	}{
		{name: "transport", transportError: true},
		{name: "plain HTTP error", status: 502, body: "bad gateway"},
		{name: "OAuth invalid_client", status: 401, body: `{"error":"invalid_client"}`},
		{name: "OAuth server_error", status: 500, body: `{"error":"server_error"}`},
		{name: "malformed JSON", status: 200, body: `{"active":`},
		{name: "missing active", status: 200, body: `{}`},
		{name: "nonboolean active", status: 200, body: `{"active":"true"}`},
		{name: "missing endpoint", metadata: `{"issuer":"https://keycard.cloud"}`},
		{name: "mismatching issuer", metadata: `{"issuer":"https://elsewhere.example","introspection_endpoint":"https://elsewhere.example/custom"}`},
		{name: "discovery redirect", status: 302},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := introspectionClient(t, func(*http.Request) (*http.Response, error) {
				if tc.transportError {
					return nil, errors.New("connection refused")
				}
				return introspectionResponse(tc.status, tc.body), nil
			})
			if tc.metadata != "" || tc.status == 302 {
				client.Transport = introspectionTransport(func(r *http.Request) (*http.Response, error) {
					if r.URL.String() != bindingIssuer+discoveryPath {
						t.Errorf("unexpected request after failed discovery: %s", r.URL)
					}
					if tc.status == 302 {
						resp := introspectionResponse(302, "")
						resp.Header.Set("Location", "https://elsewhere.example/metadata")
						return resp, nil
					}
					return introspectionResponse(200, tc.metadata), nil
				})
			}
			h := singleIntrospectionBinding(t, key, WithIntrospect(true),
				WithIntrospectionCredential(mustClientSecret(t, "app", "secret")), WithIntrospectionHTTPClient(client))
			assertUnavailable(t, sendBindingRequest(h, bindingMCP, token, nil), false)
		})
	}
}

// Spec row 21 (bearer-token-verification-middleware): invalid local tokens and disabled introspection make no discovery or introspection request.
// Spec row 1 (net-http): omission or false preserves local verification.
func TestBearerIntrospection_SkipsDisabledAndInvalidTokens(t *testing.T) {
	key := bindingKey(t)
	token := bindingToken(t, key, bindingIssuer, bindingMCP)
	client := &http.Client{Transport: introspectionTransport(func(r *http.Request) (*http.Response, error) {
		t.Errorf("unexpected upstream request: %s", r.URL)
		return nil, errors.New("unexpected request")
	})}
	for _, opts := range [][]BearerAuthOption{{}, {WithIntrospect(false)}} {
		h := singleIntrospectionBinding(t, key, append(opts, WithIntrospectionHTTPClient(client))...)
		assertBindingResponse(t, sendBindingRequest(h, bindingMCP, token, nil), 204, "", "")
	}
	h := singleIntrospectionBinding(t, key, WithIntrospect(true),
		WithIntrospectionCredential(mustClientSecret(t, "app", "secret")), WithIntrospectionHTTPClient(client))
	for _, invalid := range []string{"malformed", bindingToken(t, key, "https://untrusted.example", bindingMCP)} {
		assertBindingResponse(t, sendBindingRequest(h, bindingMCP, invalid, nil), 401, "invalid_token", bindingHost+protectedResourcePath+"/mcp")
	}
}

// Spec row 22 (bearer-token-verification-middleware): the same token is checked on every request.
// Spec integration row 4 (bearer-token-verification-middleware), hermetic: the session becomes revoked between requests.
func TestBearerIntrospection_ObservesRevocation(t *testing.T) {
	key := bindingKey(t)
	token := bindingToken(t, key, bindingIssuer, bindingMCP)
	revoked := false
	calls := 0
	client := introspectionClient(t, func(*http.Request) (*http.Response, error) {
		calls++
		return introspectionResponse(200, fmt.Sprintf(`{"active":%t}`, !revoked)), nil
	})
	h := singleIntrospectionBinding(t, key, WithIntrospect(true),
		WithIntrospectionCredential(mustClientSecret(t, "app", "secret")), WithIntrospectionHTTPClient(client))
	assertBindingResponse(t, sendBindingRequest(h, bindingMCP, token, nil), 204, "", "")
	revoked = true
	assertBindingResponse(t, sendBindingRequest(h, bindingMCP, token, nil), 401, "invalid_token", bindingHost+protectedResourcePath+"/mcp")
	if calls != 2 {
		t.Errorf("introspection calls = %d, want 2", calls)
	}
}

// Spec row 23 (bearer-token-verification-middleware): missing, non-authenticating and unkeyed multi-zone credentials fail at construction.
// Spec row 5 (net-http): the net/http constructor reports a configuration error for a credential without client authentication.
func TestBearerIntrospection_RejectsInvalidConfiguration(t *testing.T) {
	b := makeBinding(t, bindingIssuer, WithResourceIdentifier(bindingMCP))
	key := bindingKey(t)
	keyring := &pubKeyring{pub: &key.PublicKey}
	single, err := NewJWTOAuthTokenVerifier(keyring, []string{bindingIssuer}, oauth.WithAudiences(bindingMCP))
	if err != nil {
		t.Fatal(err)
	}
	for _, cred := range []oauth.ApplicationCredential{nil, &capturingCredential{}, (*oauth.ClientSecretCredential)(nil), &oauth.ClientSecretCredential{}, oauth.NewWebIdentity()} {
		opts := []BearerAuthOption{WithIntrospect(true), WithIntrospectionCredential(cred)}
		_, err := b.BearerAuth(opts...)
		expectBindingConfigError(t, err)
		_, err = NewBearerAuth(single, opts...)
		expectBindingConfigError(t, err)
	}
	opts := []BearerAuthOption{WithIntrospect(true), WithIntrospectionCredential(mustClientSecret(t, "app", "secret"))}
	multi, err := NewMultiZoneTokenVerifier([]string{"https://a.keycard.cloud", "https://b.keycard.cloud"}, oauth.WithAudiences(bindingMCP))
	if err != nil {
		t.Fatal(err)
	}
	_, err = NewBearerAuth(multi, opts...)
	expectBindingConfigError(t, err)
	b = makeBinding(t, bindingIssuer, WithResourceIdentifiersByZone(map[string]string{"a": bindingMCP, "b": bindingHost + "/other"}))
	_, err = b.BearerAuth(append(opts, WithInboundZoneResolver(func(_, _ string) string { return "a" }))...)
	expectBindingConfigError(t, err)
}

// Spec row 24 (bearer-token-verification-middleware): the verified issuer selects its credential, or fails closed without an upstream request.
func TestBearerIntrospection_RoutesByVerifiedIssuer(t *testing.T) {
	key := bindingKey(t)
	a, b, c := "https://a.keycard.cloud", "https://b.keycard.cloud", "https://c.keycard.cloud"
	verifier, err := NewJWTOAuthTokenVerifier(&multiZoneKeyring{keys: map[string]crypto.PublicKey{
		a: &key.PublicKey, b: &key.PublicKey, c: &key.PublicKey,
	}}, []string{a, b, c}, oauth.WithAudiences(bindingMCP))
	if err != nil {
		t.Fatal(err)
	}
	creds := map[string]ClientAuth{
		a: {ClientID: "app-a", ClientSecret: "secret-a"},
		b: {ClientID: "app-b", ClientSecret: "secret-b"},
	}
	tokens := map[string]string{}
	for _, issuer := range []string{a, b, c} {
		tokens[issuer] = bindingToken(t, key, issuer, bindingMCP)
	}
	var requests []string
	client := introspectionClient(t, func(r *http.Request) (*http.Response, error) {
		issuer := "https://" + r.URL.Host
		cfg := creds[issuer]
		checkIntrospectionForm(t, r, issuer, tokens[issuer], cfg.ClientID, cfg.ClientSecret)
		return introspectionResponse(200, `{"active":true}`), nil
	})
	transport := client.Transport
	client.Transport = introspectionTransport(func(r *http.Request) (*http.Response, error) {
		requests = append(requests, r.URL.String())
		return transport.RoundTrip(r)
	})
	h := RequireBearerAuth(verifier, WithIntrospect(true), WithIntrospectionCredential(mustMultiZone(t, creds)),
		WithIntrospectionHTTPClient(client))(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	for _, issuer := range []string{b, a} {
		assertBindingResponse(t, sendBindingRequest(h, bindingMCP, tokens[issuer], nil), 204, "", "")
	}
	assertUnavailable(t, sendBindingRequest(h, bindingMCP, tokens[c], nil), false)
	if got, want := strings.Join(requests, " "), b+discoveryPath+" "+b+introspectionPath+" "+a+discoveryPath+" "+a+introspectionPath; got != want {
		t.Errorf("upstream requests = %q, want %q", got, want)
	}
}

// Spec row 25 (bearer-token-verification-middleware): insufficient scope fails with 403 before introspection.
func TestBearerIntrospection_SkipsInsufficientScope(t *testing.T) {
	key := bindingKey(t)
	h := singleIntrospectionBinding(t, key, WithIntrospect(true), WithRequiredScopes("read"),
		WithIntrospectionCredential(mustClientSecret(t, "app", "secret")),
		WithIntrospectionHTTPClient(&http.Client{Transport: introspectionTransport(func(r *http.Request) (*http.Response, error) {
			t.Errorf("unexpected request: %s", r.URL)
			return nil, errors.New("unexpected request")
		})}))
	assertBindingResponse(t, sendBindingRequest(h, bindingMCP, bindingToken(t, key, bindingIssuer, bindingMCP), nil),
		403, "insufficient_scope", bindingHost+protectedResourcePath+"/mcp")
}

// Spec integration row 5 (bearer-token-verification-middleware), hermetic: a later audience passes local verification but the zone reports it inactive.
func TestBearerIntrospection_LaterAudienceIsRejectedByZone(t *testing.T) {
	key := bindingKey(t)
	token := bindingToken(t, key, bindingIssuer, "https://different.example", bindingMCP)
	client := introspectionClient(t, func(r *http.Request) (*http.Response, error) {
		checkIntrospectionForm(t, r, bindingIssuer, token, "app", "secret")
		return introspectionResponse(200, `{"active":false}`), nil
	})
	h := singleIntrospectionBinding(t, key, WithIntrospect(true),
		WithIntrospectionCredential(mustClientSecret(t, "app", "secret")), WithIntrospectionHTTPClient(client))
	assertBindingResponse(t, sendBindingRequest(h, bindingMCP, token, nil), 401, "invalid_token", bindingHost+protectedResourcePath+"/mcp")
}

func TestBearerIntrospection_UsesConfiguredTimeout(t *testing.T) {
	key := bindingKey(t)
	token := bindingToken(t, key, bindingIssuer, bindingMCP)
	called := false
	client := introspectionClient(t, func(r *http.Request) (*http.Response, error) {
		called = true
		deadline, ok := r.Context().Deadline()
		if !ok || time.Until(deadline) > time.Second {
			t.Errorf("expected the configured short deadline, got %v", deadline)
		}
		return introspectionResponse(200, `{"active":true}`), nil
	})
	h := singleIntrospectionBinding(t, key, WithIntrospect(true), WithIntrospectionRequestTimeout(time.Second),
		WithIntrospectionCredential(mustClientSecret(t, "app", "secret")), WithIntrospectionHTTPClient(client))
	assertBindingResponse(t, sendBindingRequest(h, bindingMCP, token, nil), 204, "", "")
	if !called {
		t.Error("expected an introspection request")
	}
}

func TestBearerIntrospection_LogsEachFailureOnce(t *testing.T) {
	logs := bindingWarnings(t)
	key := bindingKey(t)
	token := bindingToken(t, key, bindingIssuer, bindingMCP)
	code := "invalid_client"
	requests := 0
	client := introspectionClient(t, func(*http.Request) (*http.Response, error) {
		requests++
		description := fmt.Sprintf("request %d: %s", requests, token)
		return introspectionResponse(500, fmt.Sprintf(`{"error":%q,"error_description":%q}`, code, description)), nil
	})
	h := singleIntrospectionBinding(t, key, WithIntrospect(true),
		WithIntrospectionCredential(mustClientSecret(t, "app", "secret")), WithIntrospectionHTTPClient(client))
	for _, next := range []string{"invalid_client", "server_error", "invalid_client", "server_error"} {
		code = next
		assertUnavailable(t, sendBindingRequest(h, bindingMCP, token, nil), false)
	}
	for _, want := range []string{"OAuth invalid_client", "OAuth server_error"} {
		if strings.Count(logs.String(), want) != 1 {
			t.Errorf("expected one log for %s", want)
		}
	}
	if strings.Contains(logs.String(), token) {
		t.Error("introspection log contains the bearer token")
	}
}

// Spec row 22 (bearer-token-verification-middleware): requests reuse discovery but not introspection results.
// Spec row 5 (base): discovery failures for a missing required endpoint use the negative TTL.
func TestBearerIntrospection_CachesDiscovery(t *testing.T) {
	key := bindingKey(t)
	token := bindingToken(t, key, bindingIssuer, bindingMCP)
	for _, tc := range []struct {
		name      string
		endpoint  string
		wantPosts int
	}{
		{name: "cache hit", endpoint: bindingIssuer + introspectionPath, wantPosts: 2},
		{name: "negative cache hit"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gets, posts := 0, 0
			client := &http.Client{Transport: introspectionTransport(func(r *http.Request) (*http.Response, error) {
				switch r.URL.Path {
				case discoveryPath:
					gets++
					return introspectionResponse(200, fmt.Sprintf(`{"issuer":%q,"introspection_endpoint":%q}`, bindingIssuer, tc.endpoint)), nil
				case introspectionPath:
					posts++
					return introspectionResponse(200, fmt.Sprintf(`{"active":%t}`, posts == 1)), nil
				default:
					return nil, fmt.Errorf("unexpected request: %s", r.URL)
				}
			})}
			h := singleIntrospectionBinding(t, key, WithIntrospect(true),
				WithIntrospectionCredential(mustClientSecret(t, "app", "secret")), WithIntrospectionHTTPClient(client))
			first := sendBindingRequest(h, bindingMCP, token, nil)
			second := sendBindingRequest(h, bindingMCP, token, nil)
			if tc.wantPosts == 0 {
				assertUnavailable(t, first, false)
				assertUnavailable(t, second, false)
			} else {
				assertBindingResponse(t, first, 204, "", "")
				assertBindingResponse(t, second, 401, "invalid_token", bindingHost+protectedResourcePath+"/mcp")
			}
			if gets != 1 || posts != tc.wantPosts {
				t.Errorf("discovery GETs = %d, introspection POSTs = %d; want 1 GET and %d POSTs", gets, posts, tc.wantPosts)
			}
		})
	}
}

// Spec row 20 (bearer-token-verification-middleware): each verified zone logs its own failure cause once.
func TestBearerIntrospection_LogsFailurePerVerifiedIssuer(t *testing.T) {
	key := bindingKey(t)
	a, b := "https://a.keycard.cloud", "https://b.keycard.cloud"
	verifier, err := NewJWTOAuthTokenVerifier(&multiZoneKeyring{keys: map[string]crypto.PublicKey{
		a: &key.PublicKey, b: &key.PublicKey,
	}}, []string{a, b}, oauth.WithAudiences(bindingMCP))
	if err != nil {
		t.Fatal(err)
	}
	cred := mustMultiZone(t, map[string]ClientAuth{
		a: {ClientID: "app-a", ClientSecret: "secret-a"},
		b: {ClientID: "app-b", ClientSecret: "secret-b"},
	})
	tokens := map[string]string{
		a: bindingToken(t, key, a, bindingMCP),
		b: bindingToken(t, key, b, bindingMCP),
	}
	for _, tc := range []struct {
		name string
		want string
	}{
		{name: "configuration", want: "does not advertise an introspection_endpoint"},
		{name: "network", want: "introspection request failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logs := bindingWarnings(t)
			client := &http.Client{Transport: introspectionTransport(func(r *http.Request) (*http.Response, error) {
				issuer := "https://" + r.URL.Host
				endpoint := ""
				if tc.name == "network" {
					endpoint = issuer + introspectionPath
				}
				if r.URL.Path == discoveryPath {
					return introspectionResponse(200, fmt.Sprintf(`{"issuer":%q,"introspection_endpoint":%q}`, issuer, endpoint)), nil
				}
				return nil, fmt.Errorf("transport error contains %s", tokens[issuer])
			})}
			h := RequireBearerAuth(verifier, WithIntrospect(true), WithIntrospectionCredential(cred),
				WithIntrospectionHTTPClient(client))(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				t.Error("unexpected handler call")
			}))
			for _, issuer := range []string{a, a, b, b} {
				assertUnavailable(t, sendBindingRequest(h, bindingMCP, tokens[issuer], nil), false)
			}
			for _, issuer := range []string{a, b} {
				count := 0
				for _, line := range strings.Split(logs.String(), "\n") {
					if strings.Contains(line, "issuer="+issuer) && strings.Contains(line, tc.want) {
						count++
					}
				}
				if count != 1 {
					t.Errorf("issuer %s logged %d matching failures, want 1", issuer, count)
				}
				if strings.Contains(logs.String(), tokens[issuer]) {
					t.Errorf("log for issuer %s contains the bearer token", issuer)
				}
			}
		})
	}
}

// Spec row 23 (bearer-token-verification-middleware): reject unusable introspection issuer configuration before serving requests.
func TestBearerIntrospection_RejectsInvalidIssuerURLsAtConstruction(t *testing.T) {
	for _, issuer := range []string{"http://keycard.cloud", "/relative", "https://:443", "", "https://keycard.cloud?query=value"} {
		t.Run("trusted issuer "+issuer, func(t *testing.T) {
			verifier, err := NewMultiZoneTokenVerifier([]string{bindingIssuer, issuer}, oauth.WithAudiences(bindingMCP))
			if err != nil {
				t.Fatal(err)
			}
			cred := mustMultiZone(t, map[string]ClientAuth{bindingIssuer: {ClientID: "app", ClientSecret: "secret"}})
			options := []BearerAuthOption{WithIntrospect(true), WithIntrospectionCredential(cred)}
			_, err = NewBearerAuth(verifier, options...)
			expectBindingConfigError(t, err)
			_, err = NewBearerAuth(verifier, append(options, WithIntrospect(false))...)
			if err != nil {
				t.Fatalf("local verification configuration: %v", err)
			}
		})
	}
	t.Run("resource binding with HTTP issuer", func(t *testing.T) {
		b := makeBinding(t, "http://keycard.cloud", WithResourceIdentifier(bindingMCP))
		_, err := b.BearerAuth(WithIntrospect(true), WithIntrospectionCredential(mustClientSecret(t, "app", "secret")))
		expectBindingConfigError(t, err)
	})
	t.Run("credential zone key not trusted by verifier", func(t *testing.T) {
		b := makeBinding(t, bindingIssuer, WithResourceIdentifier(bindingMCP))
		cred := mustMultiZone(t, map[string]ClientAuth{
			bindingIssuer:       {ClientID: "app", ClientSecret: "secret"},
			"http://other.zone": {ClientID: "other-app", ClientSecret: "other-secret"},
		})
		_, err := b.BearerAuth(WithIntrospect(true), WithIntrospectionCredential(cred))
		expectBindingConfigError(t, err)
	})
}
