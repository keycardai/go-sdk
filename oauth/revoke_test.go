package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

// Spec row 1: the public client posts to the discovered endpoint with the default hint.
// Spec row 2: the confidential client uses Basic without a client_id in the form.
// Spec row 4: an explicit hint is sent unchanged.
// Spec row 5: HTTP 200 succeeds for known and unknown tokens with no response body.
// Spec row 10: supplied metadata skips discovery.
func TestRevokeToken_Form(t *testing.T) {
	for _, tc := range []struct {
		name, token, secret, hint string
		metadata                  bool
	}{
		{name: "public client", token: "known-refresh"},
		{name: "confidential client", token: "known-refresh", secret: "confidential secret:+&"},
		{name: "explicit hint and supplied metadata", token: "unknown-token", hint: "custom+hint", metadata: true},
		{name: "expired token", token: "expired-token"},
		{name: "unparseable token", token: "not even a JWT"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const path = "/custom/revocation"
			var requests []string
			client := &http.Client{Transport: metadataTestTransport(func(r *http.Request) (*http.Response, error) {
				requests = append(requests, r.Method+" "+r.URL.Path)
				switch r.URL.Path {
				case "/.well-known/oauth-authorization-server":
					return revocationTestResponse(http.StatusOK, `{"issuer":"https://zone.example","revocation_endpoint":"https://zone.example/custom/revocation"}`), nil
				case path:
					if got := r.Header.Get("Content-Type"); got != "application/x-www-form-urlencoded" {
						t.Errorf("Content-Type = %q", got)
					}
					if err := r.ParseForm(); err != nil {
						t.Fatal(err)
					}
					hint := tc.hint
					if hint == "" {
						hint = "refresh_token"
					}
					want := url.Values{"token": {tc.token}, "token_type_hint": {hint}}
					if tc.secret == "" {
						want.Set("client_id", "client-a")
						if r.Header.Get("Authorization") != "" {
							t.Error("public client sent Authorization header")
						}
					} else {
						id, secret, ok := r.BasicAuth()
						id, idErr := url.PathUnescape(id)
						secret, secretErr := url.PathUnescape(secret)
						if !ok || idErr != nil || secretErr != nil || id != "client-a" || secret != tc.secret {
							t.Errorf("expected OAuth Basic authentication, got %q", r.Header.Get("Authorization"))
						}
					}
					if !reflect.DeepEqual(r.PostForm, want) {
						t.Errorf("form = %v, want %v", r.PostForm, want)
					}
					return revocationTestResponse(http.StatusOK, ""), nil
				default:
					t.Fatalf("unexpected request to %s", r.URL)
					return nil, nil
				}
			})}
			issuer := "https://zone.example"
			opts := []RevocationOption{WithRevocationHTTPClient(client)}
			want := []string{"GET /.well-known/oauth-authorization-server", "POST " + path}
			if tc.metadata {
				opts = append(opts, WithRevocationMetadata(&AuthorizationServerMetadata{
					Issuer: issuer, RevocationEndpoint: issuer + path,
				}))
				issuer = ""
				want = want[1:]
			}
			err := RevokeToken(context.Background(), issuer, RevokeTokenRequest{
				Token: tc.token, TokenTypeHint: tc.hint, ClientID: "client-a", ClientSecret: tc.secret,
			}, opts...)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(requests, want) {
				t.Errorf("requests = %v, want %v", requests, want)
			}
		})
	}
}

// Spec row 3: credential authentication supplies the headers and fields, and a
// private-key assertion uses only the issuer as its audience.
func TestRevokeToken_Credential(t *testing.T) {
	const issuer = "https://zone.example/"
	md := &AuthorizationServerMetadata{Issuer: strings.TrimSuffix(issuer, "/"), RevocationEndpoint: issuer + "revoke"}
	web := NewWebIdentity(WithClientID("client-a"), WithStorageDir(t.TempDir()))
	fake := &fakeAuthenticator{}
	run := func(t *testing.T, cred ApplicationCredential, check func(*http.Request)) {
		t.Helper()
		client := &http.Client{Transport: metadataTestTransport(func(r *http.Request) (*http.Response, error) {
			if r.Method != http.MethodPost || r.URL.String() != md.RevocationEndpoint {
				t.Fatalf("unexpected request: %s %s", r.Method, r.URL)
			}
			if err := r.ParseForm(); err != nil {
				t.Fatal(err)
			}
			if len(r.PostForm) != 4 || r.PostForm.Get("token") != "test-token" ||
				r.PostForm.Get("token_type_hint") != "refresh_token" ||
				r.PostForm.Get("client_assertion_type") != clientAssertionTypeJWTBearer {
				t.Errorf("unexpected fields: %v", r.PostForm)
			}
			check(r)
			return revocationTestResponse(http.StatusOK, ""), nil
		})}
		err := RevokeToken(context.Background(), issuer, RevokeTokenRequest{Token: "test-token", Credential: cred},
			WithRevocationMetadata(md), WithRevocationHTTPClient(client))
		if err != nil {
			t.Fatal(err)
		}
	}
	t.Run("signed assertion", func(t *testing.T) {
		run(t, web, func(r *http.Request) {
			assertion := r.PostForm.Get("client_assertion")
			verifyAssertionSignature(t, web, assertion)
			claims := assertionClaims(t, assertion)
			if claims["aud"] != issuer || claims["iss"] != "client-a" || claims["sub"] != "client-a" {
				t.Errorf("unexpected assertion claims: %v", claims)
			}
		})
	})
	t.Run("credential headers and fields", func(t *testing.T) {
		run(t, fake, func(r *http.Request) {
			if r.Header.Get("Authorization") != "Basic Y2xpZW50OnNlY3JldA==" ||
				r.PostForm.Get("client_assertion") != "assertion-1" {
				t.Error("missing credential authentication material")
			}
		})
		if got, want := fake.recordedCalls(), [][2]string{{issuer, issuer}}; !reflect.DeepEqual(got, want) {
			t.Errorf("authentication calls = %v, want %v", got, want)
		}
	})
}

func TestRevokeToken_ExplicitIssuerSelectsCredential(t *testing.T) {
	const issuer = "https://zone.example/"
	cred, err := NewMultiZoneClientSecret(map[string]ClientAuth{
		issuer: {ClientID: "client-a", ClientSecret: "test-secret"},
	})
	if err != nil {
		t.Fatal(err)
	}
	md := &AuthorizationServerMetadata{Issuer: strings.TrimSuffix(issuer, "/"), RevocationEndpoint: issuer + "revoke"}
	client := &http.Client{Transport: metadataTestTransport(func(r *http.Request) (*http.Response, error) {
		id, secret, ok := r.BasicAuth()
		if !ok || id != "client-a" || secret != "test-secret" {
			t.Error("want the Basic credential for the explicit issuer")
		}
		return revocationTestResponse(http.StatusOK, ""), nil
	})}
	err = RevokeToken(context.Background(), issuer, RevokeTokenRequest{Token: "test-token", Credential: cred},
		WithRevocationMetadata(md), WithRevocationHTTPClient(client))
	if err != nil {
		t.Fatal(err)
	}
}

// Spec row 6: a missing endpoint is a configuration error and never triggers a fallback.
func TestRevokeToken_MissingEndpoint(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/.well-known/oauth-authorization-server" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"issuer": "http://" + r.Host})
	}))
	defer server.Close()

	err := RevokeToken(context.Background(), server.URL, RevokeTokenRequest{ClientID: "client-a", Token: "test-token"})
	var cfg *ConfigurationError
	if !errors.As(err, &cfg) || !strings.Contains(cfg.Message, "revocation_endpoint") {
		t.Fatalf("want configuration error for missing endpoint, got %v", err)
	}
}

func TestRevokeToken_RejectsPlaintextEndpoint(t *testing.T) {
	md := &AuthorizationServerMetadata{
		Issuer: "https://zone.example", RevocationEndpoint: "http://zone.example/revoke",
	}
	client := &http.Client{Transport: metadataTestTransport(func(r *http.Request) (*http.Response, error) {
		t.Fatalf("unexpected request: %s %s", r.Method, r.URL)
		return nil, nil
	})}
	err := RevokeToken(context.Background(), "", RevokeTokenRequest{
		Token: "test-token", ClientID: "client-a", ClientSecret: "test-secret",
	}, WithRevocationMetadata(md), WithRevocationHTTPClient(client))
	var cfg *ConfigurationError
	if !errors.As(err, &cfg) || !strings.Contains(cfg.Message, "HTTPS") {
		t.Fatalf("want configuration error requiring HTTPS, got %v", err)
	}
}

func TestRevokeToken_DoesNotFollowRedirect(t *testing.T) {
	for _, status := range []int{
		http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther,
		http.StatusTemporaryRedirect, http.StatusPermanentRedirect,
	} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost || r.URL.Path != "/revoke" {
					t.Errorf("unexpected redirected request: %s %s", r.Method, r.URL)
					w.WriteHeader(http.StatusOK)
					return
				}
				w.Header().Set("Location", "/redirected")
				w.WriteHeader(status)
			}))
			defer server.Close()
			md := &AuthorizationServerMetadata{Issuer: server.URL, RevocationEndpoint: server.URL + "/revoke"}
			err := RevokeToken(context.Background(), "", RevokeTokenRequest{Token: "test-token", ClientID: "client-a"},
				WithRevocationMetadata(md), WithRevocationHTTPClient(server.Client()))
			var got *HTTPError
			if !errors.As(err, &got) || got.Status != status || got.Retryable() {
				t.Fatalf("want a non-retryable HTTP %d error, got %v", status, err)
			}
		})
	}
}

// Spec row 9: conflicting or unsupported client authentication fails before any request.
// Spec row 11: a missing token fails before any request.
func TestRevokeToken_InvalidInput(t *testing.T) {
	for _, tc := range []struct {
		name string
		req  RevokeTokenRequest
	}{
		{"credential and client ID", RevokeTokenRequest{Token: "test-token", Credential: &fakeAuthenticator{}, ClientID: "client-a"}},
		{"credential and secret", RevokeTokenRequest{Token: "test-token", Credential: &fakeAuthenticator{}, ClientSecret: "secret"}},
		{"credential without authentication", RevokeTokenRequest{Token: "test-token", Credential: noClientAuthentication{}}},
		{"secret without client ID", RevokeTokenRequest{Token: "test-token", ClientSecret: "secret"}},
		{"missing token", RevokeTokenRequest{ClientID: "client-a"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := &http.Client{Transport: metadataTestTransport(func(r *http.Request) (*http.Response, error) {
				t.Fatalf("unexpected request: %s %s", r.Method, r.URL)
				return nil, nil
			})}
			var cfg *ConfigurationError
			err := RevokeToken(context.Background(), "https://zone.example", tc.req, WithRevocationHTTPClient(client))
			if !errors.As(err, &cfg) {
				t.Fatalf("want *ConfigurationError, got %v", err)
			}
		})
	}
}

// Spec row 7: OAuth errors preserve the status, code and description.
// Spec row 12: invalid_grant and unsupported_token_type are retryable per base.
// Spec row 13: an exchanged access token produces unsupported_token_type.
// Spec row 14: an access token without sid produces unsupported_token_type.
// Spec row 15: a recognized token from another issuer produces unsupported_token_type.
func TestRevokeToken_OAuthErrors(t *testing.T) {
	for _, tc := range []struct {
		name, code string
		status     int
		retryable  bool
	}{
		{"client authentication failed", "invalid_client", http.StatusUnauthorized, false},
		{"token issued to another client", "invalid_grant", http.StatusBadRequest, true},
		{"exchanged access token with act", "unsupported_token_type", http.StatusBadRequest, true},
		{"access token without sid", "unsupported_token_type", http.StatusBadRequest, true},
		{"recognized token from another issuer", "unsupported_token_type", http.StatusBadRequest, true},
		{"status takes precedence over code", "invalid_client", http.StatusServiceUnavailable, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := fmt.Sprintf(`{"error":%q,"error_description":%q,"reason":"test_reason"}`, tc.code, tc.name)
			calls, err := revokeWithResponse(t, tc.name, func() (*http.Response, error) {
				return revocationTestResponse(tc.status, body), nil
			})
			if calls != 1 {
				t.Errorf("revocation requests = %d, want 1", calls)
			}
			var got *OAuthError
			if !errors.As(err, &got) {
				t.Fatalf("want *OAuthError, got %v", err)
			}
			if got.Status != tc.status || got.ErrorCode != tc.code || got.Retryable() != tc.retryable ||
				got.ErrorDescription == nil || *got.ErrorDescription != tc.name ||
				got.Reason == nil || *got.Reason != "test_reason" {
				t.Errorf("unexpected OAuth error: %#v", got)
			}
		})
	}
}

// Spec row 8: transport and 5xx errors are retryable and do not trigger a retry.
func TestRevokeToken_TransportAndHTTPFailures(t *testing.T) {
	t.Run("transport", func(t *testing.T) {
		cause := errors.New("connection failed")
		calls, err := revokeWithResponse(t, "test-token", func() (*http.Response, error) { return nil, cause })
		var got *NetworkError
		if calls != 1 || !errors.As(err, &got) || !errors.Is(err, cause) || !got.Retryable() {
			t.Fatalf("want one request and retryable network error wrapping cause, got %d requests and %v", calls, err)
		}
	})
	for _, tc := range []struct {
		status    int
		retryable bool
	}{
		{http.StatusServiceUnavailable, true},
		{http.StatusTooManyRequests, true},
		{http.StatusBadRequest, false},
	} {
		t.Run(http.StatusText(tc.status), func(t *testing.T) {
			calls, err := revokeWithResponse(t, "test-token", func() (*http.Response, error) {
				return revocationTestResponse(tc.status, "not an OAuth error"), nil
			})
			var got *HTTPError
			if calls != 1 || !errors.As(err, &got) || got.Status != tc.status || got.Retryable() != tc.retryable {
				t.Fatalf("want one request and HTTP %d retryable=%t, got %d requests and %v", tc.status, tc.retryable, calls, err)
			}
		})
	}
}

func revokeWithResponse(t *testing.T, token string, response func() (*http.Response, error)) (int, error) {
	t.Helper()
	md := &AuthorizationServerMetadata{Issuer: "https://zone.example", RevocationEndpoint: "https://zone.example/revoke"}
	calls := 0
	client := &http.Client{Transport: metadataTestTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != http.MethodPost || r.URL.String() != md.RevocationEndpoint {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL)
		}
		if _, ok := r.Context().Deadline(); !ok {
			t.Error("revocation request is not bounded by a deadline")
		}
		return response()
	})}
	err := RevokeToken(context.Background(), "", RevokeTokenRequest{ClientID: "client-a", Token: token},
		WithRevocationMetadata(md), WithRevocationHTTPClient(client))
	return calls, err
}

func revocationTestResponse(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}
}
