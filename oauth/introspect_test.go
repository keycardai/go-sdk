package oauth

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"
)

const (
	introspectionTestIssuer   = "https://zone.example"
	introspectionTestEndpoint = introspectionTestIssuer + "/custom/introspection"
)

func introspectionTestMetadata() *AuthorizationServerMetadata {
	return &AuthorizationServerMetadata{Issuer: introspectionTestIssuer, IntrospectionEndpoint: introspectionTestEndpoint}
}

func introspectionTestSecret(t *testing.T) *ClientSecretCredential {
	t.Helper()
	credential, err := NewClientSecret("client-a", "secret:+&")
	if err != nil {
		t.Fatal(err)
	}
	return credential
}

func introspectionTestResponse(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}
}

// Spec row 1: the confidential client posts a form to the discovered endpoint with Basic authentication.
// Spec row 10: supplied metadata skips discovery.
// Spec row 15: a hint is sent unchanged when set and omitted otherwise.
func TestIntrospectToken_Form(t *testing.T) {
	for _, tc := range []struct {
		name, hint string
		metadata   bool
	}{
		{name: "discovered endpoint"},
		{name: "supplied metadata and custom hint", hint: "custom+hint &/", metadata: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const discoveryPath = "/.well-known/oauth-authorization-server"
			credential := introspectionTestSecret(t)
			wantForm := url.Values{"token": {"opaque +& token"}}
			if tc.hint != "" {
				wantForm.Set("token_type_hint", tc.hint)
			}
			var requests []string
			client := &http.Client{Transport: metadataTestTransport(func(r *http.Request) (*http.Response, error) {
				requests = append(requests, r.Method+" "+r.URL.String())
				switch r.URL.String() {
				case introspectionTestIssuer + discoveryPath:
					if r.Header.Get("Authorization") != "" {
						t.Error("discovery sent client authentication")
					}
					return introspectionTestResponse(http.StatusOK, `{"issuer":"`+introspectionTestIssuer+`","introspection_endpoint":"`+introspectionTestEndpoint+`"}`), nil
				case introspectionTestEndpoint:
					if got := r.Header.Get("Content-Type"); got != "application/x-www-form-urlencoded" {
						t.Errorf("Content-Type = %q", got)
					}
					if err := r.ParseForm(); err != nil {
						t.Fatal(err)
					}
					if !reflect.DeepEqual(r.PostForm, wantForm) {
						t.Errorf("form = %v, want %v", r.PostForm, wantForm)
					}
					id, secret, ok := r.BasicAuth()
					id, idErr := url.QueryUnescape(id)
					secret, secretErr := url.QueryUnescape(secret)
					if !ok || idErr != nil || secretErr != nil || id != "client-a" || secret != "secret:+&" {
						t.Error("expected OAuth Basic authentication")
					}
					return introspectionTestResponse(http.StatusOK, `{"active":false}`), nil
				default:
					t.Fatalf("unexpected request to %s", r.URL)
					return nil, nil
				}
			})}
			issuer := introspectionTestIssuer
			opts := []IntrospectionOption{WithIntrospectionHTTPClient(client)}
			wantRequests := []string{"GET " + introspectionTestIssuer + discoveryPath, "POST " + introspectionTestEndpoint}
			if tc.metadata {
				issuer = ""
				opts = append(opts, WithIntrospectionMetadata(introspectionTestMetadata()))
				wantRequests = wantRequests[1:]
			}
			if _, err := IntrospectToken(context.Background(), issuer, IntrospectTokenRequest{
				Token: "opaque +& token", TokenTypeHint: tc.hint, Credential: credential,
			}, opts...); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(requests, wantRequests) {
				t.Errorf("requests = %v, want %v", requests, wantRequests)
			}
		})
	}
}

// Spec row 2: credential headers and fields are sent, and private-key assertions
// have only the zone issuer as their audience.
func TestIntrospectToken_ClientAuthentication(t *testing.T) {
	web := NewWebIdentity(WithClientID("client-a"), WithStorageDir(t.TempDir()))
	fake := &fakeAuthenticator{}
	workload, err := NewWorkloadIdentity(IdentityTokenFunc(func(context.Context) (string, error) {
		return "platform-token", nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name       string
		credential ApplicationCredential
		check      func(*testing.T, *http.Request)
	}{
		{"signed assertion", web, func(t *testing.T, r *http.Request) {
			assertion := r.PostForm.Get("client_assertion")
			verifyAssertionSignature(t, web, assertion)
			if claims := assertionClaims(t, assertion); claims["aud"] != introspectionTestIssuer || claims["iss"] != "client-a" || claims["sub"] != "client-a" {
				t.Errorf("unexpected assertion claims: %v", claims)
			}
		}},
		{"credential fields and header", fake, func(t *testing.T, r *http.Request) {
			if r.Header.Get("Authorization") != "Basic Y2xpZW50OnNlY3JldA==" || r.PostForm.Get("client_assertion") != "assertion-1" {
				t.Error("missing credential authentication material")
			}
		}},
		{"workload assertion", workload, func(t *testing.T, r *http.Request) {
			if r.PostForm.Get("client_assertion") != "platform-token" {
				t.Error("missing workload assertion")
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := &http.Client{Transport: metadataTestTransport(func(r *http.Request) (*http.Response, error) {
				if r.Method != http.MethodPost || r.URL.String() != introspectionTestEndpoint {
					t.Fatalf("unexpected request: %s %s", r.Method, r.URL)
				}
				if err := r.ParseForm(); err != nil {
					t.Fatal(err)
				}
				if len(r.PostForm) != 3 || r.PostForm.Get("token") != "test-token" || r.PostForm.Get("client_assertion_type") != clientAssertionTypeJWTBearer {
					t.Errorf("unexpected form: %v", r.PostForm)
				}
				tc.check(t, r)
				return introspectionTestResponse(http.StatusOK, `{"active":false}`), nil
			})}
			_, err := IntrospectToken(context.Background(), introspectionTestIssuer+"/", IntrospectTokenRequest{Token: "test-token", Credential: tc.credential},
				WithIntrospectionMetadata(introspectionTestMetadata()), WithIntrospectionHTTPClient(client))
			if err != nil {
				t.Fatal(err)
			}
		})
	}
	if got, want := fake.recordedCalls(), [][2]string{{introspectionTestIssuer + "/", introspectionTestIssuer}}; !reflect.DeepEqual(got, want) {
		t.Errorf("authentication calls = %v, want %v", got, want)
	}
}

// Spec row 3: an active access token has typed claims and a scope list.
// Spec row 4: an inactive token is a result, not an error.
// Spec row 13: the issuer is typed and unknown claims are preserved.
// Spec row 14: an active refresh token has no token type.
func TestIntrospectToken_Result(t *testing.T) {
	ptr := func(s string) *string { return &s }
	iat, exp := int64(0), int64(1700000010)
	for _, tc := range []struct {
		name, body string
		want       TokenIntrospection
		extra      map[string]string
	}{
		{
			name: "active access token",
			body: `{"active":true,"token_type":"Bearer","iss":"https://zone.example","sub":"subject","client_id":"client-a","aud":["resource-a","resource-b"],"scope":"read write","sid":"session","jti":"token-id","iat":0,"exp":1700000010,"act":{"sub":"actor"},"sub_profile":"user","auth_time":9007199254740993,"keycard_app_id":"app-a"}`,
			want: TokenIntrospection{
				Active: true, TokenType: ptr("Bearer"), Issuer: ptr(introspectionTestIssuer), Subject: ptr("subject"),
				ClientID: ptr("client-a"), Audience: []string{"resource-a", "resource-b"}, Scope: []string{"read", "write"},
				SessionID: ptr("session"), JWTID: ptr("token-id"), IssuedAt: &iat, Expiry: &exp,
			},
			extra: map[string]string{"act": `{"sub":"actor"}`, "sub_profile": `"user"`, "auth_time": "9007199254740993", "keycard_app_id": `"app-a"`},
		},
		{name: "inactive", body: `{"active":false}`},
		{name: "inactive with extra data", body: `{"active":false,"iss":"https://zone.example","act":{"sub":"actor"}}`},
		{
			name: "active refresh token",
			body: `{"active":true,"aud":"https://zone.example","sid":"session"}`,
			want: TokenIntrospection{Active: true, Audience: []string{introspectionTestIssuer}, SessionID: ptr("session")},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := introspectTestToken(t, introspectionTestResponse(http.StatusOK, tc.body), nil)
			if err != nil {
				t.Fatal(err)
			}
			extra := got.Extra
			got.Extra = nil
			if !reflect.DeepEqual(*got, tc.want) {
				t.Errorf("result = %#v, want %#v", *got, tc.want)
			}
			if len(extra) != len(tc.extra) {
				t.Errorf("extra = %v, want %v", extra, tc.extra)
			}
			for name, want := range tc.extra {
				if got := string(extra[name]); got != want {
					t.Errorf("extra[%q] = %s, want %s", name, got, want)
				}
			}
		})
	}
}

func introspectTestToken(t *testing.T, response *http.Response, transportErr error) (*TokenIntrospection, error) {
	t.Helper()
	calls := 0
	client := &http.Client{Transport: metadataTestTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != http.MethodPost || r.URL.String() != introspectionTestEndpoint {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL)
		}
		return response, transportErr
	})}
	result, err := IntrospectToken(context.Background(), "", IntrospectTokenRequest{
		Token: "test-token", Credential: introspectionTestSecret(t),
	}, WithIntrospectionMetadata(introspectionTestMetadata()), WithIntrospectionHTTPClient(client))
	if calls != 1 {
		t.Errorf("requests = %d, want 1", calls)
	}
	return result, err
}

// Spec row 5: a missing endpoint causes a configuration error without endpoint fallback.
// Spec row 11: a missing client authentication capability fails before discovery.
// Spec row 12: an empty token fails before discovery.
func TestIntrospectToken_ConfigurationError(t *testing.T) {
	secret := introspectionTestSecret(t)
	for _, tc := range []struct {
		name string
		req  IntrospectTokenRequest
		md   *AuthorizationServerMetadata
	}{
		{"missing endpoint", IntrospectTokenRequest{Token: "token", Credential: secret}, &AuthorizationServerMetadata{Issuer: introspectionTestIssuer}},
		{"missing client authentication", IntrospectTokenRequest{Token: "token", Credential: noClientAuthentication{}}, nil},
		{"missing credential", IntrospectTokenRequest{Token: "token"}, nil},
		{"empty token", IntrospectTokenRequest{Credential: secret}, nil},
		{"insecure endpoint", IntrospectTokenRequest{Token: "token", Credential: secret}, &AuthorizationServerMetadata{
			Issuer: introspectionTestIssuer, IntrospectionEndpoint: "http://zone.example/introspect",
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := &http.Client{Transport: metadataTestTransport(func(r *http.Request) (*http.Response, error) {
				t.Fatalf("unexpected request: %s %s", r.Method, r.URL)
				return nil, nil
			})}
			got, err := IntrospectToken(context.Background(), introspectionTestIssuer, tc.req,
				WithIntrospectionMetadata(tc.md), WithIntrospectionHTTPClient(client))
			var configErr *ConfigurationError
			if got != nil || !errors.As(err, &configErr) {
				t.Errorf("result = %v, error = %v; want nil, *ConfigurationError", got, err)
			}
		})
	}
}

// Spec row 6: OAuth failures preserve the code, description, and HTTP status.
// Spec row 7: retryable failures, including 5xx errors, do not trigger a retry.
func TestIntrospectToken_EndpointError(t *testing.T) {
	for _, tc := range []struct {
		name, code, body string
		status           int
		retryable        bool
	}{
		{"invalid client", "invalid_client", `{"error":"invalid_client","error_description":"test description"}`, http.StatusUnauthorized, false},
		{"invalid request", "invalid_request", `{"error":"invalid_request","error_description":"test description"}`, http.StatusBadRequest, true},
		{"server error", "server_error", `{"error":"server_error","error_description":"test description"}`, http.StatusInternalServerError, true},
		{"bare 503", "", "unavailable", http.StatusServiceUnavailable, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := introspectTestToken(t, introspectionTestResponse(tc.status, tc.body), nil)
			if got != nil {
				t.Errorf("result = %v, want nil", got)
			}
			if tc.code == "" {
				var httpErr *HTTPError
				if !errors.As(err, &httpErr) || httpErr.Status != tc.status || httpErr.Retryable() != tc.retryable {
					t.Errorf("error = %#v, want retryable *HTTPError with status %d", err, tc.status)
				}
				return
			}
			var oauthErr *OAuthError
			if !errors.As(err, &oauthErr) || oauthErr.ErrorCode != tc.code || oauthErr.Status != tc.status ||
				oauthErr.ErrorDescription == nil || *oauthErr.ErrorDescription != "test description" || oauthErr.Retryable() != tc.retryable {
				t.Errorf("error = %#v, want code %s, status %d, description, retryable = %v", err, tc.code, tc.status, tc.retryable)
			}
		})
	}
	t.Run("transport failure", func(t *testing.T) {
		got, err := introspectTestToken(t, nil, context.DeadlineExceeded)
		var networkErr *NetworkError
		if got != nil || !errors.As(err, &networkErr) || !networkErr.Retryable() || !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("result = %v, error = %#v; want nil, retryable *NetworkError wrapping a timeout", got, err)
		}
	})
}

// Spec row 8: invalid bodies return a typed invalid_response.
func TestIntrospectToken_InvalidResponse(t *testing.T) {
	for _, body := range []string{"", `{"active":`, `{}`, `{"active":null}`, `{"active":"false"}`, `{"active":0}`, `{"Active":true}`, `{"active":true}{}`} {
		t.Run(body, func(t *testing.T) {
			got, err := introspectTestToken(t, introspectionTestResponse(http.StatusOK, body), nil)
			var oauthErr *OAuthError
			if got != nil || !errors.As(err, &oauthErr) || oauthErr.ErrorCode != "invalid_response" || oauthErr.Status != http.StatusOK || !oauthErr.Retryable() {
				t.Errorf("result = %v, error = %#v; want nil, retryable invalid_response with status 200", got, err)
			}
		})
	}
}

// Spec row 9: each call makes a fresh introspection request, even for the same token.
func TestIntrospectToken_DoesNotCache(t *testing.T) {
	calls := 0
	client := &http.Client{Transport: metadataTestTransport(func(*http.Request) (*http.Response, error) {
		calls++
		body := `{"active":true}`
		if calls > 1 {
			body = `{"active":false}`
		}
		return introspectionTestResponse(http.StatusOK, body), nil
	})}
	req := IntrospectTokenRequest{Token: "test-token", Credential: introspectionTestSecret(t)}
	for _, want := range []bool{true, false} {
		got, err := IntrospectToken(context.Background(), "", req,
			WithIntrospectionMetadata(introspectionTestMetadata()), WithIntrospectionHTTPClient(client))
		if err != nil || got == nil || got.Active != want {
			t.Fatalf("result = %v, error = %v; want active = %v", got, err, want)
		}
	}
	if calls != 2 {
		t.Errorf("requests = %d, want 2", calls)
	}
}

func TestIntrospectToken_BoundedResponse(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusBadRequest, http.StatusServiceUnavailable} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			got, err := introspectTestToken(t, introspectionTestResponse(status, strings.Repeat("x", int(MaxResponseBodyBytes)+1)), nil)
			var oauthErr *OAuthError
			if got != nil || !errors.As(err, &oauthErr) || oauthErr.ErrorCode != "invalid_response" ||
				oauthErr.Status != status || !errors.Is(err, ErrResponseBodyTooLarge) || oauthErr.Retryable() != (status != http.StatusBadRequest) {
				t.Errorf("result = %v, error = %#v; want nil, oversized response with status %d", got, err, status)
			}
		})
	}
}

func TestIntrospectToken_BoundedRequestAndRedirect(t *testing.T) {
	const timeout = time.Minute
	response := introspectionTestResponse(http.StatusTemporaryRedirect, "")
	response.Header.Set("Location", "https://other.example/")
	calls := 0
	client := &http.Client{Transport: metadataTestTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.String() != introspectionTestEndpoint {
			t.Fatalf("unexpected request to %s", r.URL)
		}
		if deadline, ok := r.Context().Deadline(); !ok || time.Until(deadline) <= defaultFetchTimeout || time.Until(deadline) > timeout {
			t.Error("request did not get the configured timeout")
		}
		return response, nil
	})}
	_, err := IntrospectToken(context.Background(), "", IntrospectTokenRequest{
		Token: "test-token", Credential: introspectionTestSecret(t),
	}, WithIntrospectionMetadata(introspectionTestMetadata()), WithIntrospectionHTTPClient(client), WithIntrospectionRequestTimeout(timeout))
	var httpErr *HTTPError
	if calls != 1 || !errors.As(err, &httpErr) || httpErr.Status != http.StatusTemporaryRedirect {
		t.Errorf("requests = %d, error = %#v; want one request and status 307", calls, err)
	}
}
