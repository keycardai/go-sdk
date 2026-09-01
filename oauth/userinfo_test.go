package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

const testAccessToken = "user-access-token"

// userInfoServer serves the discovery document and a UserInfo response written by the
// given handler, and records the requests it received.
func userInfoServer(t *testing.T, userinfo http.HandlerFunc) (*httptest.Server, *[]*http.Request) {
	t.Helper()
	var requests []*http.Request
	var issuer string
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r)
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]any{
			"issuer":            issuer,
			"userinfo_endpoint": issuer + "/userinfo",
		}); err != nil {
			t.Errorf("encoding discovery document: %v", err)
		}
	})
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r)
		userinfo(w, r)
	})
	server := httptest.NewServer(mux)
	issuer = server.URL
	return server, &requests
}

func claimsHandler(claims map[string]any) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(claims); err != nil {
			return
		}
	}
}

// Spec row 1: valid token, endpoint returns claims JSON.
func TestFetchUserInfo(t *testing.T) {
	server, requests := userInfoServer(t, claimsHandler(map[string]any{
		"sub":    "user-123",
		"email":  "kim@example.com",
		"groups": []string{"engineering"},
	}))
	defer server.Close()

	user, err := FetchUserInfo(context.Background(), server.URL, testAccessToken)
	if err != nil {
		t.Fatalf("FetchUserInfo: %v", err)
	}

	if user.Subject != "user-123" {
		t.Errorf("Subject = %q, want %q", user.Subject, "user-123")
	}
	if user.Claims["email"] != "kim@example.com" {
		t.Errorf("email claim = %v, want kim@example.com", user.Claims["email"])
	}
	if user.Claims["sub"] != "user-123" {
		t.Errorf("sub is missing from the claims document: %v", user.Claims)
	}

	if len(*requests) != 2 {
		t.Fatalf("expected a discovery request then a UserInfo request, got %d requests", len(*requests))
	}
	discovery, userinfo := (*requests)[0], (*requests)[1]
	if discovery.URL.Path != "/.well-known/oauth-authorization-server" {
		t.Errorf("first request path = %q", discovery.URL.Path)
	}
	if userinfo.Method != http.MethodGet {
		t.Errorf("UserInfo method = %q, want GET", userinfo.Method)
	}
	if got := userinfo.Header.Get("Authorization"); got != "Bearer "+testAccessToken {
		t.Errorf("Authorization header = %q", got)
	}
	if got := userinfo.Header.Get("Accept"); got != "application/json" {
		t.Errorf("Accept header = %q, want application/json", got)
	}
}

// Spec row 6: unknown claims beyond the common set are preserved.
func TestFetchUserInfo_UnknownClaimsPreserved(t *testing.T) {
	server, _ := userInfoServer(t, claimsHandler(map[string]any{
		"sub":              "user-123",
		"urn:custom:tier":  "gold",
		"nested_extension": map[string]any{"a": "b"},
	}))
	defer server.Close()

	user, err := FetchUserInfo(context.Background(), server.URL, testAccessToken)
	if err != nil {
		t.Fatalf("FetchUserInfo: %v", err)
	}

	want := map[string]any{
		"sub":              "user-123",
		"urn:custom:tier":  "gold",
		"nested_extension": map[string]any{"a": "b"},
	}
	if !reflect.DeepEqual(user.Claims, want) {
		t.Errorf("Claims = %v, want %v", user.Claims, want)
	}
}

func TestFetchUserInfo_PreDiscoveredMetadataSkipsDiscovery(t *testing.T) {
	server, requests := userInfoServer(t, claimsHandler(map[string]any{"sub": "user-123"}))
	defer server.Close()

	metadata := &AuthorizationServerMetadata{Issuer: server.URL, UserinfoEndpoint: server.URL + "/userinfo"}
	if _, err := FetchUserInfo(context.Background(), server.URL, testAccessToken, WithUserInfoMetadata(metadata)); err != nil {
		t.Fatalf("FetchUserInfo: %v", err)
	}

	if len(*requests) != 1 {
		t.Fatalf("expected only the UserInfo request, got %d requests", len(*requests))
	}
	if (*requests)[0].URL.Path != "/userinfo" {
		t.Errorf("request path = %q, want /userinfo", (*requests)[0].URL.Path)
	}
}

// Spec row 4: metadata without userinfo_endpoint fails before any HTTP request.
func TestFetchUserInfo_MissingEndpointFailsBeforeRequest(t *testing.T) {
	var called bool
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		called = true
	}))
	defer server.Close()

	metadata := &AuthorizationServerMetadata{Issuer: server.URL}
	_, err := FetchUserInfo(context.Background(), server.URL, testAccessToken,
		WithUserInfoMetadata(metadata),
		WithUserInfoHTTPClient(server.Client()),
	)

	var configErr *ConfigurationError
	if !errors.As(err, &configErr) {
		t.Fatalf("expected *ConfigurationError, got %v", err)
	}
	if !strings.Contains(configErr.Error(), "userinfo_endpoint") {
		t.Errorf("error should name userinfo_endpoint, got %q", configErr.Error())
	}
	if called {
		t.Error("no HTTP request may be made when the metadata has no userinfo_endpoint")
	}
}

// Spec row 2: response missing sub is a protocol error.
func TestFetchUserInfo_MissingSub(t *testing.T) {
	for _, tc := range []struct {
		name  string
		claim map[string]any
	}{
		{name: "absent", claim: map[string]any{"email": "kim@example.com"}},
		{name: "empty", claim: map[string]any{"sub": ""}},
		{name: "not a string", claim: map[string]any{"sub": 123}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, _ := userInfoServer(t, claimsHandler(tc.claim))
			defer server.Close()

			_, err := FetchUserInfo(context.Background(), server.URL, testAccessToken)

			var oauthErr *OAuthError
			if !errors.As(err, &oauthErr) {
				t.Fatalf("expected *OAuthError, got %v", err)
			}
			if oauthErr.ErrorCode != "invalid_response" {
				t.Errorf("ErrorCode = %q, want invalid_response", oauthErr.ErrorCode)
			}
			if !strings.Contains(oauthErr.Error(), "sub") {
				t.Errorf("error should name the sub claim, got %q", oauthErr.Error())
			}
		})
	}
}

// Spec row 3: a 401 challenge surfaces as a typed error carrying the challenge's code.
func TestFetchUserInfo_ChallengeErrors(t *testing.T) {
	tests := []struct {
		name      string
		challenge string
		assert    func(t *testing.T, err error)
	}{
		{
			name:      "invalid_token",
			challenge: `Bearer error="invalid_token", error_description="The access token expired"`,
			assert: func(t *testing.T, err error) {
				var target *InvalidTokenError
				if !errors.As(err, &target) {
					t.Fatalf("expected *InvalidTokenError, got %v", err)
				}
				if target.ErrorCode() != "invalid_token" {
					t.Errorf("ErrorCode() = %q", target.ErrorCode())
				}
			},
		},
		{
			name:      "no challenge header",
			challenge: "",
			assert: func(t *testing.T, err error) {
				var target *InvalidTokenError
				if !errors.As(err, &target) {
					t.Fatalf("expected *InvalidTokenError, got %v", err)
				}
			},
		},
		{
			name:      "unquoted code",
			challenge: "Bearer error=invalid_token",
			assert: func(t *testing.T, err error) {
				var target *InvalidTokenError
				if !errors.As(err, &target) {
					t.Fatalf("expected *InvalidTokenError, got %v", err)
				}
			},
		},
		{
			name:      "insufficient_scope",
			challenge: `Bearer error="insufficient_scope", scope="openid profile"`,
			assert: func(t *testing.T, err error) {
				var target *InsufficientScopeError
				if !errors.As(err, &target) {
					t.Fatalf("expected *InsufficientScopeError, got %v", err)
				}
				if !strings.Contains(target.Error(), "insufficient_scope") {
					t.Errorf("error should report the challenge code, got %q", target.Error())
				}
			},
		},
		{
			name:      "other code",
			challenge: `Bearer error="invalid_request"`,
			assert: func(t *testing.T, err error) {
				var target *OAuthError
				if !errors.As(err, &target) {
					t.Fatalf("expected *OAuthError, got %v", err)
				}
				if target.ErrorCode != "invalid_request" {
					t.Errorf("ErrorCode = %q, want invalid_request", target.ErrorCode)
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server, _ := userInfoServer(t, func(w http.ResponseWriter, _ *http.Request) {
				if tc.challenge != "" {
					w.Header().Set("WWW-Authenticate", tc.challenge)
				}
				w.WriteHeader(http.StatusUnauthorized)
			})
			defer server.Close()

			_, err := FetchUserInfo(context.Background(), server.URL, testAccessToken)
			tc.assert(t, err)
		})
	}
}

// Spec row 5: an application/jwt body is a protocol error naming the content type.
func TestFetchUserInfo_SignedResponseRejected(t *testing.T) {
	server, _ := userInfoServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/jwt")
		if _, err := w.Write([]byte("eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyLTEyMyJ9.sig")); err != nil {
			return
		}
	})
	defer server.Close()

	_, err := FetchUserInfo(context.Background(), server.URL, testAccessToken)

	var oauthErr *OAuthError
	if !errors.As(err, &oauthErr) {
		t.Fatalf("expected *OAuthError, got %v", err)
	}
	if oauthErr.ErrorCode != "invalid_response" {
		t.Errorf("ErrorCode = %q, want invalid_response", oauthErr.ErrorCode)
	}
	if !strings.Contains(oauthErr.Error(), "application/jwt") {
		t.Errorf("error should name the unsupported content type, got %q", oauthErr.Error())
	}
}

func TestFetchUserInfo_MalformedBodyPreservesCause(t *testing.T) {
	server, _ := userInfoServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write([]byte("not json {")); err != nil {
			return
		}
	})
	defer server.Close()

	_, err := FetchUserInfo(context.Background(), server.URL, testAccessToken)

	var oauthErr *OAuthError
	if !errors.As(err, &oauthErr) {
		t.Fatalf("expected *OAuthError, got %v", err)
	}
	var syntaxErr *json.SyntaxError
	if !errors.As(err, &syntaxErr) {
		t.Errorf("the decode cause must stay wrapped for errors.As, got %v", err)
	}
}

func TestFetchUserInfo_NonObjectBody(t *testing.T) {
	server, _ := userInfoServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write([]byte(`["user-123"]`)); err != nil {
			return
		}
	})
	defer server.Close()

	_, err := FetchUserInfo(context.Background(), server.URL, testAccessToken)

	var oauthErr *OAuthError
	if !errors.As(err, &oauthErr) {
		t.Fatalf("expected *OAuthError, got %v", err)
	}
	if oauthErr.ErrorCode != "invalid_response" {
		t.Errorf("ErrorCode = %q, want invalid_response", oauthErr.ErrorCode)
	}
}

func TestFetchUserInfo_OAuthErrorBody(t *testing.T) {
	server, _ := userInfoServer(t, claimsHandler(map[string]any{
		"error":             "invalid_request",
		"error_description": "the request is missing a parameter",
	}))
	defer server.Close()

	_, err := FetchUserInfo(context.Background(), server.URL, testAccessToken)

	var oauthErr *OAuthError
	if !errors.As(err, &oauthErr) {
		t.Fatalf("expected *OAuthError, got %v", err)
	}
	if oauthErr.ErrorCode != "invalid_request" {
		t.Errorf("ErrorCode = %q, want invalid_request", oauthErr.ErrorCode)
	}
}

func TestFetchUserInfo_NonAuthErrorStatus(t *testing.T) {
	server, _ := userInfoServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	defer server.Close()

	_, err := FetchUserInfo(context.Background(), server.URL, testAccessToken)

	var httpErr *HTTPError
	if !errors.As(err, &httpErr) {
		t.Fatalf("expected *HTTPError, got %v", err)
	}
	if httpErr.Status != http.StatusServiceUnavailable {
		t.Errorf("Status = %d, want 503", httpErr.Status)
	}
}

func TestFetchUserInfo_DiscoveryFailureIsWrapped(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if err := json.NewEncoder(w).Encode(map[string]string{"issuer": "https://attacker.example.com"}); err != nil {
			return
		}
	}))
	defer server.Close()

	_, err := FetchUserInfo(context.Background(), server.URL, testAccessToken)

	var discoveryErr *UserInfoDiscoveryError
	if !errors.As(err, &discoveryErr) {
		t.Fatalf("expected *UserInfoDiscoveryError, got %v", err)
	}
	var mismatch *IssuerMismatchError
	if !errors.As(err, &mismatch) {
		t.Errorf("the discovery cause must stay wrapped for errors.As, got %v", err)
	}
}

func TestFetchUserInfo_TransportFailureIsWrapped(t *testing.T) {
	metadata := &AuthorizationServerMetadata{
		Issuer:           "https://auth.example.com",
		UserinfoEndpoint: "https://127.0.0.1:1/userinfo",
	}

	_, err := FetchUserInfo(context.Background(), metadata.Issuer, testAccessToken, WithUserInfoMetadata(metadata))

	var fetchErr *UserInfoFetchError
	if !errors.As(err, &fetchErr) {
		t.Fatalf("expected *UserInfoFetchError, got %v", err)
	}
	if fetchErr.Unwrap() == nil {
		t.Error("the transport cause must stay wrapped")
	}
}

func TestFetchUserInfo_EmptyAccessToken(t *testing.T) {
	var configErr *ConfigurationError
	_, err := FetchUserInfo(context.Background(), "https://auth.example.com", "")
	if !errors.As(err, &configErr) {
		t.Fatalf("expected *ConfigurationError, got %v", err)
	}
}

// Spec row 7: userinfo_endpoint and end_session_endpoint are typed on the metadata.
func TestFetchAuthorizationServerMetadata_OIDCFields(t *testing.T) {
	var issuer string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if err := json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                issuer,
			"userinfo_endpoint":                     issuer + "/userinfo",
			"end_session_endpoint":                  issuer + "/logout",
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
			"claims_supported":                      []string{"sub", "email"},
			"code_challenge_methods_supported":      []string{"S256"},
		}); err != nil {
			t.Errorf("encoding discovery document: %v", err)
		}
	}))
	defer server.Close()
	issuer = server.URL

	md, err := FetchAuthorizationServerMetadata(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("FetchAuthorizationServerMetadata: %v", err)
	}

	if md.UserinfoEndpoint != issuer+"/userinfo" {
		t.Errorf("UserinfoEndpoint = %q", md.UserinfoEndpoint)
	}
	if md.EndSessionEndpoint != issuer+"/logout" {
		t.Errorf("EndSessionEndpoint = %q", md.EndSessionEndpoint)
	}
	if !reflect.DeepEqual(md.SubjectTypesSupported, []string{"public"}) {
		t.Errorf("SubjectTypesSupported = %v", md.SubjectTypesSupported)
	}
	if !reflect.DeepEqual(md.IDTokenSigningAlgValuesSupported, []string{"RS256"}) {
		t.Errorf("IDTokenSigningAlgValuesSupported = %v", md.IDTokenSigningAlgValuesSupported)
	}
	if !reflect.DeepEqual(md.ClaimsSupported, []string{"sub", "email"}) {
		t.Errorf("ClaimsSupported = %v", md.ClaimsSupported)
	}
	if !reflect.DeepEqual(md.CodeChallengeMethodsSupported, []string{"S256"}) {
		t.Errorf("CodeChallengeMethodsSupported = %v", md.CodeChallengeMethodsSupported)
	}
	if len(md.Extra) != 0 {
		t.Errorf("typed OIDC fields must not be duplicated into Extra, got %v", md.Extra)
	}
}

// Spec row 8: the OIDC fields are absent, not zero-rendered, when the server omits them.
func TestFetchAuthorizationServerMetadata_OIDCFieldsAbsent(t *testing.T) {
	var issuer string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if err := json.NewEncoder(w).Encode(map[string]any{"issuer": issuer}); err != nil {
			t.Errorf("encoding discovery document: %v", err)
		}
	}))
	defer server.Close()
	issuer = server.URL

	md, err := FetchAuthorizationServerMetadata(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("FetchAuthorizationServerMetadata: %v", err)
	}

	if md.UserinfoEndpoint != "" || md.EndSessionEndpoint != "" {
		t.Errorf("absent OIDC endpoints should stay empty, got %q and %q", md.UserinfoEndpoint, md.EndSessionEndpoint)
	}
	if md.SubjectTypesSupported != nil || md.ClaimsSupported != nil || md.IDTokenSigningAlgValuesSupported != nil {
		t.Error("absent OIDC lists should stay nil")
	}

	encoded, err := json.Marshal(md)
	if err != nil {
		t.Fatalf("marshaling metadata: %v", err)
	}
	for _, field := range []string{"userinfo_endpoint", "end_session_endpoint", "subject_types_supported", "claims_supported", "id_token_signing_alg_values_supported"} {
		if strings.Contains(string(encoded), field) {
			t.Errorf("absent field %q must not be rendered on re-encode: %s", field, encoded)
		}
	}
}
