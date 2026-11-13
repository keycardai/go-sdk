package oauth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestRefreshAuthorization(t *testing.T) {
	tokenWithoutRefresh := tokenStep{status: http.StatusOK, body: map[string]any{
		"access_token": "access-2",
		"token_type":   "Bearer",
		"expires_in":   3600,
	}}
	rotated := &TokenResponse{
		AccessToken:  "access-1",
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		RefreshToken: "refresh-1",
		IDToken:      "header.claims.signature",
		Scope:        []string{"openid"},
	}
	clientSecret, err := NewClientSecret("confidential-1", "secret-1")
	if err != nil {
		t.Fatal(err)
	}

	cases := map[string]struct {
		req         RefreshAuthorizationRequest
		useMetadata bool
		step        tokenStep
		wantForm    url.Values
		wantHeader  http.Header
		// wantCredentialCall is true when the credential is asked for client
		// authentication for the token endpoint once.
		wantCredentialCall bool
		wantDiscovery      int32
		// Exactly one of the following describes the result.
		wantToken   *TokenResponse
		wantCode    string
		wantHTTP    int
		wantNetwork bool
	}{
		"public client with two resources": {
			req: RefreshAuthorizationRequest{
				RefreshToken: "refresh-0",
				ClientID:     "public-1",
				Resources:    []string{"https://api-1.example.com", "https://api-2.example.com"},
			},
			step: stepToken,
			wantForm: url.Values{
				"grant_type":    {"refresh_token"},
				"refresh_token": {"refresh-0"},
				"client_id":     {"public-1"},
				"resource":      {"https://api-1.example.com", "https://api-2.example.com"},
			},
			wantHeader:    formHeader,
			wantDiscovery: 1,
			wantToken:     rotated,
		},
		"public client with scopes": {
			req: RefreshAuthorizationRequest{
				RefreshToken: "refresh-0",
				ClientID:     "public-1",
				Scopes:       []string{"openid", "profile"},
			},
			step: tokenWithoutRefresh,
			wantForm: url.Values{
				"grant_type":    {"refresh_token"},
				"refresh_token": {"refresh-0"},
				"client_id":     {"public-1"},
				"scope":         {"openid profile"},
			},
			wantHeader:    formHeader,
			wantDiscovery: 1,
			wantToken:     &TokenResponse{AccessToken: "access-2", TokenType: "Bearer", ExpiresIn: 3600},
		},
		"confidential client authenticates with Basic and no body client_id": {
			req: RefreshAuthorizationRequest{
				RefreshToken: "refresh-0",
				ClientID:     "confidential-1",
				ClientSecret: "secret-1",
			},
			step: stepToken,
			wantForm: url.Values{
				"grant_type":    {"refresh_token"},
				"refresh_token": {"refresh-0"},
			},
			wantHeader:    withAuthorization(formHeader, "Basic "+basicCredentials("confidential-1", "secret-1")),
			wantDiscovery: 1,
			wantToken:     rotated,
		},
		"credential with one resource": {
			req: RefreshAuthorizationRequest{
				RefreshToken: "refresh-0",
				Credential:   &fakeAuthenticator{},
				Resources:    []string{"https://api-2.example.com"},
			},
			step: stepToken,
			wantForm: url.Values{
				"grant_type":            {"refresh_token"},
				"refresh_token":         {"refresh-0"},
				"resource":              {"https://api-2.example.com"},
				"client_assertion":      {"assertion-1"},
				"client_assertion_type": {clientAssertionTypeJWTBearer},
			},
			wantHeader:         withAuthorization(formHeader, "Basic Y2xpZW50OnNlY3JldA=="),
			wantCredentialCall: true,
			wantDiscovery:      1,
			wantToken:          rotated,
		},
		"client secret credential": {
			req: RefreshAuthorizationRequest{
				RefreshToken: "refresh-0",
				Credential:   clientSecret,
			},
			step: stepToken,
			wantForm: url.Values{
				"grant_type":    {"refresh_token"},
				"refresh_token": {"refresh-0"},
			},
			wantHeader:    withAuthorization(formHeader, "Basic "+basicCredentials("confidential-1", "secret-1")),
			wantDiscovery: 1,
			wantToken:     rotated,
		},
		"pre-discovered metadata makes no discovery request": {
			req:         RefreshAuthorizationRequest{RefreshToken: "refresh-0", ClientID: "public-1"},
			useMetadata: true,
			step:        stepToken,
			wantForm: url.Values{
				"grant_type":    {"refresh_token"},
				"refresh_token": {"refresh-0"},
				"client_id":     {"public-1"},
			},
			wantHeader:    formHeader,
			wantDiscovery: 0,
			wantToken:     rotated,
		},
		"invalid_grant": {
			req:  RefreshAuthorizationRequest{RefreshToken: "refresh-0", ClientID: "public-1"},
			step: stepOAuthError("invalid_grant"),
			wantForm: url.Values{
				"grant_type":    {"refresh_token"},
				"refresh_token": {"refresh-0"},
				"client_id":     {"public-1"},
			},
			wantHeader:    formHeader,
			wantDiscovery: 1,
			wantCode:      "invalid_grant",
		},
		"503 without an OAuth error": {
			req:  RefreshAuthorizationRequest{RefreshToken: "refresh-0", ClientID: "public-1"},
			step: stepStatus(http.StatusServiceUnavailable),
			wantForm: url.Values{
				"grant_type":    {"refresh_token"},
				"refresh_token": {"refresh-0"},
				"client_id":     {"public-1"},
			},
			wantHeader:    formHeader,
			wantDiscovery: 1,
			wantHTTP:      http.StatusServiceUnavailable,
		},
		"network error": {
			req:           RefreshAuthorizationRequest{RefreshToken: "refresh-0", ClientID: "public-1"},
			step:          stepNetwork,
			wantDiscovery: 1,
			wantNetwork:   true,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			zone := newFakeZone(t)
			zone.script(tc.step)
			opts := []RefreshOption{WithRefreshHTTPClient(zone.httpClient())}
			if tc.useMetadata {
				opts = append(opts, WithRefreshMetadata(zone.metadata()))
			}

			token, err := RefreshAuthorization(context.Background(), zone.URL, tc.req, opts...)

			switch {
			case tc.wantCode != "":
				wantOAuthError(t, err, tc.wantCode)
			case tc.wantHTTP != 0:
				wantHTTPError(t, err, tc.wantHTTP)
			case tc.wantNetwork:
				if !errors.Is(err, errNetwork) {
					t.Fatalf("error: got %v, want the transport error", err)
				}
			default:
				if err != nil {
					t.Fatalf("RefreshAuthorization: %v", err)
				}
				if !reflect.DeepEqual(token, tc.wantToken) {
					t.Errorf("token: got %+v, want %+v", token, tc.wantToken)
				}
			}

			calls := zone.tokenCalls()
			if len(calls) != 1 {
				t.Fatalf("token requests: got %d, want 1", len(calls))
			}
			if !tc.wantNetwork {
				if !reflect.DeepEqual(calls[0].form, tc.wantForm) {
					t.Errorf("form: got %v, want %v", calls[0].form, tc.wantForm)
				}
				if !reflect.DeepEqual(calls[0].header, tc.wantHeader) {
					t.Errorf("header: got %v, want %v", calls[0].header, tc.wantHeader)
				}
			}
			if got := zone.discoveryRequests.Load(); got != tc.wantDiscovery {
				t.Errorf("discovery requests: got %d, want %d", got, tc.wantDiscovery)
			}
			if fake, ok := tc.req.Credential.(*fakeAuthenticator); ok {
				var want [][2]string
				if tc.wantCredentialCall {
					want = [][2]string{{zone.URL, zone.URL + "/token"}}
				}
				if got := fake.recordedCalls(); !reflect.DeepEqual(got, want) {
					t.Errorf("credential calls: got %v, want %v", got, want)
				}
			}
		})
	}
}

// Each configuration error is returned before discovery or any other request.
func TestRefreshAuthorization_Configuration(t *testing.T) {
	public := RefreshAuthorizationRequest{RefreshToken: "refresh-0", ClientID: "public-1"}
	cases := map[string]struct {
		// issuer replaces the zone URL as the issuer argument when set. "-" means empty.
		issuer      string
		metadata    *AuthorizationServerMetadata
		req         RefreshAuthorizationRequest
		wantMessage string
	}{
		"credential and client id": {
			req:         RefreshAuthorizationRequest{RefreshToken: "refresh-0", Credential: &fakeAuthenticator{}, ClientID: "public-1"},
			wantMessage: "not both",
		},
		"credential and client secret": {
			req:         RefreshAuthorizationRequest{RefreshToken: "refresh-0", Credential: &fakeAuthenticator{}, ClientSecret: "secret-1"},
			wantMessage: "not both",
		},
		"credential without client authentication": {
			req:         RefreshAuthorizationRequest{RefreshToken: "refresh-0", Credential: noClientAuthentication{}},
			wantMessage: "does not provide client authentication",
		},
		"neither credential nor client id": {
			req:         RefreshAuthorizationRequest{RefreshToken: "refresh-0"},
			wantMessage: "requires a Credential or a ClientID",
		},
		"client secret without client id": {
			req:         RefreshAuthorizationRequest{RefreshToken: "refresh-0", ClientSecret: "secret-1"},
			wantMessage: "requires a Credential or a ClientID",
		},
		"no refresh token": {
			req:         RefreshAuthorizationRequest{ClientID: "public-1"},
			wantMessage: "requires a refresh token",
		},
		"no issuer and no metadata": {
			issuer:      "-",
			req:         public,
			wantMessage: "an issuer or metadata is required",
		},
		"metadata without an issuer": {
			issuer:      "-",
			metadata:    &AuthorizationServerMetadata{TokenEndpoint: "https://zone.example.com/token"},
			req:         public,
			wantMessage: "metadata has no issuer",
		},
		"issuer that does not match the metadata": {
			issuer:      "https://other.example.com",
			metadata:    &AuthorizationServerMetadata{Issuer: "https://zone.example.com", TokenEndpoint: "https://zone.example.com/token"},
			req:         public,
			wantMessage: "does not match the metadata issuer",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			zone := newFakeZone(t)
			issuer := zone.URL
			switch tc.issuer {
			case "":
			case "-":
				issuer = ""
			default:
				issuer = tc.issuer
			}
			opts := []RefreshOption{WithRefreshHTTPClient(zone.httpClient())}
			if tc.metadata != nil {
				opts = append(opts, WithRefreshMetadata(tc.metadata))
			}

			_, err := RefreshAuthorization(context.Background(), issuer, tc.req, opts...)

			var cfgErr *ConfigurationError
			if !errors.As(err, &cfgErr) {
				t.Fatalf("error: got %v (%T), want *ConfigurationError", err, err)
			}
			if !strings.Contains(cfgErr.Message, tc.wantMessage) {
				t.Errorf("message: got %q, want it to contain %q", cfgErr.Message, tc.wantMessage)
			}
			if got := zone.discoveryRequests.Load(); got != 0 {
				t.Errorf("discovery requests: got %d, want 0", got)
			}
			if got := len(zone.tokenCalls()); got != 0 {
				t.Errorf("token requests: got %d, want 0", got)
			}
			if fake, ok := tc.req.Credential.(*fakeAuthenticator); ok {
				if got := fake.recordedCalls(); len(got) != 0 {
					t.Errorf("credential calls: got %v, want none", got)
				}
			}
		})
	}
}

// A token endpoint that discovery cannot find is a *TokenEndpointDiscoveryError. The
// refresh request is not sent.
func TestRefreshAuthorization_NoTokenEndpoint(t *testing.T) {
	failing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	t.Cleanup(failing.Close)

	cases := map[string]struct {
		issuer string
		opts   []RefreshOption
		// wantStatus is the status of the *HTTPError cause, or 0 for no cause.
		wantStatus int
	}{
		"discovery fails": {
			issuer:     failing.URL,
			wantStatus: http.StatusServiceUnavailable,
		},
		"metadata without token_endpoint": {
			issuer: "https://zone.example.com",
			opts:   []RefreshOption{WithRefreshMetadata(&AuthorizationServerMetadata{Issuer: "https://zone.example.com"})},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := RefreshAuthorization(context.Background(), tc.issuer,
				RefreshAuthorizationRequest{RefreshToken: "refresh-0", ClientID: "public-1"}, tc.opts...)

			var discErr *TokenEndpointDiscoveryError
			if !errors.As(err, &discErr) {
				t.Fatalf("error: got %v (%T), want *TokenEndpointDiscoveryError", err, err)
			}
			var httpErr *HTTPError
			switch {
			case tc.wantStatus == 0 && discErr.Err != nil:
				t.Errorf("cause: got %v, want none", discErr.Err)
			case tc.wantStatus != 0 && !errors.As(err, &httpErr):
				t.Errorf("cause: got %v, want *HTTPError %d", discErr.Err, tc.wantStatus)
			case tc.wantStatus != 0 && httpErr.Status != tc.wantStatus:
				t.Errorf("status: got %d, want %d", httpErr.Status, tc.wantStatus)
			}
		})
	}
}

// The default timeout applies only when the caller's context has no deadline. A later
// caller deadline wins.
func TestRefreshAuthorization_CallerDeadlineWins(t *testing.T) {
	zone := newFakeZone(t)
	zone.delay = 100 * time.Millisecond
	zone.script(stepToken)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := RefreshAuthorization(ctx, zone.URL,
		RefreshAuthorizationRequest{RefreshToken: "refresh-0", ClientID: "public-1"},
		WithRefreshHTTPClient(zone.httpClient()),
		WithRefreshMetadata(zone.metadata()),
		WithRefreshRequestTimeout(20*time.Millisecond))

	if err != nil {
		t.Fatalf("RefreshAuthorization: %v, want the token", err)
	}
}
