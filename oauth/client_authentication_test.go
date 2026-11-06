package oauth

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"reflect"
	"testing"
)

func TestClientAuthentication(t *testing.T) {
	const (
		issuer   = "https://zone-a.example.com"
		endpoint = "https://zone-a.example.com/oauth2/device/authorize"
	)
	basic := func(id, secret string) http.Header {
		return http.Header{"Authorization": {"Basic " + base64.StdEncoding.EncodeToString([]byte(id+":"+secret))}}
	}
	mustClientSecret := func(t *testing.T) ClientAuthenticator {
		c, err := NewClientSecret("id-a", "secret-a")
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	mustMultiZone := func(t *testing.T) ClientAuthenticator {
		c, err := NewMultiZoneClientSecret(map[string]ClientAuth{
			issuer:                       {ClientID: "id-a", ClientSecret: "secret-a"},
			"https://zone-b.example.com": {ClientID: "id-b", ClientSecret: "secret-b"},
		})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	mustWorkload := func(token string, opts ...WorkloadIdentityOption) func(t *testing.T) ClientAuthenticator {
		return func(t *testing.T) ClientAuthenticator {
			c, err := NewWorkloadIdentity(IdentityTokenFunc(func(context.Context) (string, error) { return token, nil }), opts...)
			if err != nil {
				t.Fatal(err)
			}
			return c
		}
	}
	// checkAssertion verifies the form fields of a WebIdentity client assertion. The
	// assertion is newly signed, so its value cannot be compared literally.
	checkAssertion := func(t *testing.T, form url.Values) {
		t.Helper()
		if got := form["client_assertion_type"]; !reflect.DeepEqual(got, []string{clientAssertionTypeJWTBearer}) {
			t.Errorf("client_assertion_type: got %v", got)
		}
		if len(form["client_assertion"]) != 1 {
			t.Fatalf("client_assertion: got %v, want one value", form["client_assertion"])
		}
		claims := assertionClaims(t, form.Get("client_assertion"))
		if claims["iss"] != "client-a" || claims["sub"] != "client-a" {
			t.Errorf("iss/sub: got %v/%v, want client-a", claims["iss"], claims["sub"])
		}
		if claims["aud"] != endpoint {
			t.Errorf("aud: got %v, want %q", claims["aud"], endpoint)
		}
		if jti, _ := claims["jti"].(string); jti == "" {
			t.Error("jti is empty")
		}
		iat, _ := claims["iat"].(float64)
		exp, _ := claims["exp"].(float64)
		if exp-iat != 300 {
			t.Errorf("exp - iat: got %v, want 300", exp-iat)
		}
		if len(form) != 2 {
			t.Errorf("form: got %v, want only client_assertion and client_assertion_type", form)
		}
	}

	cases := map[string]struct {
		cred       func(t *testing.T) ClientAuthenticator
		issuer     string
		wantHeader http.Header
		wantForm   url.Values
		checkForm  func(t *testing.T, form url.Values)
		wantErr    any
	}{
		"client secret": {
			cred:       mustClientSecret,
			issuer:     issuer,
			wantHeader: basic("id-a", "secret-a"),
			wantForm:   url.Values{},
		},
		"multi-zone client secret, configured zone": {
			cred:       mustMultiZone,
			issuer:     "https://zone-b.example.com",
			wantHeader: basic("id-b", "secret-b"),
			wantForm:   url.Values{},
		},
		"multi-zone client secret, unknown zone fails closed": {
			cred:    mustMultiZone,
			issuer:  "https://zone-c.example.com",
			wantErr: new(*ClientSecretConfigurationError),
		},
		"web identity": {
			cred: func(t *testing.T) ClientAuthenticator {
				return NewWebIdentity(WithClientID("client-a"), WithStorageDir(t.TempDir()))
			},
			issuer:     issuer,
			wantHeader: http.Header{},
			checkForm:  checkAssertion,
		},
		"web identity ignores the audience override": {
			cred: func(t *testing.T) ClientAuthenticator {
				return NewWebIdentity(WithClientID("client-a"), WithAudienceConfig("https://other.example.com"), WithStorageDir(t.TempDir()))
			},
			issuer:     issuer,
			wantHeader: http.Header{},
			checkForm:  checkAssertion,
		},
		"web identity without a client id": {
			cred: func(t *testing.T) ClientAuthenticator {
				return NewWebIdentity(WithStorageDir(t.TempDir()))
			},
			issuer:  issuer,
			wantErr: new(*WebIdentityConfigurationError),
		},
		"workload identity with client id": {
			cred:       mustWorkload("platform.jwt.token", WithWorkloadClientID("app-cred-1")),
			issuer:     issuer,
			wantHeader: http.Header{},
			wantForm: url.Values{
				"client_assertion":      {"platform.jwt.token"},
				"client_assertion_type": {clientAssertionTypeJWTBearer},
				"client_id":             {"app-cred-1"},
			},
		},
		"workload identity without client id": {
			cred:       mustWorkload("platform.jwt.token"),
			issuer:     issuer,
			wantHeader: http.Header{},
			wantForm: url.Values{
				"client_assertion":      {"platform.jwt.token"},
				"client_assertion_type": {clientAssertionTypeJWTBearer},
			},
		},
		"workload identity sends a non-JWT token unchanged": {
			cred:       mustWorkload("opaque-token"),
			issuer:     issuer,
			wantHeader: http.Header{},
			wantForm: url.Values{
				"client_assertion":      {"opaque-token"},
				"client_assertion_type": {clientAssertionTypeJWTBearer},
			},
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := tc.cred(t).ClientAuthentication(context.Background(), tc.issuer, endpoint)
			if tc.wantErr != nil {
				if !errors.As(err, tc.wantErr) {
					t.Fatalf("error: got %v, want %T", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ClientAuthentication: %v", err)
			}
			if !reflect.DeepEqual(got.Header, tc.wantHeader) {
				t.Errorf("header: got %v, want %v", got.Header, tc.wantHeader)
			}
			if tc.checkForm != nil {
				tc.checkForm(t, got.Form)
			} else if !reflect.DeepEqual(got.Form, tc.wantForm) {
				t.Errorf("form: got %v, want %v", got.Form, tc.wantForm)
			}
		})
	}
}
