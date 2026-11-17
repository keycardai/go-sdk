package oauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"testing"

	"github.com/golang-jwt/jwt/v5"
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
	// assertion is newly signed, so the test checks its signature and claims instead of
	// comparing it literally.
	checkAssertion := func(t *testing.T, cred ClientAuthenticator, form url.Values) {
		t.Helper()
		if got := form["client_assertion_type"]; !reflect.DeepEqual(got, []string{clientAssertionTypeJWTBearer}) {
			t.Errorf("client_assertion_type: got %v", got)
		}
		if len(form["client_assertion"]) != 1 {
			t.Fatalf("client_assertion: got %v, want one value", form["client_assertion"])
		}
		verifyAssertionSignature(t, cred.(*WebIdentityCredential), form.Get("client_assertion"))
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
		checkForm  func(t *testing.T, cred ClientAuthenticator, form url.Values)
		// wantErr is a pointer to the expected error type, and wantMessage the
		// error's exact text.
		wantErr     any
		wantMessage string
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
			cred:        mustMultiZone,
			issuer:      "https://zone-c.example.com",
			wantErr:     new(*ClientSecretConfigurationError),
			wantMessage: `no client credentials configured for zone "https://zone-c.example.com"`,
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
			issuer:      issuer,
			wantErr:     new(*WebIdentityConfigurationError),
			wantMessage: "client id is required for the assertion: set WithClientID",
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
		"workload identity wraps a custom source error": {
			cred: func(t *testing.T) ClientAuthenticator {
				c, err := NewWorkloadIdentity(IdentityTokenFunc(func(context.Context) (string, error) {
					return "", errors.New("platform token unavailable")
				}))
				if err != nil {
					t.Fatal(err)
				}
				return c
			},
			issuer:      issuer,
			wantErr:     new(*WorkloadIdentityRuntimeError),
			wantMessage: "fetching identity token: platform token unavailable",
		},
		"workload identity rejects an empty token": {
			cred:        mustWorkload("  "),
			issuer:      issuer,
			wantErr:     new(*WorkloadIdentityRuntimeError),
			wantMessage: "identity token source returned an empty token",
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
			cred := tc.cred(t)
			got, err := cred.ClientAuthentication(context.Background(), tc.issuer, endpoint)
			if tc.wantErr != nil {
				if !errors.As(err, tc.wantErr) {
					t.Fatalf("error: got %v, want %T", err, tc.wantErr)
				}
				if err.Error() != tc.wantMessage {
					t.Errorf("message: got %q, want %q", err.Error(), tc.wantMessage)
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
				tc.checkForm(t, cred, got.Form)
			} else if !reflect.DeepEqual(got.Form, tc.wantForm) {
				t.Errorf("form: got %v, want %v", got.Form, tc.wantForm)
			}
		})
	}
}

// verifyAssertionSignature checks that assertion is an RS256 JWT whose kid names the
// credential's public key, and that the key verifies its signature.
func verifyAssertionSignature(t *testing.T, cred *WebIdentityCredential, assertion string) {
	t.Helper()
	raw, err := json.Marshal(cred.PublicJWKS())
	if err != nil {
		t.Fatalf("marshaling public JWKS: %v", err)
	}
	var jwks struct {
		Keys []jwkJSON `json:"keys"`
	}
	if err := json.Unmarshal(raw, &jwks); err != nil || len(jwks.Keys) != 1 {
		t.Fatalf("public JWKS: got %s, want one key", raw)
	}
	key, err := importJWK(&jwks.Keys[0])
	if err != nil {
		t.Fatalf("importing public key: %v", err)
	}
	_, err = jwt.Parse(assertion, func(tok *jwt.Token) (any, error) {
		if kid := tok.Header["kid"]; kid != jwks.Keys[0].KID {
			return nil, fmt.Errorf("kid %v, want %q", kid, jwks.Keys[0].KID)
		}
		return key, nil
	}, jwt.WithValidMethods([]string{"RS256"}))
	if err != nil {
		t.Errorf("assertion does not verify with the credential's public key: %v", err)
	}
}

// Spec WebIdentity row 8: without a client id, client authentication fails before
// the credential creates or loads a key.
func TestWebIdentityClientAuthentication_NoClientIDCreatesNoKey(t *testing.T) {
	dir := t.TempDir()
	cred := NewWebIdentity(WithStorageDir(dir))

	_, err := cred.ClientAuthentication(context.Background(), "https://zone-a.example.com", "https://zone-a.example.com/token")

	var cfgErr *WebIdentityConfigurationError
	if !errors.As(err, &cfgErr) {
		t.Fatalf("error: got %v (%T), want *WebIdentityConfigurationError", err, err)
	}
	if want := "client id is required for the assertion: set WithClientID"; err.Error() != want {
		t.Errorf("message: got %q, want %q", err.Error(), want)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading storage dir: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("storage dir: got %d entries, want none", len(entries))
	}
	if cred.PublicJWKS() != nil {
		t.Errorf("public JWKS: got %v, want nil before bootstrap", cred.PublicJWKS())
	}
}
