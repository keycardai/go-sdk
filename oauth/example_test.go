package oauth_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"

	"github.com/keycardai/go-sdk/oauth"
)

func ExampleDiscoverCredential() {
	credential, err := oauth.DiscoverCredential(map[string]string{
		"KEYCARD_CLIENT_ID":     "my-client",
		"KEYCARD_CLIENT_SECRET": "example-secret",
	})
	if err != nil {
		panic(err)
	}
	fmt.Printf("%T\n", credential)
	// Output: *oauth.ClientSecretCredential
}

// ExampleGenerateCodeChallenge derives an S256 PKCE challenge from a verifier
// (RFC 7636 Appendix B vector).
func ExampleGenerateCodeChallenge() {
	challenge, err := oauth.GenerateCodeChallenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk", oauth.PKCEMethodS256)
	if err != nil {
		panic(err)
	}
	fmt.Println(challenge)
	// Output: E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
}

// ExampleBuildAuthorizeURL builds an authorization-code request URL with PKCE.
func ExampleBuildAuthorizeURL() {
	url, err := oauth.BuildAuthorizeURL("https://zone.keycard.cloud/authorize", oauth.AuthorizeURLParams{
		ClientID:      "my-client",
		RedirectURI:   "http://127.0.0.1:8765/callback",
		CodeChallenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		Scopes:        []string{"openid"},
		State:         "xyz",
	})
	if err != nil {
		panic(err)
	}
	fmt.Println(url)
	// Output: https://zone.keycard.cloud/authorize?client_id=my-client&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256&redirect_uri=http%3A%2F%2F127.0.0.1%3A8765%2Fcallback&response_type=code&scope=openid&state=xyz
}

func ExampleRevokeToken() {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	err := oauth.RevokeToken(context.Background(), "", oauth.RevokeTokenRequest{
		Token:    "refresh-token",
		ClientID: "public-client",
	}, oauth.WithRevocationMetadata(&oauth.AuthorizationServerMetadata{
		Issuer:             server.URL,
		RevocationEndpoint: server.URL + "/revoke",
	}), oauth.WithRevocationHTTPClient(server.Client()))
	if err != nil {
		panic(err)
	}
	fmt.Println("revoked")
	// Output: revoked
}

func ExampleIntrospectToken() {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"active":false}`)
	}))
	defer server.Close()

	credential, err := oauth.NewClientSecret("confidential-client", "example-secret")
	if err != nil {
		panic(err)
	}
	result, err := oauth.IntrospectToken(context.Background(), "", oauth.IntrospectTokenRequest{
		Token:      "example-token",
		Credential: credential,
	}, oauth.WithIntrospectionMetadata(&oauth.AuthorizationServerMetadata{
		Issuer:                server.URL,
		IntrospectionEndpoint: server.URL + "/introspect",
	}), oauth.WithIntrospectionHTTPClient(server.Client()))
	if err != nil {
		panic(err)
	}
	fmt.Println("active:", result.Active)
	// Output: active: false
}
