package oauth_test

import (
	"fmt"

	"github.com/keycardai/go-sdk/oauth"
)

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
