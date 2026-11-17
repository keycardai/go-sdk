package oauth

import (
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
)

// setBasicAuth sets the HTTP Basic Authorization header that authenticates a client
// with its ID and secret.
func setBasicAuth(h http.Header, clientID, clientSecret string) {
	h.Set("Authorization", "Basic "+basicCredentials(clientID, clientSecret))
}

// basicCredentials returns the base64 user-pass value of an HTTP Basic Authorization
// header for a client. RFC 6749 section 2.3.1 requires the client ID and the secret
// to be encoded before they go into the header.
func basicCredentials(clientID, clientSecret string) string {
	return base64.StdEncoding.EncodeToString([]byte(basicEncode(clientID) + ":" + basicEncode(clientSecret)))
}

// basicEncode percent-encodes s for one half of a Basic credential. A space becomes
// %20, never +. Keycard zones percent-decode each half and keep + as is. Servers that
// form-decode read %20 as a space too.
func basicEncode(s string) string {
	return strings.ReplaceAll(url.QueryEscape(s), "+", "%20")
}
