package oauth

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
)

const clientAssertionTypeJWTBearer = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

// ClientAuthentication is the part of a request that authenticates the client to the
// authorization server: headers and form fields to add to the request. It never
// includes a grant parameter such as grant_type or subject_token_type.
type ClientAuthentication struct {
	Header http.Header
	Form   url.Values
}

// ClientAuthenticator is implemented by credentials that authenticate requests to the
// authorization server other than token exchange, such as the device authorization
// grant. It is separate from [ApplicationCredential], so a credential implemented
// outside this package does not have to provide it. Operations that need it check for
// it with a type assertion. [ClientSecretCredential], [WebIdentityCredential], and
// [WorkloadIdentityCredential] implement it.
type ClientAuthenticator interface {
	// ClientAuthentication returns the headers and form fields that authenticate the
	// client to the zone identified by issuer, for a request sent to endpoint.
	ClientAuthentication(ctx context.Context, issuer, endpoint string) (*ClientAuthentication, error)
}

// clientAuthenticator returns cred as a ClientAuthenticator, or a ConfigurationError
// when cred does not implement it.
func clientAuthenticator(cred ApplicationCredential) (ClientAuthenticator, error) {
	ca, ok := cred.(ClientAuthenticator)
	if !ok {
		return nil, &ConfigurationError{Message: fmt.Sprintf("credential %T does not provide client authentication", cred)}
	}
	return ca, nil
}

// addClientAuthentication adds the headers and form fields from ca for a request to
// endpoint.
func addClientAuthentication(ctx context.Context, ca ClientAuthenticator, issuer, endpoint string, header http.Header, form url.Values) error {
	auth, err := ca.ClientAuthentication(ctx, issuer, endpoint)
	if err != nil {
		return fmt.Errorf("client authentication: %w", err)
	}
	for k, vs := range auth.Form {
		for _, v := range vs {
			form.Add(k, v)
		}
	}
	for k, vs := range auth.Header {
		for _, v := range vs {
			header.Add(k, v)
		}
	}
	return nil
}

var (
	_ ClientAuthenticator = (*ClientSecretCredential)(nil)
	_ ClientAuthenticator = (*WebIdentityCredential)(nil)
	_ ClientAuthenticator = (*WorkloadIdentityCredential)(nil)
)

// ClientAuthentication returns an HTTP Basic Authorization header and no form fields.
// A multi-zone credential returns a ClientSecretConfigurationError for an issuer it
// has no credentials for.
func (c *ClientSecretCredential) ClientAuthentication(_ context.Context, issuer, _ string) (*ClientAuthentication, error) {
	auth := c.Auth(issuer)
	if auth == nil {
		return nil, &ClientSecretConfigurationError{Message: fmt.Sprintf("no client credentials configured for zone %q", issuer)}
	}
	h := http.Header{}
	h.Set("Authorization", "Basic "+basicCredentials(auth.ClientID, auth.ClientSecret))
	return &ClientAuthentication{Header: h, Form: url.Values{}}, nil
}

// basicCredentials returns the base64 user-pass value of an HTTP Basic Authorization
// header, as http.Request.SetBasicAuth builds it.
func basicCredentials(clientID, clientSecret string) string {
	return base64.StdEncoding.EncodeToString([]byte(clientID + ":" + clientSecret))
}

// ClientAuthentication returns a newly signed client_assertion and its
// client_assertion_type. The assertion's aud is endpoint, because a Keycard zone
// rejects an assertion whose aud is not the URL of the endpoint it is sent to.
// WithAudienceConfig does not apply. The assertion's iss and sub are the client id
// set with WithClientID; a credential without one returns a
// WebIdentityConfigurationError.
func (w *WebIdentityCredential) ClientAuthentication(ctx context.Context, _, endpoint string) (*ClientAuthentication, error) {
	if w.clientID == "" {
		return nil, &WebIdentityConfigurationError{Message: "client id is required for the assertion: set WithClientID"}
	}
	if endpoint == "" {
		return nil, &WebIdentityConfigurationError{Message: "endpoint is required for the assertion audience"}
	}
	if err := w.Bootstrap(); err != nil {
		return nil, fmt.Errorf("bootstrapping identity: %w", err)
	}
	assertion, err := w.keyManager.CreateClientAssertion(ctx, w.clientID, endpoint)
	if err != nil {
		return nil, fmt.Errorf("creating client assertion: %w", err)
	}
	form := url.Values{}
	form.Set("client_assertion", assertion)
	form.Set("client_assertion_type", clientAssertionTypeJWTBearer)
	return &ClientAuthentication{Header: http.Header{}, Form: form}, nil
}

// ClientAuthentication fetches the current token from the source and returns it as
// client_assertion, with client_assertion_type and, when configured, client_id. Source
// errors are returned as for PrepareTokenExchangeRequest.
func (w *WorkloadIdentityCredential) ClientAuthentication(ctx context.Context, _, _ string) (*ClientAuthentication, error) {
	assertion, err := w.identityToken(ctx)
	if err != nil {
		return nil, err
	}
	form := url.Values{}
	form.Set("client_assertion", assertion)
	form.Set("client_assertion_type", clientAssertionTypeJWTBearer)
	if w.clientID != "" {
		form.Set("client_id", w.clientID)
	}
	return &ClientAuthentication{Header: http.Header{}, Form: form}, nil
}
