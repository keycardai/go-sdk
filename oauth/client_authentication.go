package oauth

import (
	"context"
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

// Credentials that authenticate requests to the authorization server other than
// token exchange implement ClientAuthenticator. It is separate from
// [ApplicationCredential], so a credential implemented outside this package does not
// have to provide it. Operations that need it check for it with a type assertion, and
// return a ConfigurationError before sending a request when it is missing.
type ClientAuthenticator interface {
	// ClientAuthentication returns the headers and form fields that authenticate the
	// client to the zone identified by issuer, for a request sent to endpoint. Call it
	// once per request.
	ClientAuthentication(ctx context.Context, issuer, endpoint string) (*ClientAuthentication, error)
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
	setBasicAuth(h, auth.ClientID, auth.ClientSecret)
	return &ClientAuthentication{Header: h, Form: url.Values{}}, nil
}

// ClientAuthentication returns a newly signed client_assertion and its
// client_assertion_type. The assertion's aud is endpoint, because a Keycard zone
// rejects an assertion whose aud is not the URL of the endpoint it is sent to.
// WithAudienceConfig does not apply. The assertion's iss and sub are the client id
// set with WithClientID. A credential without one returns a
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
// client_assertion, with client_assertion_type and, when configured, client_id.
// Built-in sources fail with WorkloadIdentityConfigurationError or
// WorkloadIdentityRuntimeError. Any other source error is wrapped in a
// WorkloadIdentityRuntimeError with Source "custom".
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

// clientAuthenticator returns cred as a ClientAuthenticator, or a ConfigurationError
// when cred does not implement it.
func clientAuthenticator(cred ApplicationCredential) (ClientAuthenticator, error) {
	ca, ok := cred.(ClientAuthenticator)
	if !ok {
		return nil, &ConfigurationError{Message: fmt.Sprintf("credential %T does not provide client authentication", cred)}
	}
	return ca, nil
}

// addClientAuthentication gets the client authentication from the client
// authenticator and adds its headers and form fields to header and form.
// endpoint must be the URL the request is sent to.
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
