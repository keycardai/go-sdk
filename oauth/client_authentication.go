package oauth

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/keycardai/go-sdk/internal/printed"
)

const clientAssertionTypeJWTBearer = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

// ClientAuthentication is the part of a request that authenticates the client to the
// authorization server: headers and form fields to add to the request. It never
// includes a grant parameter such as grant_type or subject_token_type.
//
// Header and Form hold the client secret or a client assertion. String, GoString,
// and LogValue show the header and form field names, never their values.
type ClientAuthentication struct {
	Header http.Header
	Form   url.Values
}

func (a ClientAuthentication) printed() printed.Struct {
	return printed.Struct{Type: "oauth.ClientAuthentication", Fields: []printed.Field{
		{Name: "Header", Key: "header", Value: printed.Keys(a.Header)},
		{Name: "Form", Key: "form", Value: printed.Keys(a.Form)},
	}}
}

// String implements [fmt.Stringer].
func (a ClientAuthentication) String() string { return a.printed().String() }

// GoString implements [fmt.GoStringer].
func (a ClientAuthentication) GoString() string { return a.printed().GoString() }

// LogValue implements [slog.LogValuer].
func (a ClientAuthentication) LogValue() slog.Value { return a.printed().LogValue() }

// Credentials that authenticate requests to the authorization server other than
// token exchange implement ClientAuthenticator. It is separate from
// [ApplicationCredential], so a credential implemented outside this package does not
// have to provide it. Operations that need it check for it with a type assertion, and
// return a ConfigurationError before sending a request when it is missing. A
// credential that also has a CheckClientAuthentication() error method is checked
// with it before any request, such as WorkloadIdentityCredential without a client id.
type ClientAuthenticator interface {
	// ClientAuthentication returns the headers and form fields that authenticate the
	// client to the zone identified by issuer. The endpoint is the request URL,
	// except for revocation and introspection, which pass the issuer from metadata
	// as the assertion audience.
	// Call it once per request. When the error is nil, the result must not be nil.
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
// client_assertion_type. The assertion's aud is endpoint: the request URL for
// token requests and the metadata issuer for revocation and introspection.
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
	assertion, err := fetchIdentityToken(ctx, w.source)
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

// CheckClientAuthentication returns a ConfigurationError when no client id is set
// with WithWorkloadClientID. The interactive grants (authorization code, refresh,
// device authorization) need a v2 token credential, which the zone resolves by
// client_id, so they call it before sending any request.
func (w *WorkloadIdentityCredential) CheckClientAuthentication() error {
	if w.clientID == "" {
		return &ConfigurationError{Message: "workload identity: client id is required for interactive grants (the public ID of a v2 token credential): set WithWorkloadClientID"}
	}
	return nil
}

// clientAuthenticationChecker is implemented by a ClientAuthenticator that can tell,
// before any request, that it cannot authenticate the client.
type clientAuthenticationChecker interface {
	CheckClientAuthentication() error
}

// clientAuthenticator returns cred as a ClientAuthenticator, or a ConfigurationError
// when cred does not implement it. When cred also has a CheckClientAuthentication
// method, it returns that method's error. Callers run it before any request.
func clientAuthenticator(cred ApplicationCredential) (ClientAuthenticator, error) {
	ca, ok := cred.(ClientAuthenticator)
	if !ok {
		return nil, &ConfigurationError{Message: fmt.Sprintf("credential %T does not provide client authentication", cred)}
	}
	if checker, ok := cred.(clientAuthenticationChecker); ok {
		if err := checker.CheckClientAuthentication(); err != nil {
			return nil, err
		}
	}
	return ca, nil
}

// addClientAuthentication gets the client authentication from the client
// authenticator and sets its headers and form fields in header and form. A field
// it sets replaces the values already there, so the request does not send it
// twice. It returns an error from the client authenticator as is.
func addClientAuthentication(ctx context.Context, ca ClientAuthenticator, issuer, endpoint string, header http.Header, form url.Values) error {
	auth, err := ca.ClientAuthentication(ctx, issuer, endpoint)
	if err != nil {
		return err
	}
	if auth == nil {
		return fmt.Errorf("client authentication: %T returned no result and no error", ca)
	}
	for k, vs := range auth.Form {
		form.Del(k)
		for _, v := range vs {
			form.Add(k, v)
		}
	}
	for k, vs := range auth.Header {
		header.Del(k)
		for _, v := range vs {
			header.Add(k, v)
		}
	}
	return nil
}
