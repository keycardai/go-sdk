package oauth

import (
	"fmt"
	"net/http"
	"strings"
)

// ResourceTransport is an http.RoundTripper that authorizes every request with
// a token from Source for Resource and Scopes, setting
// "Authorization: Bearer <token>" and replacing any existing value.
//
// It is bound to one resource and never derives one from the request URL: the
// resource indicator is the caller's choice, and reconstructing it from a URL
// would be a second opinion about which resource was approved. A client that
// calls several resources uses one transport per resource.
//
// It authorizes whatever request it is given, whatever its host. An
// http.Client strips Authorization from a cross-origin redirect only when the
// caller set the header, not a transport, so a client that installs this
// transport directly sends the token to every redirect target. Install it
// through [NewResourceClient], which refuses such redirects, or give the
// client an equivalent CheckRedirect.
//
// It adds no timeout: obtaining the token can wait on a human approving a
// prompt. An error from Source is returned as is, so the Is* predicates apply
// to it, and the request is not sent. Nor is it when Source returns neither an
// error nor a token with an AccessToken.
type ResourceTransport struct {
	// Source mints the token. Required.
	Source ResourceTokenSource
	// Resource is the RFC 8707 resource indicator every request is authorized
	// against. Required.
	Resource string
	// Scopes are requested alongside Resource.
	Scopes []string
	// Base sends the authorized request. nil uses http.DefaultTransport.
	Base http.RoundTripper
}

// NewResourceTransport returns a ResourceTransport over http.DefaultTransport.
// It returns a *ConfigurationError when source is nil or resource is empty.
func NewResourceTransport(source ResourceTokenSource, resource string, scopes ...string) (*ResourceTransport, error) {
	t := &ResourceTransport{Source: source, Resource: resource, Scopes: scopes}
	if err := t.validate(); err != nil {
		return nil, err
	}
	return t, nil
}

// NewResourceClient returns an http.Client with a ResourceTransport installed
// and no timeout, since obtaining the token can wait on a human; bound each
// request with its context. It follows a redirect only to the origin (scheme,
// host and port) of the request that started the chain, and fails any other
// before it is sent, since the transport would authorize it. It returns a
// *ConfigurationError when source is nil or resource is empty.
func NewResourceClient(source ResourceTokenSource, resource string, scopes ...string) (*http.Client, error) {
	t, err := NewResourceTransport(source, resource, scopes...)
	if err != nil {
		return nil, err
	}
	return &http.Client{Transport: t, CheckRedirect: sameOriginRedirect}, nil
}

// maxResourceRedirects keeps http.Client's default limit, which setting
// CheckRedirect replaces.
const maxResourceRedirects = 10

func sameOriginRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= maxResourceRedirects {
		return fmt.Errorf("stopped after %d redirects", maxResourceRedirects)
	}
	first := via[0].URL
	if !strings.EqualFold(req.URL.Scheme, first.Scheme) || !strings.EqualFold(req.URL.Host, first.Host) {
		return fmt.Errorf("refusing redirect from %s://%s to %s://%s: ResourceTransport would send the token to a different origin",
			first.Scheme, first.Host, req.URL.Scheme, req.URL.Host)
	}
	return nil
}

// RoundTrip implements http.RoundTripper. It sets the header on a clone, since
// a RoundTripper must not modify the request it is given.
func (t *ResourceTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := t.validate(); err != nil {
		closeRequestBody(req)
		return nil, err
	}

	tok, err := t.Source.ResourceToken(req.Context(), t.Resource, t.Scopes...)
	if err != nil {
		closeRequestBody(req)
		return nil, err
	}
	if tok == nil || tok.AccessToken == "" {
		closeRequestBody(req)
		return nil, fmt.Errorf("ResourceTransport: %T returned no token and no error", t.Source)
	}

	authorized := req.Clone(req.Context())
	authorized.Header.Set("Authorization", "Bearer "+tok.AccessToken)

	base := t.Base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(authorized)
}

func (t *ResourceTransport) validate() error {
	if t.Source == nil {
		return &ConfigurationError{Message: "ResourceTransport requires a Source"}
	}
	if t.Resource == "" {
		return &ConfigurationError{Message: "ResourceTransport requires a Resource"}
	}
	return nil
}

// closeRequestBody honors the RoundTripper contract that RoundTrip closes the
// request body, including on errors, when it returns before sending.
func closeRequestBody(req *http.Request) {
	if req.Body != nil {
		_ = req.Body.Close()
	}
}
