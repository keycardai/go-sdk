package oauth

import "net/http"

// ResourceTransport is an http.RoundTripper that authorizes every request with
// a token from Source for Resource and Scopes, setting
// "Authorization: Bearer <token>" and replacing any existing value.
//
// It is bound to one resource and never derives one from the request URL: the
// resource indicator is the caller's choice, and reconstructing it from a URL
// would be a second opinion about which resource was approved. A client that
// calls several resources uses one transport per resource.
//
// It adds no timeout: obtaining the token can wait on a human approving a
// prompt. An error from Source is returned as is, so the Is* predicates apply
// to it, and the request is not sent.
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
// request with its context. It returns a *ConfigurationError when source is nil
// or resource is empty.
func NewResourceClient(source ResourceTokenSource, resource string, scopes ...string) (*http.Client, error) {
	t, err := NewResourceTransport(source, resource, scopes...)
	if err != nil {
		return nil, err
	}
	return &http.Client{Transport: t}, nil
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
