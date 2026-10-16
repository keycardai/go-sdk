package oauth

import (
	"net/http"
)

// ResourceTransport attaches a resource token to every request it carries.
//
// It is bound to one resource rather than deriving one from each request URL.
// That looks like a convenience worth having and is not: the resource
// indicator the authorization server resolves is a value the caller chose, and
// reconstructing it from a URL would mean inventing a normalization — which
// scheme, which trailing slash, what to do with a path — that the server has
// no obligation to agree with. Two opinions about which resource is being
// requested is the failure this avoids by not having a second one.
//
// A client that talks to several resources uses one transport per resource.
type ResourceTransport struct {
	// Source mints the token. Required.
	Source ResourceTokenSource
	// Resource is the RFC 8707 resource indicator every request is authorized
	// against. Required.
	Resource string
	// Scopes is requested alongside the resource. A change here is a different
	// grant and may require a fresh human approval.
	Scopes []string
	// Base is the underlying transport. nil uses http.DefaultTransport.
	Base http.RoundTripper
}

// NewResourceClient returns an http.Client that authorizes every request
// against resource.
//
// The client carries no timeout: obtaining the token can block on a human
// answering an approval prompt, and a timeout short enough for the request is
// too short for the person. Bound the work with a context instead.
func NewResourceClient(src ResourceTokenSource, resource string, scopes ...string) *http.Client {
	return &http.Client{
		Transport: &ResourceTransport{Source: src, Resource: resource, Scopes: scopes},
	}
}

// RoundTrip implements http.RoundTripper.
func (t *ResourceTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.Source == nil {
		return nil, &ConfigurationError{Message: "ResourceTransport requires a Source"}
	}
	if t.Resource == "" {
		return nil, &ConfigurationError{Message: "ResourceTransport requires a Resource"}
	}

	tok, err := t.Source.ResourceToken(req.Context(), t.Resource, t.Scopes...)
	if err != nil {
		return nil, err
	}

	// RoundTrip must not modify the request it is given, per the
	// http.RoundTripper contract — the caller may retry it, and a retry that
	// inherited a now-expired header would be authorized with a stale token.
	clone := req.Clone(req.Context())
	clone.Header.Set("Authorization", "Bearer "+tok.AccessToken)

	base := t.Base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(clone)
}
