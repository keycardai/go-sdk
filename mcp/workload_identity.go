package mcp

import (
	"context"
	"errors"
	"strings"

	"github.com/keycardai/go-sdk/oauth"
)

// IdentityTokenSource supplies a platform-signed OIDC token for use as a client
// assertion during token exchange. It is the only per-platform piece of a
// workload identity credential: [FileTokenSource] covers platforms that
// project the token to a file (EKS, AKS, Kubernetes projected service-account
// tokens), [GCPMetadataTokenSource] covers platforms that serve it from the
// GCP metadata endpoint (GKE, GCE, Cloud Run), and [IdentityTokenFunc] adapts
// any custom fetch.
//
// IdentityToken is called on every token exchange. Implementations must return
// the current token; platforms rotate these tokens, so returning a stale
// cached value risks an expired assertion.
type IdentityTokenSource interface {
	IdentityToken(ctx context.Context) (string, error)
}

// IdentityTokenFunc adapts a function to a IdentityTokenSource.
type IdentityTokenFunc func(ctx context.Context) (string, error)

// IdentityToken implements IdentityTokenSource.
func (f IdentityTokenFunc) IdentityToken(ctx context.Context) (string, error) { return f(ctx) }

// WorkloadIdentityCredential implements ApplicationCredential using a
// platform-signed OIDC token obtained from a IdentityTokenSource. On every
// token exchange it fetches the current token from the source and attaches it
// as a jwt-bearer client assertion. It holds no shared secret and never
// caches the token across requests.
type WorkloadIdentityCredential struct {
	source   IdentityTokenSource
	clientID string
}

// WorkloadIdentityOption configures a WorkloadIdentityCredential.
type WorkloadIdentityOption func(*WorkloadIdentityCredential)

// WithWorkloadClientID sets the ID of the Keycard application credential this
// workload authenticates as. It is sent as the client_id form parameter
// alongside the client assertion. Token-federation application credentials
// are resolved by this ID, so they require it; legacy token credentials are
// resolved by the assertion's subject and ignore it.
func WithWorkloadClientID(clientID string) WorkloadIdentityOption {
	return func(w *WorkloadIdentityCredential) { w.clientID = clientID }
}

// NewWorkloadIdentity creates a WorkloadIdentityCredential backed by source.
// It returns a WorkloadIdentityConfigurationError if source is nil (including
// a nil IdentityTokenFunc).
func NewWorkloadIdentity(source IdentityTokenSource, opts ...WorkloadIdentityOption) (*WorkloadIdentityCredential, error) {
	if source == nil {
		return nil, &WorkloadIdentityConfigurationError{Message: "identity token source must not be nil"}
	}
	if f, ok := source.(IdentityTokenFunc); ok && f == nil {
		return nil, &WorkloadIdentityConfigurationError{Message: "identity token source function must not be nil"}
	}
	w := &WorkloadIdentityCredential{source: source}
	for _, opt := range opts {
		opt(w)
	}
	return w, nil
}

// Auth returns nil (workload identity uses assertion-based auth, not basic auth).
func (w *WorkloadIdentityCredential) Auth(_ string) *ClientAuth {
	return nil
}

// PrepareTokenExchangeRequest builds a token exchange request with the current
// platform token as the client assertion. Built-in sources fail with
// WorkloadIdentityConfigurationError or WorkloadIdentityRuntimeError; any
// other source error is wrapped in a WorkloadIdentityRuntimeError with
// Source "custom".
func (w *WorkloadIdentityCredential) PrepareTokenExchangeRequest(ctx context.Context, subjectToken, resource string, _ *PrepareOptions) (*oauth.TokenExchangeRequest, error) {
	assertion, err := w.source.IdentityToken(ctx)
	if err != nil {
		var cfgErr *WorkloadIdentityConfigurationError
		var runtimeErr *WorkloadIdentityRuntimeError
		if errors.As(err, &runtimeErr) || errors.As(err, &cfgErr) {
			return nil, err
		}
		return nil, &WorkloadIdentityRuntimeError{Source: WorkloadIdentitySourceCustom, Message: "fetching identity token", Err: err}
	}
	if strings.TrimSpace(assertion) == "" {
		return nil, &WorkloadIdentityRuntimeError{Source: WorkloadIdentitySourceCustom, Message: "identity token source returned an empty token"}
	}

	return &oauth.TokenExchangeRequest{
		SubjectToken:        subjectToken,
		Resource:            resource,
		SubjectTokenType:    "urn:ietf:params:oauth:token-type:access_token",
		ClientAssertionType: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
		ClientAssertion:     assertion,
		ClientID:            w.clientID,
	}, nil
}
